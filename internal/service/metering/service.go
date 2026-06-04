// Package metering models and enforces per-tenant cost budgets for
// the resource-consuming subsystems of the ShieldNet Gateway control
// plane: LLM inference (via the AI guardrails), URL-categorisation
// and malware feed lookups, ClickHouse telemetry writes, S3 archive,
// and proxied bandwidth.
//
// The package is split into three concerns:
//
//   - service.go (this file) — MeteringService tracks real-time
//     consumption with sync/atomic counters on the hot path and
//     flushes accumulated deltas to Postgres every FlushInterval via
//     a single batch upsert.
//   - budget.go — BudgetEnforcer turns a meter reading into an
//     allow / soft-exceed / hard-exceed decision against per-tenant,
//     per-tier budgets.
//   - cost.go — CostCalculator maps meter readings to estimated
//     dollar costs and produces a per-tenant cost report.
//
// Tenant isolation: the metering tables (tenant_usage,
// tenant_budgets — migration 040) are RLS-scoped to the
// `sng.tenant_id` GUC. Per-tenant reads run tenant-scoped; the
// background flush worker and the MSP/admin platform-wide cost
// report run system-scoped (sng.system_role='true'), matching the
// cross-tenant pattern established by the webhook delivery worker.
package metering

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Meter is the canonical name of a metered resource. Stored verbatim
// in tenant_usage.meter and tenant_budgets.meter.
type Meter string

const (
	// MeterLLMTokensUsed counts LLM tokens consumed (prompt +
	// completion) across all AI features. This is the meter the AI
	// guardrails gate on before every LLM call.
	//nolint:gosec // G101 false positive: meter name constant, not a credential.
	MeterLLMTokensUsed Meter = "llm_tokens_used"
	// MeterLLMCalls counts individual LLM invocations.
	MeterLLMCalls Meter = "llm_calls"
	// MeterURLCatLookups counts URL-categorisation feed lookups.
	MeterURLCatLookups Meter = "url_cat_lookups"
	// MeterMalwareScans counts malware-verdict feed lookups.
	MeterMalwareScans Meter = "malware_scans"
	// MeterClickHouseRowsWritten counts telemetry rows persisted to
	// ClickHouse (write-amplification cost driver).
	MeterClickHouseRowsWritten Meter = "clickhouse_rows_written"
	// MeterS3BytesArchived counts bytes written to the cold S3
	// telemetry archive.
	MeterS3BytesArchived Meter = "s3_bytes_archived"
	// MeterBandwidthProxiedBytes counts bytes proxied through the SWG
	// data plane (egress cost driver).
	MeterBandwidthProxiedBytes Meter = "bandwidth_proxied_bytes"
)

// AllMeters is the canonical, ordered list of known meters. Used to
// validate handler / config input and to iterate deterministically.
var AllMeters = []Meter{
	MeterLLMTokensUsed,
	MeterLLMCalls,
	MeterURLCatLookups,
	MeterMalwareScans,
	MeterClickHouseRowsWritten,
	MeterS3BytesArchived,
	MeterBandwidthProxiedBytes,
}

// Valid reports whether m is a known meter.
func (m Meter) Valid() bool {
	for _, k := range AllMeters {
		if k == m {
			return true
		}
	}
	return false
}

// Period is the budget / accumulation cadence for a meter.
type Period string

const (
	// PeriodDaily buckets usage into UTC calendar days.
	PeriodDaily Period = "daily"
	// PeriodMonthly buckets usage into UTC calendar months.
	PeriodMonthly Period = "monthly"
)

// Valid reports whether p is a recognised period.
func (p Period) Valid() bool { return p == PeriodDaily || p == PeriodMonthly }

// Bounds returns the inclusive start and exclusive end of the period
// that contains `at`. Both are normalised to UTC midnight so they map
// cleanly onto the `date`-typed period_start / period_end columns.
func (p Period) Bounds(at time.Time) (start, end time.Time) {
	at = at.UTC()
	switch p {
	case PeriodDaily:
		start = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		end = start.AddDate(0, 0, 1)
	default: // monthly is the safe default for any unknown value
		start = time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		end = start.AddDate(0, 1, 0)
	}
	return start, end
}

// PeriodResolver maps a meter to its accumulation / budget period.
// MeteringService and BudgetEnforcer share one resolver so a meter's
// usage rows and its budget window always agree.
type PeriodResolver func(Meter) Period

// DefaultMeterPeriod is the built-in PeriodResolver. URL-cat and
// malware lookups are high-volume and budgeted daily; everything else
// is budgeted monthly (matching the tier-default table in budget.go).
func DefaultMeterPeriod(m Meter) Period {
	switch m {
	case MeterURLCatLookups, MeterMalwareScans:
		return PeriodDaily
	default:
		return PeriodMonthly
	}
}

// UsageDelta is one accumulated increment to flush into tenant_usage.
type UsageDelta struct {
	TenantID    uuid.UUID
	Meter       Meter
	PeriodStart time.Time
	PeriodEnd   time.Time
	Delta       int64
}

// UsageRecord is a persisted (or aggregated) usage row.
type UsageRecord struct {
	TenantID    uuid.UUID
	Meter       Meter
	PeriodStart time.Time
	PeriodEnd   time.Time
	Value       int64
	UpdatedAt   time.Time
}

// UsageStore is the persistence surface the MeteringService and the
// metering handler depend on. The production implementation
// (PostgresUsageStore, store.go) is backed by pgxpool and honours the
// migration-040 RLS policy; unit tests use an in-memory fake.
type UsageStore interface {
	// BatchUpsertUsage applies every delta in a single system-scoped
	// transaction, adding to any existing
	// (tenant_id, meter, period_start) row. Implementations MUST be
	// additive (value = value + delta), never last-write-wins, so a
	// concurrent writer (or a replayed flush) cannot lose counts.
	BatchUpsertUsage(ctx context.Context, deltas []UsageDelta) error
	// TenantPeriodUsage returns the persisted value for a single
	// (tenant, meter, period_start), or 0 when no row exists. Used to
	// seed the in-memory baseline so accounting survives a restart.
	TenantPeriodUsage(ctx context.Context, tenantID uuid.UUID, meter Meter, periodStart time.Time) (int64, error)
	// TenantCurrentUsage returns every usage row for a tenant whose
	// period contains `at` (tenant-scoped read).
	TenantCurrentUsage(ctx context.Context, tenantID uuid.UUID, at time.Time) ([]UsageRecord, error)
	// TenantUsageHistory returns monthly-bucketed usage for a tenant
	// over the trailing `months` calendar months (tenant-scoped).
	TenantUsageHistory(ctx context.Context, tenantID uuid.UUID, months int) ([]UsageRecord, error)
	// PlatformCurrentUsage returns every tenant's usage rows whose
	// period contains `at` (system-scoped read) for the admin cost
	// report.
	PlatformCurrentUsage(ctx context.Context, at time.Time) ([]UsageRecord, error)
}

// meterCell holds the live counters for one (tenant, meter) within a
// single billing period. value is the cumulative consumption for the
// period; flushed is the high-water mark persisted at the last flush.
// The flush delta is value-flushed. Both are accessed with sync/atomic
// so Record stays lock-free once the cell exists.
type meterCell struct {
	value       int64
	flushed     int64
	periodStart int64 // unix seconds; identifies the active period
	periodEnd   int64
}

// cellKey identifies a meterCell.
type cellKey struct {
	tenant uuid.UUID
	meter  Meter
}

// MeteringService tracks per-tenant resource consumption in real time
// and flushes it to Postgres on a fixed cadence.
type MeteringService struct {
	store         UsageStore
	logger        *slog.Logger
	periodOf      PeriodResolver
	flushInterval time.Duration
	now           func() time.Time

	mu    sync.RWMutex
	cells map[cellKey]*meterCell

	// flushes / flushErrors are observability counters surfaced via
	// Stats for tests and the ops-health endpoint.
	flushes    atomic.Int64
	flushErrs  atomic.Int64
	lastFlush  atomic.Int64 // unix nanos
	recordSeen atomic.Int64
}

// Option customises a MeteringService.
type Option func(*MeteringService)

// WithPeriodResolver overrides the meter→period mapping.
func WithPeriodResolver(r PeriodResolver) Option {
	return func(s *MeteringService) {
		if r != nil {
			s.periodOf = r
		}
	}
}

// WithFlushInterval overrides the flush cadence. Values <= 0 are
// ignored (the default stands).
func WithFlushInterval(d time.Duration) Option {
	return func(s *MeteringService) {
		if d > 0 {
			s.flushInterval = d
		}
	}
}

// withClock overrides the wall clock; test-only.
func withClock(now func() time.Time) Option {
	return func(s *MeteringService) {
		if now != nil {
			s.now = now
		}
	}
}

// DefaultFlushInterval is the flush cadence when none is configured.
const DefaultFlushInterval = 60 * time.Second

// NewMeteringService constructs a MeteringService. store must not be
// nil. logger defaults to slog.Default().
func NewMeteringService(store UsageStore, logger *slog.Logger, opts ...Option) (*MeteringService, error) {
	if store == nil {
		return nil, fmt.Errorf("metering: store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &MeteringService{
		store:         store,
		logger:        logger,
		periodOf:      DefaultMeterPeriod,
		flushInterval: DefaultFlushInterval,
		now:           time.Now,
		cells:         make(map[cellKey]*meterCell),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// getCell returns the live cell for (tenant, meter), creating and
// baseline-seeding it on first use and rolling it over when the active
// period has elapsed. The common path (cell exists, same period) takes
// only a read lock and no allocation.
func (s *MeteringService) getCell(ctx context.Context, tenantID uuid.UUID, meter Meter) *meterCell {
	key := cellKey{tenant: tenantID, meter: meter}
	now := s.now()
	start, end := s.periodOf(meter).Bounds(now)

	s.mu.RLock()
	c, ok := s.cells[key]
	s.mu.RUnlock()
	if ok && atomic.LoadInt64(&c.periodStart) == start.Unix() {
		return c
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok = s.cells[key]
	if ok && atomic.LoadInt64(&c.periodStart) == start.Unix() {
		return c
	}
	if ok {
		// Period rollover: best-effort flush of the trailing delta
		// before resetting so the previous period's tail is not lost.
		s.flushCellLocked(ctx, key, c)
		atomic.StoreInt64(&c.value, 0)
		atomic.StoreInt64(&c.flushed, 0)
		atomic.StoreInt64(&c.periodStart, start.Unix())
		atomic.StoreInt64(&c.periodEnd, end.Unix())
		// Seed the new period from any persisted value (e.g. another
		// replica already wrote some of this period's usage).
		s.seedCellLocked(ctx, key, c, start)
		return c
	}
	c = &meterCell{periodStart: start.Unix(), periodEnd: end.Unix()}
	s.cells[key] = c
	s.seedCellLocked(ctx, key, c, start)
	return c
}

// seedCellLocked loads the persisted current-period value into the
// cell so budget accounting reflects usage written by previous
// processes / other replicas. Must hold s.mu. A load failure is
// logged and tolerated (the cell simply starts at 0).
func (s *MeteringService) seedCellLocked(ctx context.Context, key cellKey, c *meterCell, start time.Time) {
	v, err := s.store.TenantPeriodUsage(ctx, key.tenant, key.meter, start)
	if err != nil {
		s.logger.WarnContext(ctx, "metering: baseline seed failed",
			slog.String("tenant_id", key.tenant.String()),
			slog.String("meter", string(key.meter)),
			slog.String("error", err.Error()))
		return
	}
	atomic.StoreInt64(&c.value, v)
	atomic.StoreInt64(&c.flushed, v)
}

// Record adds `amount` to the (tenant, meter) counter for the current
// period. A non-positive amount is a no-op (we never decrement a
// monotonic meter). Unknown meters are rejected so a typo cannot
// silently create an unbudgeted counter.
func (s *MeteringService) Record(ctx context.Context, tenantID uuid.UUID, meter Meter, amount int64) error {
	if amount <= 0 {
		return nil
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("metering: record: tenant id must not be nil")
	}
	if !meter.Valid() {
		return fmt.Errorf("metering: record: unknown meter %q", meter)
	}
	c := s.getCell(ctx, tenantID, meter)
	atomic.AddInt64(&c.value, amount)
	s.recordSeen.Add(1)
	return nil
}

// Current returns the cumulative value of (tenant, meter) for the
// active period, including unflushed in-memory increments. Allocation-
// free on the hot path once the cell exists; this is what the
// BudgetEnforcer reads.
func (s *MeteringService) Current(ctx context.Context, tenantID uuid.UUID, meter Meter) int64 {
	if !meter.Valid() || tenantID == uuid.Nil {
		return 0
	}
	c := s.getCell(ctx, tenantID, meter)
	return atomic.LoadInt64(&c.value)
}

// flushCellLocked appends the cell's pending delta to `out`-style
// persistence by issuing a single-delta upsert. Used only on the
// rollover path (where we already hold the lock and want a synchronous
// write); the periodic flush batches all cells instead. Must hold
// s.mu. Errors are logged, not returned, so a rollover is never
// blocked by a transient DB error.
func (s *MeteringService) flushCellLocked(ctx context.Context, key cellKey, c *meterCell) {
	value := atomic.LoadInt64(&c.value)
	flushed := atomic.LoadInt64(&c.flushed)
	delta := value - flushed
	if delta <= 0 {
		return
	}
	start := time.Unix(atomic.LoadInt64(&c.periodStart), 0).UTC()
	end := time.Unix(atomic.LoadInt64(&c.periodEnd), 0).UTC()
	d := UsageDelta{TenantID: key.tenant, Meter: key.meter, PeriodStart: start, PeriodEnd: end, Delta: delta}
	if err := s.store.BatchUpsertUsage(ctx, []UsageDelta{d}); err != nil {
		s.flushErrs.Add(1)
		s.logger.WarnContext(ctx, "metering: rollover flush failed",
			slog.String("tenant_id", key.tenant.String()),
			slog.String("meter", string(key.meter)),
			slog.String("error", err.Error()))
		return
	}
	atomic.AddInt64(&c.flushed, delta)
}

// Flush persists every cell's accumulated delta in one batch upsert.
// Safe to call concurrently with Record: each cell's delta is snapshot
// via atomic loads and the high-water mark is only advanced after the
// batch commits, so a Record that races a Flush is counted in the next
// flush rather than lost or double-counted.
func (s *MeteringService) Flush(ctx context.Context) error {
	type pending struct {
		key   cellKey
		cell  *meterCell
		delta int64
	}
	s.mu.RLock()
	pend := make([]pending, 0, len(s.cells))
	deltas := make([]UsageDelta, 0, len(s.cells))
	for key, c := range s.cells {
		value := atomic.LoadInt64(&c.value)
		flushed := atomic.LoadInt64(&c.flushed)
		delta := value - flushed
		if delta <= 0 {
			continue
		}
		start := time.Unix(atomic.LoadInt64(&c.periodStart), 0).UTC()
		end := time.Unix(atomic.LoadInt64(&c.periodEnd), 0).UTC()
		deltas = append(deltas, UsageDelta{TenantID: key.tenant, Meter: key.meter, PeriodStart: start, PeriodEnd: end, Delta: delta})
		pend = append(pend, pending{key: key, cell: c, delta: delta})
	}
	s.mu.RUnlock()

	if len(deltas) == 0 {
		return nil
	}
	if err := s.store.BatchUpsertUsage(ctx, deltas); err != nil {
		s.flushErrs.Add(1)
		return fmt.Errorf("metering: flush: %w", err)
	}
	// Advance each high-water mark by exactly the delta we committed.
	// Using AddInt64 (not Store) means concurrent Record increments
	// that arrived after the snapshot remain pending for the next
	// flush instead of being dropped.
	for _, p := range pend {
		atomic.AddInt64(&p.cell.flushed, p.delta)
	}
	s.flushes.Add(1)
	s.lastFlush.Store(s.now().UnixNano())
	return nil
}

// Run drives the periodic flush loop until ctx is cancelled. On
// cancellation it performs one final flush (with a short bounded
// timeout) so a graceful shutdown does not drop the trailing window.
func (s *MeteringService) Run(ctx context.Context) {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.Flush(flushCtx); err != nil {
				s.logger.Warn("metering: final flush failed", slog.String("error", err.Error()))
			}
			cancel()
			return
		case <-ticker.C:
			if err := s.Flush(ctx); err != nil {
				s.logger.WarnContext(ctx, "metering: periodic flush failed", slog.String("error", err.Error()))
			}
		}
	}
}

// Stats is a point-in-time snapshot of the service's flush
// bookkeeping, surfaced for tests and ops-health.
type Stats struct {
	Cells       int
	Flushes     int64
	FlushErrors int64
	RecordsSeen int64
	LastFlush   time.Time
}

// Stats returns the current bookkeeping snapshot.
func (s *MeteringService) Stats() Stats {
	s.mu.RLock()
	n := len(s.cells)
	s.mu.RUnlock()
	var last time.Time
	if v := s.lastFlush.Load(); v != 0 {
		last = time.Unix(0, v)
	}
	return Stats{
		Cells:       n,
		Flushes:     s.flushes.Load(),
		FlushErrors: s.flushErrs.Load(),
		RecordsSeen: s.recordSeen.Load(),
		LastFlush:   last,
	}
}

// CurrentUsage returns the current-period usage for a tenant, merging
// the persisted rows with any unflushed in-memory increments so the
// reading is live rather than as-of-last-flush. Tenant-scoped.
func (s *MeteringService) CurrentUsage(ctx context.Context, tenantID uuid.UUID) ([]UsageRecord, error) {
	now := s.now()
	rows, err := s.store.TenantCurrentUsage(ctx, tenantID, now)
	if err != nil {
		return nil, fmt.Errorf("metering: current usage: %w", err)
	}
	byMeter := make(map[Meter]UsageRecord, len(rows))
	for _, r := range rows {
		byMeter[r.Meter] = r
	}
	// Overlay unflushed deltas held in memory for this tenant.
	s.mu.RLock()
	for key, c := range s.cells {
		if key.tenant != tenantID {
			continue
		}
		start := time.Unix(atomic.LoadInt64(&c.periodStart), 0).UTC()
		end := time.Unix(atomic.LoadInt64(&c.periodEnd), 0).UTC()
		if !start.Equal(s.periodOf(key.meter).boundsStart(now)) {
			continue
		}
		live := atomic.LoadInt64(&c.value)
		rec := byMeter[key.meter]
		rec.TenantID = tenantID
		rec.Meter = key.meter
		rec.PeriodStart = start
		rec.PeriodEnd = end
		if live > rec.Value {
			rec.Value = live
		}
		byMeter[key.meter] = rec
	}
	s.mu.RUnlock()

	out := make([]UsageRecord, 0, len(byMeter))
	for _, r := range byMeter {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meter < out[j].Meter })
	return out, nil
}

// boundsStart is a small helper so CurrentUsage can compare a cell's
// period to the active one without re-deriving the end bound.
func (p Period) boundsStart(at time.Time) time.Time {
	start, _ := p.Bounds(at)
	return start
}

// UsageHistory returns monthly-aggregated usage for a tenant over the
// trailing `months` calendar months. Tenant-scoped.
func (s *MeteringService) UsageHistory(ctx context.Context, tenantID uuid.UUID, months int) ([]UsageRecord, error) {
	if months <= 0 {
		months = 6
	}
	rows, err := s.store.TenantUsageHistory(ctx, tenantID, months)
	if err != nil {
		return nil, fmt.Errorf("metering: usage history: %w", err)
	}
	return rows, nil
}
