// Package clickhouse implements the hot-path telemetry sink backed
// by ClickHouse. The writer batches incoming envelopes in memory
// and flushes them on a size or interval trigger using the v2
// native protocol's column-oriented PrepareBatch API, which is
// roughly an order of magnitude faster than per-row INSERT VALUES
// against a busy MergeTree table.
//
// The schema is deliberately denormalised — each event lands as a
// single row in `sng_telemetry` with the envelope header fields
// promoted to columns and the class-specific payload stored as a
// raw msgpack blob. Schema migrations live in EnsureSchema so the
// control-plane can bootstrap a fresh ClickHouse deployment
// without an out-of-band DDL step. Subsequent schema changes
// would be additive (new columns, new MV) so EnsureSchema's
// CREATE … IF NOT EXISTS stays idempotent.
//
// The Writer is safe for concurrent Write calls. Internal state
// (batch buffer, flush goroutine) is guarded by a mutex; the
// flush goroutine swaps the buffer under the lock and releases
// it before performing the INSERT so concurrent Writes are not
// blocked on Postgres-style network I/O. A Write that lands while
// a flush is in flight is appended to the new buffer and will be
// committed in the next flush cycle.
package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// identifierPattern is the strict subset of ClickHouse unquoted
// identifier syntax we accept for Database and Table names: an
// ASCII letter or underscore followed by ASCII letters, digits,
// or underscores. ClickHouse itself allows broader identifiers
// behind backticks, but we never quote in our generated DDL/DML,
// so accepting only the unquoted-safe pattern is what closes the
// SQL-injection surface that a malicious or fat-fingered
// operator-supplied Config.Table value would otherwise open via
// the fmt.Sprintf-based query construction in EnsureSchema /
// insertSQL / Stats.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateIdentifier(role, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("clickhouse: %s %q must match %s",
			role, value, identifierPattern.String())
	}
	return nil
}

// DefaultTable is the table name the writer targets when Config.Table
// is left blank.
const DefaultTable = "sng_telemetry"

// DefaultFlushInterval is the maximum age of a buffered batch
// before the writer flushes it irrespective of size.
const DefaultFlushInterval = 2 * time.Second

// DefaultBatchSize is the maximum number of rows buffered before
// the writer flushes synchronously on the next Write call.
const DefaultBatchSize = 1024

// Config configures a ClickHouse Writer. Endpoint is required;
// everything else has sane defaults.
type Config struct {
	// Endpoints is the comma-separated list of ClickHouse hosts
	// (host:port). The native protocol port is 9000; secure
	// native is 9440.
	Endpoints []string
	// Database to write events into. Defaults to "default".
	Database string
	// Username / Password authenticate to ClickHouse. Optional
	// when ClickHouse is configured to allow the default user
	// without authentication (development / single-tenant
	// deployments). In production credentials must be supplied.
	Username string
	Password string
	// Table to insert into. Defaults to DefaultTable.
	Table string
	// TLS enables the secure native protocol. The writer uses
	// the system root CA pool; a custom CA must be configured
	// out-of-band (e.g. SSL_CERT_FILE env).
	TLS bool
	// FlushInterval is the maximum age of a buffered batch
	// before the writer flushes it. Defaults to
	// DefaultFlushInterval.
	FlushInterval time.Duration
	// BatchSize is the maximum number of buffered rows before
	// the writer triggers a synchronous flush. Defaults to
	// DefaultBatchSize.
	BatchSize int
	// DialTimeout caps the time spent on initial connection.
	// Defaults to 5s.
	DialTimeout time.Duration
}

func (c *Config) fillDefaults() {
	if c.Database == "" {
		c.Database = "default"
	}
	if c.Table == "" {
		c.Table = DefaultTable
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
}

// validate runs the structural checks that fillDefaults cannot:
// it rejects identifier values that would, if interpolated into
// a CREATE TABLE / INSERT / SELECT statement via fmt.Sprintf,
// either produce malformed SQL or — worse — allow operator-
// controlled metacharacters (semicolons, quotes, comments) to
// escape their column position. The Auth.Database field is also
// validated even though it is passed to the driver as a struct
// field rather than being sprintf'd: keeping both identifiers
// under the same rule means a Database value cannot, for example,
// embed a newline that would surprise the driver's auth handshake.
func (c *Config) validate() error {
	if err := validateIdentifier("Config.Database", c.Database); err != nil {
		return err
	}
	return validateIdentifier("Config.Table", c.Table)
}

// Writer is the ClickHouse-backed HotWriter implementation.
type Writer struct {
	conn   driver.Conn
	cfg    Config
	logger *slog.Logger

	mu          sync.Mutex
	pending     []schema.Envelope
	startOnce   sync.Once
	stopOnce    sync.Once
	cancel      context.CancelFunc
	done        chan struct{}
	flushSignal chan struct{}

	insertSQL string

	// Counters guarded by mu; reads happen via Stats which also
	// takes the mutex. Keeping these as plain ints under the mu
	// means a Stats call gets a coherent snapshot rather than
	// the torn (pending, flushed, flushErrors, consecutiveErrors)
	// tuple atomic counters would produce.
	flushed           uint64
	flushErrors       uint64
	consecutiveErrors uint64
}

// New connects to ClickHouse and returns a Writer.
//
// The returned Writer has its background flush goroutine started
// immediately so a producer can call Write straight away. Stop
// terminates the flusher and drains any pending rows.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Writer, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("clickhouse: at least one endpoint is required")
	}
	cfg.fillDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := &clickhouse.Options{
		Addr: cfg.Endpoints,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		DialTimeout: cfg.DialTimeout,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	}
	if cfg.TLS {
		// Empty config triggers the driver's default TLS bring-
		// up: system roots, no client cert, the host name from
		// the endpoint. Operators who need a custom CA bundle
		// can point SSL_CERT_FILE at it.
		opts.TLS = newTLSConfig()
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clickhouse: ping: %w", err)
	}

	w := &Writer{
		conn:    conn,
		cfg:     cfg,
		logger:  logger,
		pending: make([]schema.Envelope, 0, cfg.BatchSize),
		done:    make(chan struct{}),
		// Use explicit column names so the prepared batch's
		// positional Append cannot be silently mis-aligned by a
		// later ALTER TABLE that appends a column at the end of
		// the table (the default placement for ADD COLUMN without
		// an AFTER clause). The order here is the contract that
		// flushOnce's Append() call must match. ingested_at is
		// omitted so the column's DEFAULT clause supplies the
		// timestamp.
		insertSQL: fmt.Sprintf(
			"INSERT INTO %s "+
				"(event_id, tenant_id, device_id, site_id, timestamp, "+
				"event_class, platform, schema_version, traffic_class, "+
				"bytes_in, bytes_out, payload)",
			cfg.Table,
		),
	}
	w.start()
	return w, nil
}

// EnsureSchema creates the telemetry table if it does not exist
// and applies idempotent ALTERs so existing deployments pick up
// columns added by later releases. The DDL is safe to call on
// every boot without conditional logic.
//
// Two-phase rationale: CREATE TABLE IF NOT EXISTS is a no-op when
// the table already exists, so an upgrade from a pre-`traffic_class`
// schema would leave the column missing and silently break the
// flush path. ALTER TABLE ... ADD COLUMN IF NOT EXISTS fills that
// gap. The MergeTree ORDER BY tuple cannot be changed in place
// after creation — existing deployments retain the old sort key
// and pay a small scan penalty on per-class aggregations until
// the table is rebuilt. Fresh deployments get the optimal sort
// key from the CREATE TABLE statement above.
func (w *Writer) EnsureSchema(ctx context.Context) error {
	createDDL := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    event_id        UUID,
    tenant_id       UUID,
    device_id       UUID,
    site_id         Nullable(UUID),
    timestamp       DateTime64(6, 'UTC'),
    event_class     LowCardinality(String),
    platform        LowCardinality(String),
    schema_version  UInt8,
    traffic_class   LowCardinality(String) DEFAULT 'inspect_full',
    bytes_in        UInt64 DEFAULT 0,
    bytes_out       UInt64 DEFAULT 0,
    payload         String,
    ingested_at     DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC')
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, event_class, traffic_class, timestamp, event_id)
SETTINGS index_granularity = 8192`, w.cfg.Table)
	if err := w.conn.Exec(ctx, createDDL); err != nil {
		return fmt.Errorf("clickhouse: ensure schema: %w", err)
	}
	// Idempotent forward-migrations for tables that pre-date the
	// traffic_class / bytes_in / bytes_out columns. ClickHouse
	// honours IF NOT EXISTS on ADD COLUMN so this is a no-op
	// once the columns are present.
	//
	// AFTER clauses pin the physical column order so that
	// upgraded tables match the CREATE TABLE layout above
	// regardless of when the migration ran. The prepared batch
	// in flushOnce binds by explicit column names (see insertSQL
	// in newWriter) so column position no longer affects the
	// flush path, but keeping the physical layout consistent
	// makes SELECT * results identical across deployments and
	// removes a class of operator surprises.
	for _, alter := range []string{
		fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN IF NOT EXISTS traffic_class LowCardinality(String) DEFAULT 'inspect_full' AFTER schema_version",
			w.cfg.Table,
		),
		fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN IF NOT EXISTS bytes_in UInt64 DEFAULT 0 AFTER traffic_class",
			w.cfg.Table,
		),
		fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN IF NOT EXISTS bytes_out UInt64 DEFAULT 0 AFTER bytes_in",
			w.cfg.Table,
		),
	} {
		if err := w.conn.Exec(ctx, alter); err != nil {
			return fmt.Errorf("clickhouse: ensure schema columns: %w", err)
		}
	}
	return nil
}

// Write buffers an envelope. The buffered events are flushed by
// the background goroutine on a size or interval trigger. Write
// returns once the row has been enqueued; durable delivery is
// signalled by the next successful flush.
//
// Returning sync errors from Write would require us to either
// flush per-event (defeating the batching purpose) or block the
// caller until the next flush completes (deadlock-prone under
// JetStream's MaxAckPending budget). Two safety nets backstop the
// async durability gap:
//
//  1. Stats.ConsecutiveErrors counts back-to-back flush failures.
//     Operators alert on this rising (e.g. > 10) and divert
//     traffic before the ack-then-lose window grows.
//  2. The cold-path S3 archive is written alongside ClickHouse
//     in the same telemetry dispatch step (see telemetry.Service
//     in internal/service/telemetry/service.go). If ClickHouse
//     flushes fail, the events are still durably archived in S3
//     and can be replayed via the DLQ admin endpoint.
//
// Operators wiring this into the telemetry consumer should treat
// a successful Write as "queued for ClickHouse, durably archived
// in S3" — losing buffered ClickHouse rows on crash is acceptable
// because the S3 archive is the durable record of truth.
func (w *Writer) Write(_ context.Context, env schema.Envelope) error {
	w.mu.Lock()
	w.pending = append(w.pending, env)
	full := len(w.pending) >= w.cfg.BatchSize
	w.mu.Unlock()
	if full {
		// Asynchronous trigger — wake the flusher immediately
		// rather than waiting for its interval timer. A select-
		// send with a default branch keeps Write nonblocking
		// when the wake channel is already buffered.
		w.signalFlush()
	}
	return nil
}

// Stop drains the buffer with one final flush and closes the
// ClickHouse connection. Safe to call multiple times. Honours the
// passed context for the final flush; if the context expires
// before flush completes, remaining buffered rows are dropped and
// the error is returned.
func (w *Writer) Stop(ctx context.Context) error {
	var stopErr error
	w.stopOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
		// Wait for the loop to exit so we own the buffer.
		<-w.done
		// Final flush of whatever remains.
		stopErr = w.flushOnce(ctx)
		if err := w.conn.Close(); err != nil && stopErr == nil {
			stopErr = fmt.Errorf("clickhouse: close: %w", err)
		}
	})
	return stopErr
}

// Stats returns a snapshot of writer counters. Useful for the
// /metrics endpoint and the operator-runbook playbook.
//
// ConsecutiveErrors is reset to zero on every successful flush
// and incremented on every failed flush. Operators alert on this
// rising past a configured threshold (e.g. > 10) as the signal
// that the async-batching ack-then-lose window is opening and
// traffic should be diverted from ClickHouse to the cold-path
// archive until the writer recovers.
type Stats struct {
	Pending           int
	Flushed           uint64
	FlushErrors       uint64
	ConsecutiveErrors uint64
}

// Stats returns a snapshot of writer counters.
func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		Pending:           len(w.pending),
		Flushed:           w.flushed,
		FlushErrors:       w.flushErrors,
		ConsecutiveErrors: w.consecutiveErrors,
	}
}

// --- internals ---

func (w *Writer) start() {
	w.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(context.Background())
		w.cancel = cancel
		w.flushSignal = make(chan struct{}, 1)
		go w.loop(runCtx)
	})
}

// signalFlush wakes the flush loop when the batch fills up. The
// channel is buffered at 1; a redundant wake while one is already
// pending is dropped via the default branch.
func (w *Writer) signalFlush() {
	select {
	case w.flushSignal <- struct{}{}:
	default:
	}
}

// loop runs the background flusher. ctx signals "exit the loop"
// (e.g. Stop was called); it intentionally does NOT propagate into
// flushOnce because cancelling an in-flight INSERT during graceful
// shutdown would drop the swapped-out batch on the floor (a small
// but real data-loss window). Each in-loop flush uses
// context.Background() so a flush that's already begun completes
// naturally before the loop checks ctx.Done() again. The trade-off:
// a hung ClickHouse backend can stall Stop until the underlying
// driver's own dial / IO timeout fires (DialTimeout, configured in
// New).
func (w *Writer) loop(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.flushOnce(context.Background()); err != nil {
				w.logger.Warn("clickhouse: flush failed", slog.Any("error", err))
			}
		case <-w.flushSignal:
			if err := w.flushOnce(context.Background()); err != nil {
				w.logger.Warn("clickhouse: flush failed", slog.Any("error", err))
			}
		}
	}
}

// flushOnce sends the current buffer (if any) to ClickHouse as a
// single batch. The buffer is swapped under the mutex and the
// network I/O happens outside the mutex so concurrent Writes are
// not blocked.
func (w *Writer) flushOnce(ctx context.Context) error {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return nil
	}
	batch := w.pending
	w.pending = make([]schema.Envelope, 0, w.cfg.BatchSize)
	w.mu.Unlock()

	prepared, err := w.conn.PrepareBatch(ctx, w.insertSQL)
	if err != nil {
		w.mu.Lock()
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	for i := range batch {
		env := batch[i]
		var siteID *uuid.UUID
		if env.SiteID != nil {
			sid := *env.SiteID
			siteID = &sid
		}
		// Hoist traffic_class / bytes_in / bytes_out out of the
		// envelope onto their dedicated ClickHouse columns.
		// Legacy producers that pre-date the classification
		// engine omit traffic_class; the column DEFAULT supplies
		// `inspect_full`, but we promote the same value
		// explicitly so per-class aggregations report a stable
		// label rather than a NULL. bytes_in / bytes_out default
		// to zero for non-flow events.
		//
		// The order of Append arguments below MUST match the
		// column list in insertSQL (constructed in newWriter).
		trafficClass := env.TrafficClass
		if trafficClass == "" {
			trafficClass = "inspect_full"
		}
		if err := prepared.Append(
			env.EventID,
			env.TenantID,
			env.DeviceID,
			siteID,
			env.Timestamp.UTC(),
			string(env.EventClass),
			string(env.Platform),
			env.SchemaVersion,
			trafficClass,
			env.BytesIn,
			env.BytesOut,
			string(env.Payload),
		); err != nil {
			w.mu.Lock()
			w.flushErrors++
			w.consecutiveErrors++
			w.mu.Unlock()
			return fmt.Errorf("clickhouse: append row: %w", err)
		}
	}
	if err := prepared.Send(); err != nil {
		w.mu.Lock()
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
		return fmt.Errorf("clickhouse: send batch: %w", err)
	}
	w.mu.Lock()
	w.flushed += uint64(len(batch))
	w.consecutiveErrors = 0
	w.mu.Unlock()
	return nil
}

// TrafficClassCount is one row of the per-class flow distribution.
// Used by the operator UI to render the cost-attribution chart.
type TrafficClassCount struct {
	// Class is the traffic_class label
	// (trusted_direct | trusted_media_bypass | inspect_lite |
	// inspect_full | tunnel_private | block).
	Class string `json:"class"`
	// Events is the total number of telemetry events recorded for
	// the class in the window.
	Events uint64 `json:"events"`
	// Bytes is the sum of bytes_in + bytes_out across flow events
	// for the class. Zero when the window contained no FlowEvents.
	Bytes uint64 `json:"bytes"`
}

// QueryTrafficClassDistribution returns the per-class event /
// byte distribution for the tenant in the given window. Bytes
// are summed across the dedicated `bytes_in` / `bytes_out`
// columns (zero for non-flow event classes), so the result is
// a true per-class byte total rather than an event-counter-only
// approximation.
func (w *Writer) QueryTrafficClassDistribution(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]TrafficClassCount, error) {
	// SUM over the dedicated bytes_in / bytes_out columns. The
	// previous implementation tried to JSONExtractUInt the values
	// out of the `payload` column, which holds raw MessagePack
	// bytes; ClickHouse's JSON extractors silently return 0 on
	// non-JSON input so every row produced 0 bytes, leaving the
	// cost-attribution chart non-functional. With the columns
	// hoisted to the table schema (see EnsureSchema), the byte
	// totals are now a column-level aggregate the planner can
	// run as a streaming SUM.
	//
	// Uses w.cfg.Table rather than DefaultTable so operators who
	// override the table name in Config get their custom table
	// queried (writes already use w.cfg.Table via insertSQL).
	q := fmt.Sprintf(`
SELECT
    traffic_class AS class,
    count() AS events,
    sum(bytes_in + bytes_out) AS bytes
FROM %s
WHERE tenant_id = $1
  AND timestamp >= $2
GROUP BY traffic_class
ORDER BY events DESC
`, w.cfg.Table)
	rows, err := w.conn.Query(ctx, q, tenantID, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("clickhouse: query traffic_class: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []TrafficClassCount
	for rows.Next() {
		var row TrafficClassCount
		if err := rows.Scan(&row.Class, &row.Events, &row.Bytes); err != nil {
			return nil, fmt.Errorf("clickhouse: scan traffic_class: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clickhouse: iterate traffic_class: %w", err)
	}
	return out, nil
}
