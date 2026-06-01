// Package s3 — archiver.go is the tamper-evident, zstd-compressed,
// budget-guarded cold-tier archiver that lives alongside the
// gzip+JSON-lines Writer in this package.
//
// Architecture differences from writer.go:
//
//   - Compression: zstd via klauspost/compress instead of gzip.
//     zstd is ~30% smaller at equivalent CPU on the SNG envelope
//     mix (per-event sizes 100-300B post-msgpack); on a typical
//     SME tenant it saves ~25% of the S3 archive bill.
//
//   - Partitioning: `tenant_id={uuid}/yyyy={YYYY}/mm={MM}/dd={DD}/`
//     instead of the writer.go `tenant=/date=/hour=/class=` layout.
//     This shape is what Athena / ClickHouse's S3 engine expects
//     out of the box (Hive-style key=value partition pairs), and
//     the tenant/year/month/day grain matches the budget guard
//     window — per-tenant per-day caps catch the runaway case
//     (compromised producer flooding events) before the bill
//     compounds.
//
//   - Tamper detection: every sealed batch carries a SHA-256
//     content hash in its key, and a per-batch manifest object
//     records the batch metadata + hash for end-to-end integrity
//     audit. An operator (or the integrity-monitor goroutine
//     that future work will add) can re-fetch the data object,
//     re-hash it, and compare against the manifest — any
//     mismatch is a tamper signal.
//
//   - Budget guardrails: per-tenant rolling byte budgets bound
//     the runaway-archive failure mode. Once a tenant exceeds
//     their daily budget, Archive returns ErrBudgetExceeded and
//     the consumer drops the event on the cold path (the hot
//     path keeps the event queryable in ClickHouse — the cold
//     archive is best-effort by contract).
//
// Archiver is safe for concurrent use.

package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// DefaultArchiverFlushInterval is the maximum age of a buffered
// per-tenant partition before the archiver seals + uploads it.
const DefaultArchiverFlushInterval = 60 * time.Second

// DefaultArchiverMaxBytesPerObject is the size threshold that
// triggers an upload for a single partition before the interval
// fires.
const DefaultArchiverMaxBytesPerObject = 8 * 1024 * 1024 // 8 MiB compressed

// DefaultArchiverMaxEventsPerObject is the per-partition row count
// that triggers an upload before the interval fires.
const DefaultArchiverMaxEventsPerObject = 25_000

// DefaultDailyBudgetBytes is the per-tenant daily uncompressed-
// bytes archive budget when the operator does not provide a
// resolver. 8 GiB/day at 200B/event is ≈ 40M events/day, which
// is the upper bound a healthy SME tenant emits.
const DefaultDailyBudgetBytes int64 = 8 * 1024 * 1024 * 1024

// ErrBudgetExceeded is returned when an Archive call would push
// the tenant past their daily byte budget. The caller drops the
// event from the cold path; the hot path is independent.
var ErrBudgetExceeded = errors.New("s3: tenant daily archive budget exceeded")

// ErrArchiverClosed is returned when Archive is called after
// Stop. Idempotent shutdown is a contract of the archiver.
var ErrArchiverClosed = errors.New("s3: archiver closed")

// BudgetResolver returns the per-tenant daily uncompressed-bytes
// budget for the given tenant. Implementations would typically
// read from the tenant service (`tier == 'enterprise'` → 100GB,
// `tier == 'pro'` → 20GB, etc.). A nil resolver means "every
// tenant gets DefaultDailyBudgetBytes".
type BudgetResolver interface {
	DailyBudget(ctx context.Context, tenantID uuid.UUID) int64
}

// StaticBudgetResolver is the simplest BudgetResolver — every
// tenant gets the same daily budget.
type StaticBudgetResolver struct{ Bytes int64 }

// DailyBudget returns the configured static budget.
func (s StaticBudgetResolver) DailyBudget(_ context.Context, _ uuid.UUID) int64 {
	return s.Bytes
}

// ArchiverConfig configures the Archiver.
type ArchiverConfig struct {
	// Bucket is the destination S3 bucket. Required.
	Bucket string
	// Prefix is the per-deployment top-level key prefix
	// (e.g. "telemetry-cold-archive"). Defaults to "telemetry-archive".
	Prefix string
	// StorageClass controls the S3 storage class for archive
	// objects. Defaults to STANDARD_IA — the right trade-off
	// for cold-tier archive (≈5× cheaper storage with a per-GB
	// retrieval fee). Operators with frequent-replay workloads
	// can set STANDARD.
	StorageClass string
	// CompressionLevel is the zstd compression level. Defaults
	// to zstd.SpeedDefault. Higher levels (zstd.SpeedBetterCompression)
	// trade CPU for ratio.
	CompressionLevel zstd.EncoderLevel
	// FlushInterval / MaxBytesPerObject / MaxEventsPerObject
	// match writer.go semantics but with archiver-specific
	// defaults.
	FlushInterval      time.Duration
	MaxBytesPerObject  int
	MaxEventsPerObject int
}

func (c *ArchiverConfig) fillDefaults() {
	if c.Prefix == "" {
		c.Prefix = "telemetry-archive"
	}
	if c.StorageClass == "" {
		c.StorageClass = string(types.StorageClassStandardIa)
	}
	if c.CompressionLevel <= 0 {
		c.CompressionLevel = zstd.SpeedDefault
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultArchiverFlushInterval
	}
	if c.MaxBytesPerObject <= 0 {
		c.MaxBytesPerObject = DefaultArchiverMaxBytesPerObject
	}
	if c.MaxEventsPerObject <= 0 {
		c.MaxEventsPerObject = DefaultArchiverMaxEventsPerObject
	}
}

// ArchiverAPI is the S3 surface the Archiver depends on. A
// superset of the writer's API (adds GetObject for integrity
// verification). Defined here so a test can inject a fake
// without spinning up MinIO.
type ArchiverAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Archiver is the cold-tier sealed-archive writer.
type Archiver struct {
	api      ArchiverAPI
	cfg      ArchiverConfig
	budgets  BudgetResolver
	logger   *slog.Logger
	nowFunc  func() time.Time

	mu         sync.Mutex
	partitions map[archiverPartitionKey]*archiverPartition
	usage      map[budgetKey]*tenantDayUsage
	closed     bool

	stats ArchiverStats
}

// ArchiverStats is the counter snapshot exposed by Stats().
type ArchiverStats struct {
	EventsArchived       atomic.Uint64
	BytesArchivedRaw     atomic.Uint64
	BytesArchivedSealed  atomic.Uint64
	ObjectsSealed        atomic.Uint64
	BudgetRejections     atomic.Uint64
	SealFailures         atomic.Uint64
	IntegrityValidations atomic.Uint64
}

// Snapshot returns a value-copy of the counters.
func (s *ArchiverStats) Snapshot() ArchiverStatsSnapshot {
	return ArchiverStatsSnapshot{
		EventsArchived:       s.EventsArchived.Load(),
		BytesArchivedRaw:     s.BytesArchivedRaw.Load(),
		BytesArchivedSealed:  s.BytesArchivedSealed.Load(),
		ObjectsSealed:        s.ObjectsSealed.Load(),
		BudgetRejections:     s.BudgetRejections.Load(),
		SealFailures:         s.SealFailures.Load(),
		IntegrityValidations: s.IntegrityValidations.Load(),
	}
}

// ArchiverStatsSnapshot is a point-in-time copy of ArchiverStats.
type ArchiverStatsSnapshot struct {
	EventsArchived       uint64
	BytesArchivedRaw     uint64
	BytesArchivedSealed  uint64
	ObjectsSealed        uint64
	BudgetRejections     uint64
	SealFailures         uint64
	IntegrityValidations uint64
}

// NewArchiver constructs an Archiver. The API and Bucket are
// required.
func NewArchiver(api ArchiverAPI, cfg ArchiverConfig, budgets BudgetResolver, logger *slog.Logger) (*Archiver, error) {
	if api == nil {
		return nil, errors.New("s3: API client is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("s3: bucket is required")
	}
	cfg.fillDefaults()
	if budgets == nil {
		budgets = StaticBudgetResolver{Bytes: DefaultDailyBudgetBytes}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Archiver{
		api:        api,
		cfg:        cfg,
		budgets:    budgets,
		logger:     logger,
		nowFunc:    time.Now,
		partitions: make(map[archiverPartitionKey]*archiverPartition),
		usage:      make(map[budgetKey]*tenantDayUsage),
	}, nil
}

// archiverPartitionKey groups events into per-tenant per-day
// buffers. Day grain matches the partition layout, so a sealed
// object never spans the day boundary.
type archiverPartitionKey struct {
	tenant uuid.UUID
	year   int
	month  int
	day    int
}

// archiverPartition holds the in-memory accumulator for one
// tenant/day partition before its zstd seal + upload.
type archiverPartition struct {
	mu             sync.Mutex
	events         []sealedEvent
	rawBytes       int
	openedAt       time.Time
}

// sealedEvent is the per-event row in a sealed object. The raw
// MessagePack bytes are base64-stamped so a downstream pipeline
// can decode without msgpack-aware tooling.
type sealedEvent struct {
	Envelope schema.Envelope `json:"envelope"`
	RawB64   string          `json:"raw_b64"`
}

// budgetKey is the per-tenant per-day counter key.
type budgetKey struct {
	tenant uuid.UUID
	day    string // YYYY-MM-DD UTC
}

type tenantDayUsage struct {
	mu      sync.Mutex
	bytes   int64
}

// Archive buffers the envelope + raw bytes for cold-tier sealing.
// Returns ErrBudgetExceeded when the tenant has hit their daily
// budget; returns ErrArchiverClosed after Stop.
//
// The seal + upload happens later, triggered by FlushInterval,
// MaxBytesPerObject, MaxEventsPerObject, or an explicit Flush()
// call. Archive itself is non-blocking on the network — just
// buffer + counter math.
func (a *Archiver) Archive(ctx context.Context, env schema.Envelope, raw []byte) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrArchiverClosed
	}
	a.mu.Unlock()

	if env.TenantID == uuid.Nil {
		return errors.New("s3: tenant_id is required")
	}

	now := a.nowFunc().UTC()
	day := dayString(now)

	// Budget check — gate before buffering so a tenant past
	// their cap is rejected without consuming memory.
	budget := a.budgets.DailyBudget(ctx, env.TenantID)
	usage := a.usageFor(env.TenantID, day)
	usage.mu.Lock()
	rawBytes := int64(len(raw))
	if budget > 0 && usage.bytes+rawBytes > budget {
		usage.mu.Unlock()
		a.stats.BudgetRejections.Add(1)
		return fmt.Errorf("tenant %s day %s used=%d budget=%d: %w",
			env.TenantID, day, usage.bytes, budget, ErrBudgetExceeded)
	}
	usage.bytes += rawBytes
	usage.mu.Unlock()

	key := archiverPartitionKey{
		tenant: env.TenantID,
		year:   now.Year(),
		month:  int(now.Month()),
		day:    now.Day(),
	}
	partition := a.partitionFor(key)
	partition.mu.Lock()
	if len(partition.events) == 0 {
		partition.openedAt = now
	}
	partition.events = append(partition.events, sealedEvent{
		Envelope: env,
		RawB64:   encodeBase64(raw),
	})
	partition.rawBytes += len(raw)
	shouldFlush := partition.rawBytes >= a.cfg.MaxBytesPerObject ||
		len(partition.events) >= a.cfg.MaxEventsPerObject
	partition.mu.Unlock()

	a.stats.EventsArchived.Add(1)
	a.stats.BytesArchivedRaw.Add(uint64(rawBytes))

	if shouldFlush {
		if err := a.flushPartition(ctx, key); err != nil {
			a.stats.SealFailures.Add(1)
			return fmt.Errorf("flush partition: %w", err)
		}
	}
	return nil
}

// Flush forces an upload of every buffered partition. Returns
// the first error encountered; partitions later in iteration
// are still attempted.
func (a *Archiver) Flush(ctx context.Context) error {
	a.mu.Lock()
	keys := make([]archiverPartitionKey, 0, len(a.partitions))
	for k := range a.partitions {
		keys = append(keys, k)
	}
	a.mu.Unlock()

	var firstErr error
	for _, k := range keys {
		if err := a.flushPartition(ctx, k); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Stop drains every buffered partition and marks the archiver
// closed. Idempotent.
func (a *Archiver) Stop(ctx context.Context) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	return a.Flush(ctx)
}

// Stats returns a snapshot of the internal counters.
func (a *Archiver) Stats() ArchiverStatsSnapshot { return a.stats.Snapshot() }

// VerifyIntegrity re-fetches the sealed object at key, recomputes
// the SHA-256 of the bytes, and compares against the hex hash
// embedded in the manifest. Returns nil on match,
// ErrIntegrityViolation on mismatch.
func (a *Archiver) VerifyIntegrity(ctx context.Context, dataKey, manifestKey string) error {
	a.stats.IntegrityValidations.Add(1)
	manifestObj, err := a.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.cfg.Bucket),
		Key:    aws.String(manifestKey),
	})
	if err != nil {
		return fmt.Errorf("get manifest %s: %w", manifestKey, err)
	}
	defer manifestObj.Body.Close()
	manifestBytes, err := readAll(manifestObj.Body)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest sealedManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	dataObj, err := a.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.cfg.Bucket),
		Key:    aws.String(dataKey),
	})
	if err != nil {
		return fmt.Errorf("get data %s: %w", dataKey, err)
	}
	defer dataObj.Body.Close()
	dataBytes, err := readAll(dataObj.Body)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	got := sha256Hex(dataBytes)
	if got != manifest.SealedSHA256 {
		return fmt.Errorf("data sha256=%s manifest sha256=%s: %w", got, manifest.SealedSHA256, ErrIntegrityViolation)
	}
	return nil
}

// ErrIntegrityViolation is returned when VerifyIntegrity detects
// a mismatch between a sealed object and its manifest.
var ErrIntegrityViolation = errors.New("s3: sealed-object integrity violation")

// usageFor returns the per-tenant per-day usage row, creating
// it on first touch.
func (a *Archiver) usageFor(tenantID uuid.UUID, day string) *tenantDayUsage {
	key := budgetKey{tenant: tenantID, day: day}
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.usage[key]; ok {
		return u
	}
	u := &tenantDayUsage{}
	a.usage[key] = u
	return u
}

// partitionFor returns the per-(tenant, year, month, day)
// partition, creating it on first touch.
func (a *Archiver) partitionFor(key archiverPartitionKey) *archiverPartition {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := a.partitions[key]; ok {
		return p
	}
	p := &archiverPartition{}
	a.partitions[key] = p
	return p
}

// flushPartition serialises one partition to JSON-Lines, zstd-
// compresses, computes the SHA-256 seal, and uploads both the
// sealed object and its manifest. After a successful upload the
// in-memory buffer is detached so the archiver can keep
// accumulating new events for the same partition.
func (a *Archiver) flushPartition(ctx context.Context, key archiverPartitionKey) error {
	a.mu.Lock()
	partition, ok := a.partitions[key]
	a.mu.Unlock()
	if !ok {
		return nil
	}
	// Swap-and-restore: take the in-flight slice out of the
	// partition so concurrent Archive() calls can keep appending
	// onto a fresh slice, but on ANY failure below we re-prepend
	// the in-flight slice so a later flush retries the same
	// events. This mirrors the ClickHouse writer's requeueBatch
	// pattern (writer.go) — both the hot path and the cold path
	// MUST hold the buffer until upload is confirmed, otherwise
	// a single transient S3 / serialization / zstd failure
	// silently loses up to MaxEventsPerObject events. The Archive
	// API contract is "buffered for sealing", not "successfully
	// archived", so the restore-on-failure semantics keep
	// callers honest.
	partition.mu.Lock()
	if len(partition.events) == 0 {
		partition.mu.Unlock()
		return nil
	}
	inFlight := partition.events
	inFlightRawBytes := partition.rawBytes
	openedAt := partition.openedAt
	partition.events = nil
	partition.rawBytes = 0
	partition.mu.Unlock()

	// requeue re-prepends the in-flight slice onto the partition
	// (in FIFO order — the in-flight events were emitted before
	// any events appended by concurrent Archive() calls during
	// the upload window). Called under defer-on-error below so
	// every error path restores the buffer; the happy path
	// resets the flag before returning.
	restored := false
	requeue := func() {
		partition.mu.Lock()
		defer partition.mu.Unlock()
		if len(partition.events) == 0 {
			partition.events = inFlight
		} else {
			merged := make([]sealedEvent, 0, len(inFlight)+len(partition.events))
			merged = append(merged, inFlight...)
			merged = append(merged, partition.events...)
			partition.events = merged
		}
		partition.rawBytes += inFlightRawBytes
		if partition.openedAt.IsZero() || openedAt.Before(partition.openedAt) {
			partition.openedAt = openedAt
		}
	}
	defer func() {
		if !restored {
			requeue()
		}
	}()

	// Serialize → zstd → seal.
	var jsonBuf bytes.Buffer
	for _, ev := range inFlight {
		line, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal event: %w", err)
		}
		jsonBuf.Write(line)
		jsonBuf.WriteByte('\n')
	}
	rawBytes := jsonBuf.Bytes()
	rawHash := sha256.Sum256(rawBytes)

	var sealedBuf bytes.Buffer
	enc, err := zstd.NewWriter(&sealedBuf, zstd.WithEncoderLevel(a.cfg.CompressionLevel))
	if err != nil {
		return fmt.Errorf("zstd writer: %w", err)
	}
	if _, err := enc.Write(rawBytes); err != nil {
		_ = enc.Close()
		return fmt.Errorf("zstd write: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("zstd close: %w", err)
	}
	sealedBytes := sealedBuf.Bytes()
	sealedHash := sha256.Sum256(sealedBytes)

	dataKey, manifestKey := a.objectKeys(key, openedAt, hex.EncodeToString(sealedHash[:]))
	if err := a.uploadSealed(ctx, dataKey, sealedBytes); err != nil {
		return fmt.Errorf("upload data: %w", err)
	}
	manifest := sealedManifest{
		Bucket:        a.cfg.Bucket,
		Tenant:        key.tenant,
		Year:          key.year,
		Month:         key.month,
		Day:           key.day,
		EventCount:    len(inFlight),
		RawSHA256:     hex.EncodeToString(rawHash[:]),
		SealedSHA256:  hex.EncodeToString(sealedHash[:]),
		RawBytes:      len(rawBytes),
		SealedBytes:   len(sealedBytes),
		OpenedAt:      openedAt,
		SealedAt:      a.nowFunc().UTC(),
		DataKey:       dataKey,
		Compression:   "zstd",
		SchemaVersion: schema.SchemaVersion,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := a.uploadManifest(ctx, manifestKey, manifestBytes); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}
	// Upload confirmed end-to-end (data + manifest both landed).
	// Mark restored so the defer'd requeue is skipped — the
	// in-flight slice is now durable in S3 and must NOT be
	// re-archived.
	restored = true
	a.stats.ObjectsSealed.Add(1)
	a.stats.BytesArchivedSealed.Add(uint64(len(sealedBytes)))
	a.logger.Info("s3: sealed archive uploaded",
		slog.String("tenant", key.tenant.String()),
		slog.String("data_key", dataKey),
		slog.String("manifest_key", manifestKey),
		slog.Int("events", len(inFlight)),
		slog.Int("raw_bytes", len(rawBytes)),
		slog.Int("sealed_bytes", len(sealedBytes)),
		slog.String("sealed_sha256", manifest.SealedSHA256))
	return nil
}

// objectKeys returns the (data, manifest) key pair for a sealed
// partition. The key layout is:
//
//	{prefix}/tenant_id={tenant}/yyyy={YYYY}/mm={MM}/dd={DD}/seal={SHORT_HASH}/data.zst
//	{prefix}/tenant_id={tenant}/yyyy={YYYY}/mm={MM}/dd={DD}/seal={SHORT_HASH}/manifest.json
//
// The seal segment in the path makes the key content-addressed
// so a re-flush of the same logical batch produces the same key
// (idempotent on retry), and a key collision is by-definition
// the same bytes (sha256). The short hash form (first 16 chars)
// keeps the key length tractable.
func (a *Archiver) objectKeys(key archiverPartitionKey, _ time.Time, sealedHashHex string) (string, string) {
	short := sealedHashHex
	if len(short) > 16 {
		short = short[:16]
	}
	base := fmt.Sprintf("%s/tenant_id=%s/yyyy=%04d/mm=%02d/dd=%02d/seal=%s",
		a.cfg.Prefix, key.tenant.String(), key.year, key.month, key.day, short)
	return base + "/data.zst", base + "/manifest.json"
}

func (a *Archiver) uploadSealed(ctx context.Context, key string, body []byte) error {
	_, err := a.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(a.cfg.Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentType:   aws.String("application/zstd"),
		StorageClass:  types.StorageClass(a.cfg.StorageClass),
		ContentLength: aws.Int64(int64(len(body))),
	})
	return err
}

func (a *Archiver) uploadManifest(ctx context.Context, key string, body []byte) error {
	_, err := a.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(a.cfg.Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentType:   aws.String("application/json"),
		StorageClass:  types.StorageClass(a.cfg.StorageClass),
		ContentLength: aws.Int64(int64(len(body))),
	})
	return err
}

// sealedManifest is the JSON-encoded per-batch metadata uploaded
// alongside each sealed object.
type sealedManifest struct {
	Bucket        string    `json:"bucket"`
	Tenant        uuid.UUID `json:"tenant_id"`
	Year          int       `json:"year"`
	Month         int       `json:"month"`
	Day           int       `json:"day"`
	EventCount    int       `json:"event_count"`
	RawSHA256     string    `json:"raw_sha256"`
	SealedSHA256  string    `json:"sealed_sha256"`
	RawBytes      int       `json:"raw_bytes"`
	SealedBytes   int       `json:"sealed_bytes"`
	OpenedAt      time.Time `json:"opened_at"`
	SealedAt      time.Time `json:"sealed_at"`
	DataKey       string    `json:"data_key"`
	Compression   string    `json:"compression"`
	SchemaVersion uint8     `json:"schema_version"`
}

func dayString(t time.Time) string { return t.UTC().Format("2006-01-02") }

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
