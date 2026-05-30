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
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/stats"
)

// identifierPattern is the strict subset of ClickHouse unquoted
// identifier syntax we accept for Database and Table names: an
// ASCII letter or underscore followed by ASCII letters, digits,
// or underscores. ClickHouse itself allows broader identifiers
// behind backticks (which the table accessor on Writer uses
// uniformly via quoteIdentifier), but we also gate the value at
// the validate() step so that even a Writer literal whose Config
// was not run through validate (e.g. constructed in a test or by
// a future caller that bypassed New) cannot inject metacharacters
// via the quoted-identifier path.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateIdentifier(role, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("clickhouse: %s %q must match %s",
			role, value, identifierPattern.String())
	}
	return nil
}

// quoteIdentifier wraps an already-validated ClickHouse
// identifier in backticks and escapes any embedded backticks by
// doubling them — ClickHouse's documented quoted-identifier
// syntax. The function is the only call site that inserts a
// caller-controlled identifier into generated SQL; all DDL/DML
// builders inside this package route through it.
//
// In practice, validateIdentifier upstream rejects any string
// containing a backtick (the regex permits only
// [A-Za-z_][A-Za-z0-9_]*), so the escape branch is dead code
// against the production validate() path. It is kept as
// defense-in-depth: if a future change broadens the validator
// to accept e.g. dot-separated database.table paths, the escape
// remains correct.
func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
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
// a CREATE TABLE / INSERT / SELECT statement, either produce
// malformed SQL or — worse — allow operator-controlled
// metacharacters (semicolons, quotes, comments) to escape their
// column position. The Auth.Database field is also validated
// even though it is passed to the driver as a struct field
// rather than being interpolated: keeping both identifiers under
// the same rule means a Database value cannot, for example,
// embed a newline that would surprise the driver's auth
// handshake.
func (c *Config) validate() error {
	if err := validateIdentifier("Config.Database", c.Database); err != nil {
		return err
	}
	return validateIdentifier("Config.Table", c.Table)
}

// Validate is the exported entry point for callers that build a
// Config literal outside New() and want the same structural
// guarantees applied. New() calls validate internally so callers
// going through the constructor do not need to call Validate
// separately.
func (c *Config) Validate() error {
	return c.validate()
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

	// validated is set to true at the end of New() once the
	// embedded cfg has passed validate(). The accessor method
	// qualifiedTable() consults this flag and re-runs validation
	// on every call when it is unset — so a future caller that
	// constructs a Writer literal (bypassing New) still hits the
	// identifier check at the use site rather than relying solely
	// on the constructor path. The flag is set-once at
	// construction and never mutated after, so no mutex is
	// required for the read.
	validated bool

	// Counters guarded by mu; reads happen via Stats which also
	// takes the mutex. Keeping these as plain ints under the mu
	// means a Stats call gets a coherent snapshot rather than
	// the torn (pending, flushed, flushErrors, consecutiveErrors,
	// droppedRows) tuple atomic counters would produce.
	flushed           uint64
	flushErrors       uint64
	consecutiveErrors uint64
	// droppedRows counts individual envelopes that flushOnce
	// could not Append to the prepared batch (e.g. a value
	// rejected by the driver as a type-mismatch). The flushOnce
	// path skips a bad row and keeps Appending the rest, so a
	// single corrupted envelope no longer takes the whole batch
	// down with it. This counter is the durability budget that
	// the operator sees in Stats / dashboards; the slog.Warn at
	// the drop site carries the per-row context (event id,
	// tenant id, traffic class, error) for forensic root-cause.
	//
	// Alerting contract — IMPORTANT:
	//
	// Operators who previously alerted on `ConsecutiveErrors > N`
	// to detect bad-row scenarios will no longer fire on a partial
	// flush (a few bad rows mixed with good ones), because Send()
	// still succeeded and consecutiveErrors resets to 0 on a
	// partially-successful flush. The replacement signal is
	// `rate(DroppedRows[5m]) > threshold` — point alerting at this
	// counter to catch upstream producers emitting malformed
	// envelopes. ConsecutiveErrors retains its original meaning:
	// "the writer is wedged (all-Append-rejected, Send-failed, or
	// transport-down)" — a different operational condition.
	//
	// Counting model — what is and isn't accounted in DroppedRows:
	//
	//   - Append-rejected row: increments DroppedRows.
	//   - All-rows-rejected batch (no Send): increments DroppedRows
	//     by the batch size, increments flushErrors, increments
	//     consecutiveErrors.
	//   - Partial-Append-then-Send-failure: increments DroppedRows
	//     by ONLY the Append-rejected count (the
	//     successfully-Appended-but-not-Sent rows are accounted for
	//     by flushErrors / consecutiveErrors, NOT by DroppedRows).
	//     Append rejections and network failures are distinct
	//     failure modes; conflating them into a single counter
	//     would hide the producer-side vs control-plane-side
	//     attribution that dashboards rely on. The S3 cold archive
	//     remains the durable record of truth for both classes.
	droppedRows uint64
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
		conn:      conn,
		cfg:       cfg,
		logger:    logger,
		pending:   make([]schema.Envelope, 0, cfg.BatchSize),
		done:      make(chan struct{}),
		validated: true,
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
			quoteIdentifier(cfg.Table),
		),
	}
	w.start()
	return w, nil
}

// qualifiedTable returns the writer's table name wrapped in
// ClickHouse identifier-quoting backticks. The accessor re-runs
// validate on every call when the Writer was not constructed via
// New(), so a future caller that builds a Writer{} literal still
// gets the same identifier-injection guard the constructor
// applies. When the Writer was built through New() (the only
// supported construction path), validated is set and we skip the
// redundant re-validation.
//
// Database vs. Table asymmetry — DELIBERATE:
//
// Only Config.Table is re-validated here, not Config.Database.
// Config.Database is never interpolated into a SQL string in this
// package; it is passed exclusively to the clickhouse-go driver
// via the clickhouse.Auth.Database field (see New() above), which
// uses it as a connection-protocol parameter rather than as a
// query token. There is therefore no identifier-injection surface
// associated with Config.Database for qualifiedTable to defend.
// New() still runs validate() on both Database and Table for
// defence-in-depth at the connection boundary; if a future change
// ever interpolates Database into a SQL string (e.g. a fully
// database-qualified table reference in DDL), this function must
// gain a matching re-validation branch.
func (w *Writer) qualifiedTable() (string, error) {
	if !w.validated {
		if err := validateIdentifier("Config.Table", w.cfg.Table); err != nil {
			return "", err
		}
	}
	return quoteIdentifier(w.cfg.Table), nil
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
	table, err := w.qualifiedTable()
	if err != nil {
		return fmt.Errorf("clickhouse: ensure schema: %w", err)
	}
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
SETTINGS index_granularity = 8192`, table)
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
			table,
		),
		fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN IF NOT EXISTS bytes_in UInt64 DEFAULT 0 AFTER traffic_class",
			table,
		),
		fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN IF NOT EXISTS bytes_out UInt64 DEFAULT 0 AFTER bytes_in",
			table,
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
	// DroppedRows is the cumulative count of envelopes that
	// were skipped by flushOnce because the ClickHouse driver
	// rejected the Append call (typically a row-level
	// type-mismatch). A non-zero value indicates partial-batch
	// loss — the offending row was dropped, the rest of the
	// batch was sent normally. Operators should alert on a
	// sustained non-zero rate (it suggests a schema / producer
	// drift) while a transient blip on a malformed envelope is
	// expected. Per-row context for every drop is in the
	// structured logs at WARN level.
	DroppedRows uint64
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
		DroppedRows:       w.droppedRows,
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
	// Per-flush drop counter. A row that the driver rejects on
	// Append (type mismatch, oversized value, etc.) is skipped
	// individually instead of taking the whole batch down with
	// it — the previous behaviour returned early on the first
	// Append error, silently losing the remaining rows that had
	// already been swapped out of w.pending. firstAppendErr is
	// surfaced to the caller / logger only as supplementary
	// context; the partial Send below is the authoritative
	// success / failure signal for the rest of the batch.
	var dropped int
	var firstAppendErr error
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
			// Drop just this row, keep the rest of the batch.
			// Returning early here would silently lose every
			// envelope after this one because the batch slice
			// has already been swapped out of w.pending; the
			// previous behaviour traded "don't half-commit" for
			// "lose 100 rows because the 1st was malformed",
			// which is the wrong trade-off given S3 archival is
			// the durable record of truth. Surface the per-row
			// context at WARN so an operator can chase the
			// producer that emitted a bad envelope.
			dropped++
			if firstAppendErr == nil {
				firstAppendErr = err
			}
			w.logger.Warn("clickhouse: drop row on append error",
				slog.String("event_id", env.EventID.String()),
				slog.String("tenant_id", env.TenantID.String()),
				slog.String("event_class", string(env.EventClass)),
				slog.String("traffic_class", trafficClass),
				slog.Any("error", err))
			continue
		}
	}
	if dropped == len(batch) {
		// Every row was rejected by Append — there is nothing
		// to send. Account the drops + the failure under the
		// mutex and bail out with the first Append error as the
		// caller-visible reason. We do NOT call prepared.Send()
		// in this branch because the clickhouse-go driver's
		// Send on an empty prepared batch is
		// implementation-defined; sending 0 rows is wasted
		// network and risks driver-specific surprises.
		w.mu.Lock()
		w.droppedRows += uint64(dropped)
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
		return fmt.Errorf("clickhouse: append row (all %d rows rejected): %w", dropped, firstAppendErr)
	}
	if err := prepared.Send(); err != nil {
		w.mu.Lock()
		w.droppedRows += uint64(dropped)
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
		return fmt.Errorf("clickhouse: send batch: %w", err)
	}
	w.mu.Lock()
	w.flushed += uint64(len(batch) - dropped)
	w.droppedRows += uint64(dropped)
	w.consecutiveErrors = 0
	w.mu.Unlock()
	if firstAppendErr != nil {
		// At least one row was dropped, but the rest of the
		// batch was sent successfully. Surface the partial
		// failure to the caller / loop logger so the WARN line
		// in the flush goroutine includes the per-flush drop
		// count; a `dropped` > 0 doesn't fail the flush.
		w.logger.Warn("clickhouse: flush completed with dropped rows",
			slog.Int("dropped", dropped),
			slog.Int("sent", len(batch)-dropped),
			slog.Any("first_error", firstAppendErr))
	}
	return nil
}

// TrafficClassCount is a type alias kept for backwards
// compatibility with callers that named the result type via this
// package. The canonical definition lives in
// [internal/service/telemetry/stats] so the handler package can
// share the same row type without importing the ClickHouse
// driver — see the package doc on stats for the rationale.
type TrafficClassCount = stats.TrafficClassCount

// QueryTrafficClassDistribution returns the per-class event /
// byte distribution for the tenant in the given window. Bytes
// are summed across the dedicated `bytes_in` / `bytes_out`
// columns (zero for non-flow event classes), so the result is
// a true per-class byte total rather than an event-counter-only
// approximation.
func (w *Writer) QueryTrafficClassDistribution(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]stats.TrafficClassCount, error) {
	table, err := w.qualifiedTable()
	if err != nil {
		return nil, fmt.Errorf("clickhouse: query traffic_class: %w", err)
	}
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
	// Uses w.cfg.Table (via qualifiedTable) rather than
	// DefaultTable so operators who override the table name in
	// Config get their custom table queried (writes already use
	// the same path via insertSQL).
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
`, table)
	rows, err := w.conn.Query(ctx, q, tenantID, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("clickhouse: query traffic_class: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []stats.TrafficClassCount
	for rows.Next() {
		var row stats.TrafficClassCount
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
