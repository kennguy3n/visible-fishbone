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

// DefaultMaxBacklogMultiplier caps how many `BatchSize`-worth of
// rows the writer is willing to hold in `pending` across
// transient ClickHouse outages. The cap matters because the
// `flushOnce` failure paths (PrepareBatch reject, all-Append-
// reject + Send skip, network Send failure) re-enqueue the
// already-swapped batch at the head of `pending` so the rows
// survive the outage and ride the next successful flush. Without
// a cap, a wedged ClickHouse plus a steady producer would grow
// `pending` until the writer ran out of memory. The default of
// 4 means the writer holds up to ~4 full batches (~4096 rows by
// default) before it starts shedding the OLDEST rows under
// pressure; older rows are credited to `droppedRows` so the
// alerting contract still surfaces the loss. The S3 cold-path
// archive backs the durability gap during the shedding window.
const DefaultMaxBacklogMultiplier = 4

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
	// MaxBacklogMultiplier bounds how many `BatchSize`-worth of
	// rows the writer is willing to keep in `pending` across
	// transient ClickHouse outages. The flushOnce failure paths
	// re-enqueue the swapped-out batch at the head of `pending`
	// so the rows survive the failure and ride the next
	// successful flush. When the resulting backlog exceeds
	// `BatchSize * MaxBacklogMultiplier`, the writer sheds the
	// OLDEST rows (FIFO) and credits them to `droppedRows`.
	// Defaults to DefaultMaxBacklogMultiplier.
	MaxBacklogMultiplier int
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
	if c.MaxBacklogMultiplier <= 0 {
		c.MaxBacklogMultiplier = DefaultMaxBacklogMultiplier
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
	// requeuedBatches counts how many times flushOnce re-enqueued
	// a swapped-out batch at the head of `pending` because a
	// transient failure (PrepareBatch reject, network Send
	// failure, all-Append-rejected fallthrough) prevented the
	// rows from reaching ClickHouse. This is the canonical
	// "writer is shielding rows from a transient outage" signal
	// and pairs with `consecutiveErrors`: a high requeue rate
	// without `consecutiveErrors` rising means individual
	// flushes are failing but recovering on the next attempt; a
	// rising `consecutiveErrors` alongside `requeuedBatches`
	// confirms a sustained outage where the backlog cap will
	// eventually trip and shed rows into `droppedRows`.
	requeuedBatches uint64
	// backlogDrops counts how many envelopes were shed from the
	// HEAD of `pending` (oldest-first FIFO) because a requeue
	// would have pushed `len(pending)` past
	// `cfg.BatchSize * cfg.MaxBacklogMultiplier`. backlogDrops
	// is also credited to `droppedRows` so the alerting contract
	// keeps a single source of truth for total per-writer data
	// loss. The split is for forensics: a non-zero backlogDrops
	// is the specific signal that the ClickHouse outage outlasted
	// the writer's in-memory shield, and operators should be
	// diverting traffic to the S3 cold path until the writer
	// recovers.
	backlogDrops uint64
	// droppedRows counts individual envelopes that flushOnce
	// could not deliver to ClickHouse — either because the
	// driver rejected the row on Append (type mismatch,
	// oversized value) or because the row was shed from the
	// head of `pending` after a sustained outage filled the
	// requeue backlog past `BatchSize * MaxBacklogMultiplier`.
	// This counter is the canonical "per-writer data loss"
	// signal; the slog.Warn at the drop site carries the per-row
	// context (event id, tenant id, traffic class, error) for
	// forensic root-cause. The S3 cold-path archive remains the
	// durable record of truth across every drop class below.
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
	// envelopes AND sustained ClickHouse outages overrunning the
	// in-memory shield. ConsecutiveErrors retains its original
	// meaning: "the writer is wedged" (rising count means flushes
	// keep failing); pair it with RequeuedBatches to distinguish
	// a recovering writer from one whose backlog cap is about to
	// trip.
	//
	// Counting model — what is and isn't accounted in DroppedRows:
	//
	//   - Append-rejected row: increments DroppedRows by 1.
	//     The row is judged bad (type mismatch, oversized value)
	//     and is NOT requeued; retrying a malformed row would
	//     loop forever.
	//   - All-rows-rejected batch (no Send): increments
	//     DroppedRows by the batch size, increments flushErrors,
	//     increments consecutiveErrors. The rows are bad and are
	//     NOT requeued (same rationale as above).
	//   - PrepareBatch failure (whole batch never reached the
	//     driver): the swapped-out batch is REQUEUED at the head
	//     of `pending` so the rows ride the next successful
	//     flush. Increments flushErrors, consecutiveErrors, and
	//     RequeuedBatches. No DroppedRows accounting unless the
	//     requeue exceeds the backlog cap and sheds rows; in
	//     that case the SHED rows are credited to both
	//     DroppedRows and BacklogDrops.
	//   - Partial-Append-then-Send-failure: the
	//     successfully-Appended-but-not-Sent rows (good rows
	//     the driver lost on the network) are REQUEUED at the
	//     head of `pending` for retry. The Append-rejected rows
	//     (genuinely bad) are credited to DroppedRows and NOT
	//     requeued. Increments flushErrors, consecutiveErrors,
	//     and RequeuedBatches.
	droppedRows uint64
	// partialDropFlushes counts flushOnce calls that completed
	// SUCCESSFULLY (prepared.Send returned nil) but had at least
	// one row rejected by Append. This is the per-flush companion
	// to droppedRows (which is per-row): dashboards that want to
	// alert on "the producer is emitting bad rows" can
	// `rate(PartialDropFlushes[5m]) > threshold` without conflating
	// the signal with sustained ClickHouse outages
	// (consecutiveErrors). Mutually-exclusive with all-rows-rejected
	// (which lands in flushErrors/consecutiveErrors instead).
	partialDropFlushes uint64
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

// backlogCapacity returns the cap on `pending` that the requeue
// path enforces, in rows: `BatchSize * MaxBacklogMultiplier`.
// Mirrors the qualifiedTable() pattern of guarding-at-the-use-
// site so a future caller that builds a Writer literal
// (bypassing New() / fillDefaults) can't accidentally collapse
// the cap to 0 — which would shed every row on every requeue.
// Whenever either field is non-positive (the only way the
// product can reach 0 here, since both are signed ints), we
// substitute the canonical default so the requeue logic
// continues to behave correctly under the same operational
// envelope the constructor advertises.
func (w *Writer) backlogCapacity() int {
	batch := w.cfg.BatchSize
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	mult := w.cfg.MaxBacklogMultiplier
	if mult <= 0 {
		mult = DefaultMaxBacklogMultiplier
	}
	return batch * mult
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
//
// Shutdown abandon contract: if the final flush fails (e.g. the
// ClickHouse cluster is down at the moment Stop is called), the
// failure paths inside flushOnce will requeue surviving rows back
// into `w.pending` via requeueBatch. Those rows are then lost on
// conn.Close() because there is no further flush loop to drain
// them — the S3 cold-path archive is the durable record of truth
// per the Write() doc comment. Without an explicit operator
// signal, an SRE reading logs after a graceful shutdown couldn't
// distinguish "all flushed cleanly" from "N rows abandoned in
// memory". We surface that count + bracket event IDs as a WARN
// right before conn.Close so the shutdown forensic trail is
// complete and matches the operator runbook contract for the
// failure-during-Stop scenario.
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
		// Surface any rows requeued by the failure path of the
		// final flush — those rows are about to be silently
		// discarded by conn.Close() and the SRE needs the
		// abandon signal in the log stream to correlate with
		// the S3 cold-path replay window.
		w.logShutdownAbandon(stopErr)
		if err := w.conn.Close(); err != nil && stopErr == nil {
			stopErr = fmt.Errorf("clickhouse: close: %w", err)
		}
	})
	return stopErr
}

// logShutdownAbandon emits a WARN with the count of rows left in
// `w.pending` after the final flush has returned. If the final
// flush succeeded, w.pending is empty and this is a no-op. If it
// failed and rows were requeued, this is the operator's explicit
// signal of "N rows abandoned at shutdown, replay from S3 cold
// path between event_id X and Y". `flushErr` is included so the
// SRE can correlate the abandon-count with the proximate cause
// (context deadline / ClickHouse outage / driver-level failure).
func (w *Writer) logShutdownAbandon(flushErr error) {
	w.mu.Lock()
	abandoned := len(w.pending)
	var firstEventID, lastEventID string
	if abandoned > 0 {
		firstEventID = w.pending[0].EventID.String()
		lastEventID = w.pending[abandoned-1].EventID.String()
	}
	w.mu.Unlock()
	if abandoned == 0 {
		return
	}
	w.logger.Warn("clickhouse: rows abandoned at shutdown after final flush failure",
		slog.Int("abandoned", abandoned),
		slog.String("first_event_id", firstEventID),
		slog.String("last_event_id", lastEventID),
		slog.Any("flush_error", flushErr))
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
	// RequeuedBatches is the cumulative count of flushOnce
	// failures that re-enqueued the swapped-out batch at the
	// head of `pending` so the rows would ride a subsequent
	// successful flush. A rising RequeuedBatches alongside a
	// flat ConsecutiveErrors means individual flushes are
	// hiccuping but recovering. A rising RequeuedBatches paired
	// with rising ConsecutiveErrors signals a sustained outage
	// where the backlog will eventually cap out and start
	// shedding into BacklogDrops / DroppedRows.
	RequeuedBatches uint64
	// BacklogDrops is the cumulative count of envelopes shed
	// from the HEAD of `pending` (oldest-first FIFO) when a
	// requeue would push the backlog past
	// `cfg.BatchSize * cfg.MaxBacklogMultiplier`. BacklogDrops
	// is also rolled into DroppedRows so the headline alert
	// signal remains DroppedRows; BacklogDrops is exposed
	// separately so dashboards can distinguish "a few bad rows"
	// (DroppedRows rising, BacklogDrops flat) from "sustained
	// outage shedding the in-memory shield" (BacklogDrops also
	// rising). When BacklogDrops > 0 operators MUST be diverting
	// to the S3 cold path until the writer recovers.
	BacklogDrops uint64
	// PartialDropFlushes is the cumulative count of flushes that
	// completed successfully (Send returned nil) but had at least
	// one row rejected by the driver's Append call. This is the
	// per-flush companion to DroppedRows (which is per-row), and
	// it is distinct from ConsecutiveErrors (which is
	// ClickHouse-health-only). Dashboards that want to alert on
	// "a producer is emitting bad envelopes" should target
	// `rate(PartialDropFlushes[5m]) > threshold` rather than
	// ConsecutiveErrors, which under the current semantics
	// resets to zero on a partially-successful flush. See the
	// alerting contract section on Writer.droppedRows for the
	// full rationale and migration guide.
	PartialDropFlushes uint64
}

// Stats returns a snapshot of writer counters.
func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		Pending:            len(w.pending),
		Flushed:            w.flushed,
		FlushErrors:        w.flushErrors,
		ConsecutiveErrors:  w.consecutiveErrors,
		DroppedRows:        w.droppedRows,
		RequeuedBatches:    w.requeuedBatches,
		BacklogDrops:       w.backlogDrops,
		PartialDropFlushes: w.partialDropFlushes,
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
		// Transient ClickHouse outage (driver-side reject before
		// any row was Appended). The swapped-out batch is
		// intact, so requeue it at the head of `pending` for the
		// next flush attempt; without this the batch would be
		// silently lost because it has already been swapped out
		// of `pending` above. Bounded by the backlog cap so a
		// sustained outage cannot OOM the writer — if the cap
		// trips, the oldest rows are shed and credited to
		// backlogDrops + droppedRows so the alerting contract
		// surfaces the loss.
		w.requeueBatch(batch, "prepare batch failed", requeueDrops{})
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	// Defensive Abort() on every non-Send exit so any
	// driver-side batch state is released. The current
	// clickhouse-go v2 native driver buffers the batch entirely
	// client-side and lets GC reclaim it — but a future driver
	// version (or a driver switch) could grow a server-side
	// batch state where leaving the batch un-aborted is a real
	// resource leak. Tracking `sent` lets us no-op the Abort
	// when Send() succeeded.
	sent := false
	defer func() {
		if !sent {
			_ = prepared.Abort()
		}
	}()
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
	// successfullyAppended collects the envelopes the driver
	// accepted on Append. If Send() then fails, these rows are
	// REQUEUED at the head of `pending` so the next flush can
	// retry them — they are not malformed (Append accepted),
	// they just lost the network race. The Append-rejected
	// rows are NOT included here; those are credited to
	// droppedRows and dropped permanently.
	successfullyAppended := make([]schema.Envelope, 0, len(batch))
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
		successfullyAppended = append(successfullyAppended, env)
	}
	if dropped == len(batch) {
		// Every row was rejected by Append — there is nothing
		// to send. Account the drops + the failure under the
		// mutex and bail out with the first Append error as the
		// caller-visible reason. We do NOT call prepared.Send()
		// in this branch because the clickhouse-go driver's
		// Send on an empty prepared batch is
		// implementation-defined; sending 0 rows is wasted
		// network and risks driver-specific surprises. We also
		// do NOT requeue — every row was judged malformed and
		// retrying would loop forever.
		w.mu.Lock()
		w.droppedRows += uint64(dropped)
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
		return fmt.Errorf("clickhouse: append row (all %d rows rejected): %w", dropped, firstAppendErr)
	}
	if err := prepared.Send(); err != nil {
		// Network-side Send failure after rows were Appended.
		// The good rows are not malformed — they just lost the
		// network race — so we REQUEUE them at the head of
		// `pending` so the next flush picks them up. Any
		// Append-rejected rows stay dropped (credited to
		// droppedRows inside requeueBatch). The reason string
		// distinguishes the "all rows Appended cleanly, Send
		// failed" case from the "some rows rejected by Append
		// AND Send failed" case so an operator reading the
		// requeue Info log can tell the two apart without
		// cross-referencing the dropped counter.
		reason := "send failed"
		if dropped > 0 {
			reason = "send failed after partial append"
		}
		w.requeueBatch(successfullyAppended, reason, requeueDrops{appendRejected: dropped})
		return fmt.Errorf("clickhouse: send batch: %w", err)
	}
	sent = true
	w.mu.Lock()
	w.flushed += uint64(len(batch) - dropped)
	w.droppedRows += uint64(dropped)
	w.consecutiveErrors = 0
	if dropped > 0 {
		// Per-flush partial-drop signal — distinct from
		// per-row droppedRows and from consecutiveErrors
		// (which under the documented contract resets on a
		// successful Send). Dashboards alert on this to
		// catch "a producer is emitting bad envelopes"
		// without conflating the signal with sustained
		// ClickHouse outages.
		w.partialDropFlushes++
	}
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

// shedLogSampleSize bounds the number of per-row WARN lines
// emitted when the backlog cap trips on a single requeue. During
// a sustained outage with a high-throughput producer the writer
// could otherwise emit one WARN per shed row per flush cycle —
// up to (BatchSize × MaxBacklogMultiplier) lines per cycle — and
// saturate the log pipeline. We keep the per-row WARN for the
// FIRST shedLogSampleSize rows so operators retain a sample for
// forensics, then emit a single aggregate WARN with the total
// shed count and the first / last shed event IDs.
const shedLogSampleSize = 8

// extraDrops bundles the per-row drop counts a failure-path
// caller wants applied alongside the requeue. Today only the
// Append-rejected-rows counter (incremented on
// partial-Append-then-Send-failure) lands here; keeping it as a
// dedicated field — rather than collapsing into a single int —
// documents the intent and leaves room for a future counter
// without breaking the call signature.
type requeueDrops struct {
	// appendRejected is the count of rows the driver rejected
	// during Append in this flush. These rows are NOT requeued
	// (they are judged malformed) but must be credited to
	// droppedRows so the alerting contract sees the loss.
	appendRejected int
}

// requeueBatch re-prepends `batch` to the head of `pending` so
// the rows ride the next successful flush, AND atomically
// updates every counter the failure-path caller would otherwise
// touch under a second lock acquisition (flushErrors,
// consecutiveErrors, droppedRows for Append-rejected rows).
// Consolidating the counter writes into the same lock as the
// requeue closes the otherwise-visible "RequeuedBatches
// incremented but FlushErrors not yet" window that a concurrent
// Stats() reader could observe.
//
// If the resulting backlog would exceed
// `cfg.BatchSize * cfg.MaxBacklogMultiplier`, the OLDEST rows
// (FIFO order, head of the merged slice) are shed and credited
// to both `droppedRows` and `backlogDrops`.
//
// The dual counting (DroppedRows + BacklogDrops) is intentional:
// DroppedRows is the canonical "per-writer data loss" signal that
// alerts fire on, while BacklogDrops is the forensic signal that
// distinguishes "bad rows arriving sporadically" from "sustained
// outage outlasting the in-memory shield" — the latter is the
// condition that requires diverting producers to the S3 cold path
// until the writer recovers.
func (w *Writer) requeueBatch(batch []schema.Envelope, reason string, drops requeueDrops) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Failure-path bookkeeping runs unconditionally — even if
	// `batch` is empty (the all-Append-rejected case can't reach
	// this helper, but a future caller might pass an empty good-
	// rows slice and the failure-counter contract should still
	// hold for that caller).
	w.flushErrors++
	w.consecutiveErrors++
	if drops.appendRejected > 0 {
		w.droppedRows += uint64(drops.appendRejected)
	}
	if len(batch) == 0 {
		return
	}
	// Re-prepend: the failed batch (oldest — was swapped out of
	// pending first) goes before any rows that arrived during
	// the flush attempt. This preserves the per-writer FIFO
	// order so the next flush sends the oldest rows first, which
	// matches the producer's ordering expectations.
	merged := make([]schema.Envelope, 0, len(batch)+len(w.pending))
	merged = append(merged, batch...)
	merged = append(merged, w.pending...)
	backlogCap := w.backlogCapacity()
	// shedFromBatch tracks how many rows from the failed `batch`
	// itself ended up shed (vs shed from the pre-existing
	// `w.pending` tail). Reported in the Info log so the operator
	// can read the actual surviving-from-batch count rather than
	// the attempt-count, which is what the previous log shape
	// implied.
	shedFromBatch := 0
	if len(merged) > backlogCap {
		shed := len(merged) - backlogCap
		shedFromBatch = shed
		if shedFromBatch > len(batch) {
			shedFromBatch = len(batch)
		}
		// Bounded sample of per-row WARN context so operators
		// can correlate the loss to the producer without
		// flooding the log pipeline during a sustained outage.
		// See [shedLogSampleSize] for the rationale.
		sample := shed
		if sample > shedLogSampleSize {
			sample = shedLogSampleSize
		}
		for i := 0; i < sample; i++ {
			env := merged[i]
			w.logger.Warn("clickhouse: shed row on backlog cap",
				slog.String("event_id", env.EventID.String()),
				slog.String("tenant_id", env.TenantID.String()),
				slog.String("event_class", string(env.EventClass)),
				slog.Int("cap", backlogCap),
				slog.String("reason", reason))
		}
		// Aggregate WARN with the total shed count + bracket
		// event IDs (first + last) so a downstream forensic
		// query can still find every shed row by walking the
		// telemetry stream between the two event IDs.
		w.logger.Warn("clickhouse: backlog cap exceeded, oldest rows shed",
			slog.Int("shed", shed),
			slog.Int("shed_from_batch", shedFromBatch),
			slog.Int("shed_from_pending", shed-shedFromBatch),
			slog.Int("sampled", sample),
			slog.Int("cap", backlogCap),
			slog.String("first_event_id", merged[0].EventID.String()),
			slog.String("last_event_id", merged[shed-1].EventID.String()),
			slog.String("reason", reason))
		merged = merged[shed:]
		w.backlogDrops += uint64(shed)
		w.droppedRows += uint64(shed)
	}
	w.pending = merged
	w.requeuedBatches++
	// `requeued` reports the rows from `batch` that ACTUALLY
	// survived the backlog-cap shed and are now sitting in
	// `w.pending` — not the attempt count. `attempted` retains
	// the original caller-supplied size so an operator can read
	// "tried to requeue X, kept X-Y after sheds, Y went to the
	// backlogDrops bucket". Without this split the Info log line
	// would overstate the surviving count whenever the cap trips.
	w.logger.Info("clickhouse: requeued batch after transient failure",
		slog.Int("attempted", len(batch)),
		slog.Int("requeued", len(batch)-shedFromBatch),
		slog.Int("shed_from_batch", shedFromBatch),
		slog.Int("backlog", len(merged)),
		slog.String("reason", reason))
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
