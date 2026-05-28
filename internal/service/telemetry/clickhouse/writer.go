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
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

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
		insertSQL: fmt.Sprintf("INSERT INTO %s", cfg.Table),
	}
	w.start()
	return w, nil
}

// EnsureSchema creates the telemetry table if it does not exist.
// The DDL is idempotent so callers can invoke this on every boot
// without conditional logic. Returns immediately if the table
// already exists.
func (w *Writer) EnsureSchema(ctx context.Context) error {
	ddl := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    event_id        UUID,
    tenant_id       UUID,
    device_id       UUID,
    site_id         Nullable(UUID),
    timestamp       DateTime64(6, 'UTC'),
    event_class     LowCardinality(String),
    platform        LowCardinality(String),
    schema_version  UInt8,
    payload         String,
    ingested_at     DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC')
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, event_class, timestamp, event_id)
SETTINGS index_granularity = 8192`, w.cfg.Table)
	if err := w.conn.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("clickhouse: ensure schema: %w", err)
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
		if err := prepared.Append(
			env.EventID,
			env.TenantID,
			env.DeviceID,
			siteID,
			env.Timestamp.UTC(),
			string(env.EventClass),
			string(env.Platform),
			env.SchemaVersion,
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
