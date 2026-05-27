// Package telemetry implements the JetStream pull-consumer that
// drains the SNG_TELEMETRY stream. The hot path:
//
//  1. Fetch a batch of messages with FetchBatchSize / FetchMaxWait
//     budget from config.
//  2. Decode the schema.Envelope (MessagePack).
//  3. Skip duplicates via an in-memory ring-buffer keyed by
//     EventID (configurable size; the JetStream-side dedup window
//     stops re-publishes within the same minute, but the in-process
//     ring is a defence in depth for cross-restart redelivery).
//  4. Hand the decoded envelope + raw payload to the configured
//     hot-path Writer (future ClickHouse) and ColdWriter
//     (future S3). Both are interfaces so callers can swap them.
//  5. Ack on success; Nak on transient writer error (the consumer's
//     MaxDeliver eventually routes hard failures to the DLQ).
//
// The service is started/stopped via Start/Stop and integrates with
// the control-plane's graceful-shutdown context in main.go.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// HotWriter is the synchronous sink for hot-path telemetry events.
// Implementations should be fast (sub-ms) and idempotent on the
// envelope's EventID. The ClickHouse writer lands in PR9.
type HotWriter interface {
	Write(ctx context.Context, env schema.Envelope) error
}

// ColdWriter is the asynchronous sink for archived telemetry
// payloads (raw MessagePack + envelope metadata). The S3 batch
// writer lands in PR9. Until then, NoopColdWriter is the default.
type ColdWriter interface {
	Archive(ctx context.Context, env schema.Envelope, raw []byte) error
}

// NoopHotWriter is the zero-value placeholder hot writer — logs
// at debug level and acks. Used when no real writer is wired yet
// so the service is still functional end-to-end.
type NoopHotWriter struct {
	Logger *slog.Logger
}

// Write logs the envelope at debug level and returns nil.
func (n NoopHotWriter) Write(_ context.Context, env schema.Envelope) error {
	if n.Logger != nil {
		n.Logger.Debug("telemetry: hot write (noop)",
			slog.String("event_id", env.EventID.String()),
			slog.String("tenant_id", env.TenantID.String()),
			slog.String("class", string(env.EventClass)))
	}
	return nil
}

// NoopColdWriter is the zero-value placeholder cold writer.
type NoopColdWriter struct{}

// Archive returns nil.
func (NoopColdWriter) Archive(_ context.Context, _ schema.Envelope, _ []byte) error { return nil }

// Metrics is the counter set updated by the consumer loop. All
// fields are atomic — safe to read concurrently while the consumer
// runs.
type Metrics struct {
	Received      atomic.Uint64
	Deduplicated  atomic.Uint64
	Enriched      atomic.Uint64
	Decoded       atomic.Uint64
	DecodeErrors  atomic.Uint64
	HotWriteFails atomic.Uint64
	Acked         atomic.Uint64
	Nacked        atomic.Uint64
}

// Snapshot returns a copy of the current counter values.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Received:      m.Received.Load(),
		Deduplicated:  m.Deduplicated.Load(),
		Enriched:      m.Enriched.Load(),
		Decoded:       m.Decoded.Load(),
		DecodeErrors:  m.DecodeErrors.Load(),
		HotWriteFails: m.HotWriteFails.Load(),
		Acked:         m.Acked.Load(),
		Nacked:        m.Nacked.Load(),
	}
}

// MetricsSnapshot is a point-in-time copy of Metrics.
type MetricsSnapshot struct {
	Received      uint64
	Deduplicated  uint64
	Enriched      uint64
	Decoded       uint64
	DecodeErrors  uint64
	HotWriteFails uint64
	Acked         uint64
	Nacked        uint64
}

// Config tunes the consumer loop.
type Config struct {
	StreamPrefix  string
	Durable       string
	FilterSubject string
	BatchSize     int
	MaxWait       time.Duration
	DedupRingSize int
}

// fillDefaults applies sane defaults to zero-value fields.
func (c *Config) fillDefaults(cfg *config.NATS) {
	if c.StreamPrefix == "" {
		c.StreamPrefix = cfg.StreamPrefix
	}
	if c.StreamPrefix == "" {
		c.StreamPrefix = "SNG"
	}
	if c.Durable == "" {
		c.Durable = "sng-control-telemetry-consumer"
	}
	if c.FilterSubject == "" {
		c.FilterSubject = "sng.*.telemetry.>"
	}
	if c.BatchSize <= 0 {
		c.BatchSize = cfg.FetchBatchSize
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}
	if c.MaxWait <= 0 {
		c.MaxWait = cfg.FetchMaxWait
	}
	if c.MaxWait <= 0 {
		c.MaxWait = 200 * time.Millisecond
	}
	if c.DedupRingSize <= 0 {
		c.DedupRingSize = 4096
	}
}

// Service is the telemetry consumer. Construct via New, then call
// Start (idempotent) to spawn the consumer goroutine, and Stop to
// drain + tear down.
type Service struct {
	js      jetstream.JetStream
	cfg     Config
	natsCfg *config.NATS
	hot     HotWriter
	cold    ColdWriter
	logger  *slog.Logger

	dedup   *dedupRing
	metrics Metrics

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New constructs a Service. None of the parameters may be nil
// except the writers (defaults are substituted).
func New(
	js jetstream.JetStream,
	natsCfg *config.NATS,
	svcCfg Config,
	hot HotWriter,
	cold ColdWriter,
	logger *slog.Logger,
) (*Service, error) {
	if js == nil {
		return nil, errors.New("telemetry: jetstream is required")
	}
	if natsCfg == nil {
		return nil, errors.New("telemetry: nats config is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	svcCfg.fillDefaults(natsCfg)
	if hot == nil {
		hot = NoopHotWriter{Logger: logger}
	}
	if cold == nil {
		cold = NoopColdWriter{}
	}
	return &Service{
		js:      js,
		cfg:     svcCfg,
		natsCfg: natsCfg,
		hot:     hot,
		cold:    cold,
		logger:  logger,
		dedup:   newDedupRing(svcCfg.DedupRingSize),
	}, nil
}

// MetricsSnapshot returns the current metric counters.
func (s *Service) MetricsSnapshot() MetricsSnapshot { return s.metrics.Snapshot() }

// Start ensures the SNG_TELEMETRY stream + the durable consumer
// exist and spawns the dispatch goroutine. Idempotent — calling
// Start twice is a no-op if already running.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}

	// Use the canonical StreamName helper so the prefix
	// normalisation (TrimSpace, empty-default) matches
	// EnsureStreams. Without this a NATS_STREAM_PREFIX with
	// leading/trailing whitespace would lookup `"SNG _TELEMETRY"`
	// while EnsureStreams created `"SNG_TELEMETRY"`.
	stream := sngnats.StreamName(s.cfg.StreamPrefix, sngnats.StreamSuffixTelemetry)
	cons, err := sngnats.EnsureConsumer(ctx, s.js, sngnats.ConsumerSpec{
		Stream:        stream,
		Durable:       s.cfg.Durable,
		FilterSubject: s.cfg.FilterSubject,
		MaxAckPending: s.cfg.BatchSize * 4,
		AckWait:       30 * time.Second,
		MaxDeliver:    5,
		Description:   "SNG telemetry hot-path consumer",
	})
	if err != nil {
		return fmt.Errorf("telemetry: ensure consumer: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})

	go s.loop(runCtx, cons)
	s.logger.Info("telemetry: consumer started",
		slog.String("stream", stream),
		slog.String("durable", s.cfg.Durable))
	return nil
}

// Stop cancels the consumer loop and waits for it to drain in-flight
// messages. Safe to call multiple times.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loop is the consumer goroutine.
func (s *Service) loop(ctx context.Context, cons jetstream.Consumer) {
	defer close(s.done)
	for {
		if ctx.Err() != nil {
			return
		}
		batch, err := cons.Fetch(s.cfg.BatchSize, jetstream.FetchMaxWait(s.cfg.MaxWait))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, jetstream.ErrNoMessages) {
				continue
			}
			// Brief backoff before retry — avoids spin if the
			// stream becomes briefly unavailable during a
			// rolling restart.
			s.logger.Warn("telemetry: fetch error", slog.Any("error", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		for msg := range batch.Messages() {
			s.dispatch(ctx, msg)
		}
		if fetchErr := batch.Error(); fetchErr != nil && !errors.Is(fetchErr, jetstream.ErrNoMessages) {
			s.logger.Warn("telemetry: batch error", slog.Any("error", fetchErr))
		}
	}
}

// dispatch processes a single delivery.
func (s *Service) dispatch(ctx context.Context, msg jetstream.Msg) {
	s.metrics.Received.Add(1)
	env, err := schema.Unmarshal(msg.Data())
	if err != nil {
		s.metrics.DecodeErrors.Add(1)
		s.logger.Warn("telemetry: decode error", slog.Any("error", err), slog.String("subject", msg.Subject()))
		// Bad payload — terminate so it lands in the DLQ via
		// MaxDeliver=1 semantics; we don't want to retry an
		// undecodable message.
		_ = msg.Term()
		s.metrics.Nacked.Add(1)
		return
	}
	s.metrics.Decoded.Add(1)

	// Read-only dedup check: only suppress redelivery if we have
	// previously processed this EventID through to a successful
	// hot write. We deliberately do NOT add to the ring before
	// hot.Write — a transient writer failure followed by
	// redelivery would otherwise be silently dropped (the
	// redelivered copy would look like a duplicate and get acked
	// without ever being written). See PR5 review finding
	// BUG_pr-review-job-22734e9d8a4f4b9cbc7782ec198361ca_0001.
	if s.dedup.Seen(env.EventID) {
		s.metrics.Deduplicated.Add(1)
		_ = msg.Ack()
		s.metrics.Acked.Add(1)
		return
	}

	if err := s.hot.Write(ctx, env); err != nil {
		s.metrics.HotWriteFails.Add(1)
		s.logger.Warn("telemetry: hot write failed",
			slog.Any("error", err),
			slog.String("event_id", env.EventID.String()))
		// Transient error — let the consumer redeliver up to
		// MaxDeliver, then DLQ.
		_ = msg.NakWithDelay(2 * time.Second)
		s.metrics.Nacked.Add(1)
		return
	}
	if err := s.cold.Archive(ctx, env, msg.Data()); err != nil {
		// Cold-path failure is logged but does NOT block ack —
		// the hot path is the source of truth; archive is best
		// effort. A separate reconciler can re-archive from the
		// hot store later.
		s.logger.Warn("telemetry: cold archive failed",
			slog.Any("error", err),
			slog.String("event_id", env.EventID.String()))
	}
	// Only record dedup *after* the hot write succeeded. This way
	// a subsequent redelivery of a transient-failure message is
	// allowed to retry the write rather than being silently acked.
	s.dedup.Add(env.EventID)
	s.metrics.Enriched.Add(1)
	if err := msg.Ack(); err != nil {
		s.logger.Warn("telemetry: ack failed", slog.Any("error", err))
		return
	}
	s.metrics.Acked.Add(1)
}

// dedupRing is a fixed-size hash-set of EventIDs used to skip
// duplicate deliveries within a process lifetime. Pure Go, no
// external dependencies. Not LRU — older entries fall out as new
// ones come in.
type dedupRing struct {
	mu   sync.Mutex
	seen map[uuid.UUID]struct{}
	ring []uuid.UUID
	head int
	cap  int
}

func newDedupRing(capacity int) *dedupRing {
	if capacity <= 0 {
		capacity = 1024
	}
	return &dedupRing{
		seen: make(map[uuid.UUID]struct{}, capacity),
		ring: make([]uuid.UUID, capacity),
		cap:  capacity,
	}
}

// Seen reports whether id has been recorded as a successfully
// processed event. It does NOT mutate the ring — use Add to record.
//
// Splitting the check from the insertion is what guarantees we never
// silently swallow a redelivery whose previous attempt failed before
// reaching Add (see dispatch()).
func (r *dedupRing) Seen(id uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.seen[id]
	return ok
}

// Add records id as processed, evicting the oldest entry to make
// room. Idempotent — adding the same id twice is a no-op.
func (r *dedupRing) Add(id uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[id]; ok {
		return
	}
	if old := r.ring[r.head]; old != uuid.Nil {
		delete(r.seen, old)
	}
	r.ring[r.head] = id
	r.seen[id] = struct{}{}
	r.head = (r.head + 1) % r.cap
}

// SeenOrAdd is retained for tests/back-compat. It is equivalent to
// `if r.Seen(id) { return true } else { r.Add(id); return false }`
// but runs under a single lock. New code SHOULD use Seen + Add
// explicitly so the failure-mode invariant is visible at the call
// site.
func (r *dedupRing) SeenOrAdd(id uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[id]; ok {
		return true
	}
	if old := r.ring[r.head]; old != uuid.Nil {
		delete(r.seen, old)
	}
	r.ring[r.head] = id
	r.seen[id] = struct{}{}
	r.head = (r.head + 1) % r.cap
	return false
}
