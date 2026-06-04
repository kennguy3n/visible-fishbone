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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// hotPathMaxDeliver is the JetStream consumer's per-message retry
// budget on the hot path. After NumDelivered reaches this value,
// dispatch routes the message to the DLQ stream (preserving the
// raw bytes + headers + cause) and Terms it, rather than letting
// JetStream silently drop it once the consumer's MaxDeliver runs
// out.
//
// The value is intentionally kept as a package-level constant
// (not a Config knob) for two reasons:
//
//  1. The dispatch path's DLQ-on-final-attempt check must match
//     the consumer's MaxDeliver exactly — a single source of
//     truth eliminates the off-by-one bug class where the two
//     drift.
//  2. There is no operator workflow that benefits from tuning
//     this independently of the consumer config. Operators tune
//     AckWait + FetchBatchSize + NATS_PUBLISH_RETRY_ATTEMPTS;
//     MaxDeliver is a worker invariant.
const hotPathMaxDeliver = 5

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

// DLQPublisher republishes failed messages onto the DLQ stream so
// they remain queryable for forensics. Satisfied by
// `*nats.Publisher`. Required for production wiring: without it,
// undecodable payloads would be lost. Tests may pass a nil
// publisher in which case the dispatcher logs a loud warning and
// terminates the message (preserving the prior degraded-mode
// behaviour rather than forcing every test to wire a real DLQ).
type DLQPublisher interface {
	PublishToDLQ(
		ctx context.Context,
		originSubject string,
		data []byte,
		headers map[string]string,
		delivery uint64,
		cause error,
	) error
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
	Received       atomic.Uint64
	Deduplicated   atomic.Uint64
	Enriched       atomic.Uint64
	Decoded        atomic.Uint64
	DecodeErrors   atomic.Uint64
	HotWriteFails  atomic.Uint64
	Acked          atomic.Uint64
	Nacked         atomic.Uint64
	DLQPublished   atomic.Uint64 // bad payloads successfully routed to DLQ
	DLQPublishFail atomic.Uint64 // DLQ publish itself failed (data preserved by Nak retry)
}

// Snapshot returns a copy of the current counter values.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Received:       m.Received.Load(),
		Deduplicated:   m.Deduplicated.Load(),
		Enriched:       m.Enriched.Load(),
		Decoded:        m.Decoded.Load(),
		DecodeErrors:   m.DecodeErrors.Load(),
		HotWriteFails:  m.HotWriteFails.Load(),
		Acked:          m.Acked.Load(),
		Nacked:         m.Nacked.Load(),
		DLQPublished:   m.DLQPublished.Load(),
		DLQPublishFail: m.DLQPublishFail.Load(),
	}
}

// MetricsSnapshot is a point-in-time copy of Metrics.
type MetricsSnapshot struct {
	Received       uint64
	Deduplicated   uint64
	Enriched       uint64
	Decoded        uint64
	DecodeErrors   uint64
	HotWriteFails  uint64
	Acked          uint64
	Nacked         uint64
	DLQPublished   uint64
	DLQPublishFail uint64
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
// drain + tear down. Wire a DLQ publisher via WithDLQ to preserve
// undecodable payloads for forensics; without it, bad payloads are
// terminated and logged (degraded mode).
type Service struct {
	js      jetstream.JetStream
	cfg     Config
	natsCfg *config.NATS
	hot     HotWriter
	cold    ColdWriter
	dlq     DLQPublisher
	logger  *slog.Logger

	dedup   *dedupRing
	metrics Metrics

	// limiter enforces per-tenant ingestion rate budgets. nil
	// means "no limiter" — every event is dispatched as fast as
	// the writers can absorb it. Set via WithPerTenantLimiter.
	// When configured, dispatch will Nak (with a short backoff)
	// any envelope whose tenant has exhausted its budget for
	// the configured wait window, letting JetStream retry the
	// delivery once the bucket has refilled.
	limiter *PerTenantLimiter

	// limiterWaitBudget caps the per-message wait spent inside
	// the limiter before falling through to Nak. Zero → use
	// DefaultTenantWaitBudget. A very small wait budget biases
	// the consumer toward shedding (back-pressuring producers
	// via Nak/redelivery) rather than holding messages
	// in-flight, which is the right trade-off when JetStream
	// MaxAckPending is the controlling resource.
	limiterWaitBudget time.Duration

	// nakBackoff is the redelivery delay used when the limiter
	// rejects an envelope. Zero → use DefaultNakBackoff. The
	// value is intentionally larger than typical JetStream
	// AckWait so the redelivery does not collide with the next
	// fetch cycle.
	nakBackoff time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	// wg tracks the per-partition consumer goroutines so Stop can
	// wait for all of them to drain before returning.
	wg sync.WaitGroup
}

// worker is one partition's consumer state: the JetStream consumer
// it drains plus the limiter and dedup ring scoped to that
// partition's tenants. With a single partition there is exactly one
// worker whose limiter/dedup are the service-level instances, so
// behaviour is identical to the pre-partitioning consumer.
type worker struct {
	partition         int
	cons              jetstream.Consumer
	limiter           *PerTenantLimiter
	limiterWaitBudget time.Duration
	nakBackoff        time.Duration
	dedup             *dedupRing
}

// WithPerTenantLimiter wires a PerTenantLimiter onto the
// service. Once set, dispatch consults the limiter before
// invoking hot/cold writers and Nak's the message with a short
// backoff when the tenant has exhausted its budget. Pass nil to
// remove the limiter (e.g. for tests). Returns the receiver for
// fluent wiring.
//
// Wiring rationale: the limiter is intentionally optional and
// additive so the existing wire-up paths (cmd/sng-control,
// tests that pre-date the limiter) keep working without change
// — the only behavioural effect of NOT wiring a limiter is that
// individual tenants are free to swamp the writers, which is
// the prior (current) behaviour. Wire a limiter in production
// to bound per-tenant ingestion.
func (s *Service) WithPerTenantLimiter(limiter *PerTenantLimiter) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limiter = limiter
	return s
}

// WithLimiterWaitBudget overrides the per-message limiter wait
// budget. Useful in tests where the default DefaultTenantWaitBudget
// is too long for the test wall-clock. Zero restores the
// default.
func (s *Service) WithLimiterWaitBudget(d time.Duration) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limiterWaitBudget = d
	return s
}

// WithNakBackoff overrides the Nak redelivery delay used when
// the limiter rejects an envelope. Zero restores the default.
func (s *Service) WithNakBackoff(d time.Duration) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nakBackoff = d
	return s
}

// WithDLQ wires an explicit DLQ publisher onto the service. Once
// set, undecodable payloads are republished onto the DLQ stream
// (preserving raw bytes + headers + the decode error) before the
// original message is terminated. Idempotent.
//
// Wiring this is required in production: `msg.Term()` alone removes
// the message from the consumer's pending set but does NOT route it
// anywhere — JetStream has no built-in DLQ. Without WithDLQ a
// malformed payload (e.g. a publisher writing a wrong schema
// version) is silently lost.
func (s *Service) WithDLQ(p DLQPublisher) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dlq = p
	return s
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

	partitioner := sngnats.PartitionerFromConfig(s.natsCfg)
	workers, err := s.buildWorkers(ctx, partitioner)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})

	s.wg.Add(len(workers))
	for _, w := range workers {
		go s.loop(runCtx, w)
	}
	// Close s.done once every partition goroutine has drained, so
	// Stop can block on a single channel regardless of partition
	// count.
	go func() {
		s.wg.Wait()
		close(s.done)
	}()

	s.logger.Info("telemetry: consumer started",
		slog.Int("partitions", len(workers)),
		slog.String("durable", s.cfg.Durable))
	return nil
}

// buildWorkers ensures the durable consumer(s) and returns one
// worker per telemetry partition. With a single partition it ensures
// the historical SNG_TELEMETRY consumer and reuses the service-level
// limiter/dedup; with N partitions it ensures one consumer per
// SNG_TELEMETRY_<i> stream, each with a partition-scoped limiter and
// its own dedup ring. Must be called with s.mu held.
func (s *Service) buildWorkers(ctx context.Context, partitioner *sngnats.TenantPartitioner) ([]*worker, error) {
	// Use the canonical StreamName helper so the prefix
	// normalisation (TrimSpace, empty-default) matches
	// EnsureStreams. Without this a NATS_STREAM_PREFIX with
	// leading/trailing whitespace would lookup `"SNG _TELEMETRY"`
	// while EnsureStreams created `"SNG_TELEMETRY"`.
	if !partitioner.Enabled() {
		stream := sngnats.StreamName(s.cfg.StreamPrefix, sngnats.StreamSuffixTelemetry)
		cons, err := sngnats.EnsureConsumer(ctx, s.js, sngnats.ConsumerSpec{
			Stream:        stream,
			Durable:       s.cfg.Durable,
			FilterSubject: s.cfg.FilterSubject,
			MaxAckPending: s.cfg.BatchSize * 4,
			AckWait:       30 * time.Second,
			MaxDeliver:    hotPathMaxDeliver,
			Description:   "SNG telemetry hot-path consumer",
		})
		if err != nil {
			return nil, fmt.Errorf("telemetry: ensure consumer: %w", err)
		}
		return []*worker{{
			partition:         0,
			cons:              cons,
			limiter:           s.limiter,
			limiterWaitBudget: s.limiterWaitBudget,
			nakBackoff:        s.nakBackoff,
			dedup:             s.dedup,
		}}, nil
	}

	n := partitioner.Count()
	workers := make([]*worker, 0, n)
	for i := 0; i < n; i++ {
		stream := sngnats.StreamName(s.cfg.StreamPrefix, sngnats.TelemetryPartitionStreamSuffix(i))
		durable := fmt.Sprintf("%s-p%d", s.cfg.Durable, i)
		cons, err := sngnats.EnsureConsumer(ctx, s.js, sngnats.ConsumerSpec{
			Stream:        stream,
			Durable:       durable,
			FilterSubject: sngnats.TelemetryPartitionSubject(i),
			MaxAckPending: s.cfg.BatchSize * 4,
			AckWait:       30 * time.Second,
			MaxDeliver:    hotPathMaxDeliver,
			Description:   fmt.Sprintf("SNG telemetry hot-path consumer (partition %d/%d)", i, n),
		})
		if err != nil {
			return nil, fmt.Errorf("telemetry: ensure consumer (partition %d): %w", i, err)
		}
		// Each partition gets its own dedup ring sized to the
		// configured DedupRingSize. A tenant is pinned to exactly one
		// partition, so a per-partition ring never misses a duplicate
		// for that tenant. The operator-facing consequence: scaling
		// from 1 to N partitions multiplies *total* dedup capacity by
		// N (N rings of DedupRingSize each) without changing the
		// per-tenant dedup window — size DedupRingSize for a single
		// partition's tenant churn, not the whole fleet's.
		workers = append(workers, &worker{
			partition:         i,
			cons:              cons,
			limiter:           s.limiter.ForPartition(),
			limiterWaitBudget: s.limiterWaitBudget,
			nakBackoff:        s.nakBackoff,
			dedup:             newDedupRing(s.cfg.DedupRingSize),
		})
	}
	return workers, nil
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

// loop is the consumer goroutine for a single partition worker.
func (s *Service) loop(ctx context.Context, w *worker) {
	defer s.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		batch, err := w.cons.Fetch(s.cfg.BatchSize, jetstream.FetchMaxWait(s.cfg.MaxWait))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, jetstream.ErrNoMessages) {
				continue
			}
			// Brief backoff before retry — avoids spin if the
			// stream becomes briefly unavailable during a
			// rolling restart.
			s.logger.Warn("telemetry: fetch error",
				slog.Int("partition", w.partition),
				slog.Any("error", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		for msg := range batch.Messages() {
			s.dispatch(ctx, w, msg)
		}
		if fetchErr := batch.Error(); fetchErr != nil && !errors.Is(fetchErr, jetstream.ErrNoMessages) {
			s.logger.Warn("telemetry: batch error",
				slog.Int("partition", w.partition),
				slog.Any("error", fetchErr))
		}
	}
}

// dispatch processes a single delivery on the given partition worker.
func (s *Service) dispatch(ctx context.Context, w *worker, msg jetstream.Msg) {
	s.metrics.Received.Add(1)
	env, err := schema.Unmarshal(msg.Data())
	if err != nil {
		s.metrics.DecodeErrors.Add(1)
		s.logger.Warn("telemetry: decode error", slog.Any("error", err), slog.String("subject", msg.Subject()))
		// Bad payload — retries won't help (the bytes are
		// already broken). Preserve the raw bytes + headers in
		// the DLQ stream so an operator can inspect what the
		// publisher actually wrote, then Term() the message so
		// JetStream stops redelivering it. NB: msg.Term() alone
		// does NOT route to a DLQ — JetStream has no built-in
		// DLQ concept and our consumer's MaxDeliver=5 only
		// governs retry budget, not destination on terminal
		// failure. The DLQ is a separate stream that we must
		// publish to explicitly.
		s.routeBadPayloadToDLQ(msg, err)
		if termErr := msg.Term(); termErr != nil {
			s.logger.Warn("telemetry: term failed",
				slog.Any("error", termErr),
				slog.String("subject", msg.Subject()))
		}
		s.metrics.Nacked.Add(1)
		return
	}
	s.metrics.Decoded.Add(1)

	// Per-tenant rate-limit gate. Sits between decode and the
	// dedup check so a swamped tenant cannot push past their
	// budget by retrying — JetStream redelivers the message,
	// the limiter rejects it again until the bucket refills.
	// A nil limiter is a no-op (existing behaviour preserved).
	//
	// The worker's limiter/budgets are captured at Start (under
	// s.mu, in buildWorkers) and are immutable for the worker's
	// lifetime, so they are read lock-free here. The With* setters
	// (WithPerTenantLimiter, WithLimiterWaitBudget, WithNakBackoff)
	// only mutate the service-level template that buildWorkers
	// reads, so there is no race between dispatch and a concurrent
	// reconfiguration; reconfiguration after Start simply does not
	// affect already-running workers. See PR #38 Devin Review
	// round-4 BUG_0001 for the original lock-and-copy this replaces.
	limiter := w.limiter
	limiterWaitBudget := w.limiterWaitBudget
	nakBackoff := w.nakBackoff

	if limiter != nil {
		wait := limiterWaitBudget
		if wait <= 0 {
			wait = DefaultTenantWaitBudget
		}
		if err := limiter.WaitWithBudget(ctx, env.TenantID, wait); err != nil {
			// Both ErrTenantBlocked and non-Blocked (typically
			// ctx.Err() during shutdown) branches share the
			// same shape: Nak with the configured backoff so
			// the bucket can refill / the consumer can come
			// back. BUT: JetStream silently drops a message
			// once NumDelivered exceeds MaxDeliver, so when
			// the message has reached the end of its retry
			// budget the limiter rejection becomes a silent
			// drop unless we route it to the DLQ first. This
			// is the same defence-in-depth as the hot-write
			// path below (service.go:570-583). The DLQ
			// metadata carries a distinct cause flavour
			// ("rate-limit exhausted") so operators can
			// tell on triage whether the tenant needs a
			// budget bump or the writer needs a fix.
			if s.deliveryExhausted(msg) {
				s.routeRateLimitExhaustionToDLQ(msg, err)
				if termErr := msg.Term(); termErr != nil {
					s.logger.Warn("telemetry: term after rate-limit exhaustion failed",
						slog.Any("error", termErr),
						slog.String("event_id", env.EventID.String()))
				}
				s.metrics.Nacked.Add(1)
				return
			}
			// Default the backoff so a misconfigured Service
			// that left nakBackoff at zero doesn't trigger
			// immediate redelivery (which would defeat the
			// MaxDeliver budget on shutdown-cancel storms).
			delay := nakBackoff
			if delay <= 0 {
				delay = DefaultNakBackoff
			}
			_ = msg.NakWithDelay(delay)
			s.metrics.Nacked.Add(1)
			if errors.Is(err, ErrTenantBlocked) {
				s.logger.Debug("telemetry: tenant rate limit",
					slog.String("tenant_id", env.TenantID.String()),
					slog.String("event_id", env.EventID.String()))
			}
			return
		}
	}

	// Read-only dedup check: only suppress redelivery if we have
	// previously processed this EventID through to a successful
	// hot write. We deliberately do NOT add to the ring before
	// hot.Write — a transient writer failure followed by
	// redelivery would otherwise be silently dropped (the
	// redelivered copy would look like a duplicate and get acked
	// without ever being written). See PR5 review finding
	// BUG_pr-review-job-22734e9d8a4f4b9cbc7782ec198361ca_0001.
	if w.dedup.Seen(env.EventID) {
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
		// JetStream has no built-in DLQ — once a message exceeds
		// the consumer's MaxDeliver it is silently removed from
		// the pending set with no automatic routing anywhere. To
		// avoid silent data loss on a persistent hot-write
		// failure (e.g. ClickHouse down for >MaxDeliver redelivery
		// cycles), check the delivery count *before* Nak'ing: when
		// this delivery would be the last (NumDelivered >=
		// hotPathMaxDeliver), route the raw envelope bytes to the
		// DLQ stream and Term() the message. The DLQ entry
		// preserves the source subject, headers, delivery count,
		// and cause so an operator can replay it after the hot
		// writer recovers.
		if s.deliveryExhausted(msg) {
			s.routeHotWriteFailureToDLQ(msg, err)
			if termErr := msg.Term(); termErr != nil {
				s.logger.Warn("telemetry: term after hot-write exhaustion failed",
					slog.Any("error", termErr),
					slog.String("event_id", env.EventID.String()))
			}
			// Counted as Nacked to keep the metric semantics
			// consistent (the message did not reach the hot
			// store), with a separate DLQPublished counter
			// distinguishing "DLQ'd" from "silently dropped".
			s.metrics.Nacked.Add(1)
			return
		}
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
	w.dedup.Add(env.EventID)
	s.metrics.Enriched.Add(1)
	if err := msg.Ack(); err != nil {
		s.logger.Warn("telemetry: ack failed", slog.Any("error", err))
		return
	}
	s.metrics.Acked.Add(1)
}

// deliveryExhausted reports whether the message has reached the
// consumer's MaxDeliver budget on this delivery. NumDelivered is
// 1-based (first delivery is 1), so the message has no further
// retries available when NumDelivered >= hotPathMaxDeliver.
//
// A message without metadata (synthetic test message, or a NATS
// client that strips metadata) is treated as NOT exhausted so the
// fallback path (Nak + redeliver) still applies — the existing
// safer default. The hot-write DLQ routing is a defence in depth;
// missing metadata shouldn't promote a transient failure to a
// permanent drop.
func (s *Service) deliveryExhausted(msg jetstream.Msg) bool {
	md, err := msg.Metadata()
	if err != nil || md == nil {
		return false
	}
	return md.NumDelivered >= hotPathMaxDeliver
}

// routeHotWriteFailureToDLQ publishes a hot-write-exhausted message
// onto the DLQ stream so the raw envelope bytes are preserved for
// replay after the hot writer recovers. Best-effort: a DLQ publish
// failure is logged + counted but does NOT block the Term() that
// follows. The alternative (retry the DLQ publish from inside
// dispatch) would just hold up the consumer loop while the DLQ
// itself is unhealthy, with no path forward — the original message
// is already past its MaxDeliver budget.
//
// Like routeBadPayloadToDLQ, this derives publishCtx from
// context.Background() so a graceful-shutdown that lands
// mid-dispatch doesn't expire the 2s DLQ budget and force a Term()
// with no forensic copy.
func (s *Service) routeHotWriteFailureToDLQ(msg jetstream.Msg, cause error) {
	s.mu.Lock()
	dlq := s.dlq
	s.mu.Unlock()
	if dlq == nil {
		s.logger.Warn("telemetry: hot-write exhausted, no DLQ publisher wired (message dropped)",
			slog.String("subject", msg.Subject()),
			slog.Any("hot_write_error", cause),
			slog.Int("payload_bytes", len(msg.Data())))
		return
	}
	headers := flattenMsgHeaders(msg)
	publishCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	delivery := uint64(0)
	if md, mdErr := msg.Metadata(); mdErr == nil && md != nil {
		delivery = md.NumDelivered
	}
	if err := dlq.PublishToDLQ(publishCtx, msg.Subject(), msg.Data(), headers, delivery, cause); err != nil {
		s.metrics.DLQPublishFail.Add(1)
		s.logger.Warn("telemetry: hot-write DLQ publish failed (message will be dropped)",
			slog.Any("dlq_error", err),
			slog.Any("hot_write_error", cause),
			slog.String("subject", msg.Subject()))
		return
	}
	s.metrics.DLQPublished.Add(1)
	s.logger.Info("telemetry: hot-write exhausted, routed to DLQ",
		slog.String("subject", msg.Subject()),
		slog.Any("hot_write_error", cause),
		slog.Uint64("num_delivered", delivery))
}

// routeRateLimitExhaustionToDLQ publishes a message whose per-tenant
// rate-limit budget has been exhausted across the consumer's
// MaxDeliver attempts. Mirrors routeHotWriteFailureToDLQ in shape
// but carries a distinct log surface + cause prefix so DLQ
// dashboards can split "tenant needs a budget bump" from "writer
// is down" without dumping the raw cause string. Best-effort: a
// DLQ publish failure is logged + counted but does NOT block the
// Term() that follows.
//
// publishCtx derives from context.Background() for the same reason
// as the hot-write path — a graceful-shutdown that lands mid-
// dispatch shouldn't expire the 2s DLQ budget and force a Term()
// with no forensic copy.
func (s *Service) routeRateLimitExhaustionToDLQ(msg jetstream.Msg, cause error) {
	s.mu.Lock()
	dlq := s.dlq
	s.mu.Unlock()
	if dlq == nil {
		s.logger.Warn("telemetry: rate-limit exhausted, no DLQ publisher wired (message dropped)",
			slog.String("subject", msg.Subject()),
			slog.Any("rate_limit_error", cause),
			slog.Int("payload_bytes", len(msg.Data())))
		return
	}
	headers := flattenMsgHeaders(msg)
	publishCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	delivery := uint64(0)
	if md, mdErr := msg.Metadata(); mdErr == nil && md != nil {
		delivery = md.NumDelivered
	}
	// Wrap so the DLQ entry's cause string is self-describing.
	wrapped := fmt.Errorf("rate-limit exhausted: %w", cause)
	if err := dlq.PublishToDLQ(publishCtx, msg.Subject(), msg.Data(), headers, delivery, wrapped); err != nil {
		s.metrics.DLQPublishFail.Add(1)
		s.logger.Warn("telemetry: rate-limit DLQ publish failed (message will be dropped)",
			slog.Any("dlq_error", err),
			slog.Any("rate_limit_error", cause),
			slog.String("subject", msg.Subject()))
		return
	}
	s.metrics.DLQPublished.Add(1)
	s.logger.Info("telemetry: rate-limit exhausted, routed to DLQ",
		slog.String("subject", msg.Subject()),
		slog.Any("rate_limit_error", cause),
		slog.Uint64("num_delivered", delivery))
}

// routeBadPayloadToDLQ republishes a decode-failed message onto the
// DLQ stream so its bytes are preserved for forensics. If no DLQ
// publisher is wired (degraded mode), it logs a loud warning so the
// data loss is at least observable; in production the wiring is
// mandatory.
//
// Best-effort: a DLQ publish failure is logged + counted but does
// not block the Term() of the original message. The alternative
// (Nak the original so it redelivers and we can retry the DLQ
// publish) would just spin until MaxDeliver runs out, ending up in
// the same Term() state with one more delivery attempt logged —
// not worth the throughput hit when the DLQ itself is unhealthy.
//
// The publish context is deliberately derived from
// context.Background() rather than the dispatch loop's runCtx.
// runCtx is cancelled by Stop() during graceful shutdown; if the
// shutdown signal lands while a bad-payload dispatch is in flight,
// inheriting runCtx would expire `publishCtx` immediately, fail
// the DLQ publish, and then proceed to Term() the message —
// permanently removing it from JetStream with NO forensic copy.
// Decoupling from runCtx lets the DLQ publish complete on its own
// 2-second budget independent of shutdown; the worst case under a
// genuinely unresponsive DLQ is that Stop() waits an extra ~2s for
// the dispatch goroutine to drain, which is well within the
// shutdown SLA.
func (s *Service) routeBadPayloadToDLQ(msg jetstream.Msg, cause error) {
	s.mu.Lock()
	dlq := s.dlq
	s.mu.Unlock()
	if dlq == nil {
		// Degraded mode — preserve the message ID + subject in
		// the log so operators can at least correlate with
		// upstream traces.
		s.logger.Warn("telemetry: undecodable payload dropped (no DLQ publisher wired)",
			slog.String("subject", msg.Subject()),
			slog.Any("error", cause),
			slog.Int("payload_bytes", len(msg.Data())))
		return
	}
	headers := flattenMsgHeaders(msg)
	publishCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	delivery := uint64(0)
	if md, mdErr := msg.Metadata(); mdErr == nil && md != nil {
		delivery = md.NumDelivered
	}
	if err := dlq.PublishToDLQ(publishCtx, msg.Subject(), msg.Data(), headers, delivery, cause); err != nil {
		s.metrics.DLQPublishFail.Add(1)
		s.logger.Warn("telemetry: DLQ publish failed (undecodable payload dropped)",
			slog.Any("dlq_error", err),
			slog.Any("decode_error", cause),
			slog.String("subject", msg.Subject()))
		return
	}
	s.metrics.DLQPublished.Add(1)
	s.logger.Info("telemetry: undecodable payload routed to DLQ",
		slog.String("subject", msg.Subject()),
		slog.Any("decode_error", cause))
}

// flattenMsgHeaders converts NATS multi-value headers into the
// single-value map expected by Publisher.PublishToDLQ. NATS allows
// the same header key to appear multiple times; we join with comma
// (RFC 7230-style) so no information is lost in the DLQ envelope.
func flattenMsgHeaders(msg jetstream.Msg) map[string]string {
	h := msg.Headers()
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		switch len(vs) {
		case 0:
			out[k] = ""
		case 1:
			out[k] = vs[0]
		default:
			out[k] = strings.Join(vs, ",")
		}
	}
	return out
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
