package hibernation

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// DefaultWakeQueueSize bounds the wake coordinator's hand-off queue. A
// full queue drops the wake signal for that observation (the next
// observation, or the controller backstop, re-triggers it), so a wake
// storm can never block the telemetry hot path that feeds Notify.
const DefaultWakeQueueSize = 1024

// Coordinator performs the fast, activity-triggered wake. It runs on
// every replica: the activity [Recorder] calls Notify on the first
// login / agent check-in / real request for a tenant, and the
// coordinator's worker rehydrates a parked tenant — clearing the
// registry marker so full telemetry resumes immediately, resuming its
// NATS subscriptions, and persisting the active state — while measuring
// the wake latency against the SLA.
//
// Notify is hot-path-cheap: an in-memory registry check plus, only for
// a tenant that is actually hibernated, a non-blocking channel send. The
// actual rehydration happens off the hot path on the worker goroutine.
type Coordinator struct {
	reg     *Registry
	store   Store
	subs    SubscriptionController
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
	queue   chan wakeReq
}

type wakeReq struct {
	tenantID uuid.UUID
	seen     time.Time
}

// CoordinatorOption customises a Coordinator at construction.
type CoordinatorOption func(*Coordinator)

// WithCoordinatorLogger sets the logger. A nil logger is ignored.
func WithCoordinatorLogger(l *slog.Logger) CoordinatorOption {
	return func(c *Coordinator) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithCoordinatorClock overrides the time source (tests).
func WithCoordinatorClock(now func() time.Time) CoordinatorOption {
	return func(c *Coordinator) {
		if now != nil {
			c.now = now
		}
	}
}

// WithCoordinatorSubscriptionController wires the NATS subscription
// manager so wake re-subscribes the tenant. A nil controller is ignored.
func WithCoordinatorSubscriptionController(s SubscriptionController) CoordinatorOption {
	return func(c *Coordinator) {
		if s != nil {
			c.subs = s
		}
	}
}

// WithCoordinatorMetrics wires the Prometheus surface (nil-safe).
func WithCoordinatorMetrics(m *Metrics) CoordinatorOption {
	return func(c *Coordinator) {
		c.metrics = m
	}
}

// WithWakeQueueSize sets the hand-off queue capacity. Values <= 0 are
// ignored.
func WithWakeQueueSize(n int) CoordinatorOption {
	return func(c *Coordinator) {
		if n > 0 {
			c.queue = make(chan wakeReq, n)
		}
	}
}

// NewCoordinator wires a Coordinator. reg and store must be non-nil.
func NewCoordinator(reg *Registry, store Store, opts ...CoordinatorOption) *Coordinator {
	c := &Coordinator{
		reg:    reg,
		store:  store,
		subs:   NoopSubscriptionController{},
		logger: slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		now:    time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	if c.queue == nil {
		c.queue = make(chan wakeReq, DefaultWakeQueueSize)
	}
	return c
}

// Notify is the hot-path entry point the activity recorder calls. For a
// hibernated tenant it enqueues a wake (non-blocking); for an active
// tenant it is a cheap registry read and returns. A nil coordinator or
// nil tenant is a no-op so callers need not branch on optional wiring.
func (c *Coordinator) Notify(tenantID uuid.UUID) {
	if c == nil || tenantID == uuid.Nil {
		return
	}
	if !c.reg.IsHibernated(tenantID) {
		return
	}
	select {
	case c.queue <- wakeReq{tenantID: tenantID, seen: c.now()}:
	default:
		// Queue full: drop this signal. The tenant stays parked until
		// the next observation or the controller backstop wakes it, so
		// a wake storm degrades latency, never correctness.
	}
}

// Wake rehydrates a single tenant synchronously and returns whether it
// was parked (woke == true) and how long rehydration took from `seen`.
// It is idempotent: waking an already-active tenant clears nothing and
// returns woke=false. Exported so tests can drive it directly and so a
// caller can wake on demand without the worker.
func (c *Coordinator) Wake(ctx context.Context, tenantID uuid.UUID, seen time.Time) (bool, time.Duration, error) {
	if tenantID == uuid.Nil {
		return false, 0, nil
	}
	if !c.reg.IsHibernated(tenantID) {
		return false, 0, nil
	}
	// Clear the registry marker first so the very next telemetry event
	// for this tenant is sampled at full fidelity — this is the part of
	// wake the user actually feels, so it happens before the slower
	// durable write and NATS resume.
	c.reg.Clear(tenantID)
	if err := c.subs.Resume(ctx, tenantID); err != nil {
		c.logger.Warn("hibernation: wake nats resume failed; continuing",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
	}
	if _, err := c.store.SetActive(ctx, tenantID, "woke on activity", c.now()); err != nil {
		c.logger.Warn("hibernation: wake persist active failed; registry already cleared",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
		return true, c.since(seen), err
	}
	latency := c.since(seen)
	c.metrics.incWake()
	c.metrics.observeWakeLatency(latency.Seconds())
	c.logger.Info("hibernation: tenant woke on activity",
		slog.String("tenant", tenantID.String()),
		slog.Duration("wake_latency", latency))
	return true, latency, nil
}

func (c *Coordinator) since(seen time.Time) time.Duration {
	if seen.IsZero() {
		return 0
	}
	d := c.now().Sub(seen)
	if d < 0 {
		return 0
	}
	return d
}

// Run drains the wake queue until ctx is cancelled, rehydrating each
// notified tenant. Callers run it in a goroutine.
func (c *Coordinator) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.queue:
			if _, _, err := c.Wake(ctx, req.tenantID, req.seen); err != nil && ctx.Err() == nil {
				c.logger.Warn("hibernation: wake failed",
					slog.String("tenant", req.tenantID.String()), slog.Any("error", err))
			}
		}
	}
}
