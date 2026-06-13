package hibernation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// Controller is the leader-only reconcile loop that hibernates dormant
// tenants and (as a backstop) wakes tenants that have become active
// again. It is wired via leader.RunIfLeader so it runs on exactly one
// replica; the per-replica [Syncer] propagates its decisions to every
// replica's [Registry], and the [Coordinator] handles the fast,
// activity-triggered wake on any replica.
//
// Each cycle classifies every tenant by its last-active signal (the
// same [tenancy.Classifier] the SweepPlanner uses) and:
//
//   - hibernates a tenant that has reached [tenancy.TierDormant] and is
//     not already hibernated, and
//   - wakes a tenant that is hibernated but has climbed back out of the
//     dormant tier.
//
// Fail-safe: a hibernate action (cold-archive + NATS condense) that
// errors leaves the tenant active and is retried next cycle, never
// force-parked on a half-applied state. Waking is best-effort and
// always marks the tenant active (the safe direction is MORE work).
type Controller struct {
	classifier tenancy.Classifier
	store      Store
	activity   ActivityLister
	cold       ColdArchiver
	subs       SubscriptionController
	metrics    *Metrics
	logger     *slog.Logger
	now        func() time.Time
}

// Option customises a Controller at construction.
type Option func(*Controller)

// WithLogger sets the logger. A nil logger is ignored (default discards).
func WithLogger(l *slog.Logger) Option {
	return func(c *Controller) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithClock overrides the time source (tests). A nil clock is ignored.
func WithClock(now func() time.Time) Option {
	return func(c *Controller) {
		if now != nil {
			c.now = now
		}
	}
}

// WithColdArchiver wires the cold-archive trigger. A nil archiver is
// ignored (the default no-op is retained).
func WithColdArchiver(a ColdArchiver) Option {
	return func(c *Controller) {
		if a != nil {
			c.cold = a
		}
	}
}

// WithSubscriptionController wires the NATS subscription manager. A nil
// controller is ignored (the default no-op is retained).
func WithSubscriptionController(s SubscriptionController) Option {
	return func(c *Controller) {
		if s != nil {
			c.subs = s
		}
	}
}

// WithMetrics wires the Prometheus surface. A nil *Metrics is fine (the
// record methods no-op).
func WithMetrics(m *Metrics) Option {
	return func(c *Controller) {
		c.metrics = m
	}
}

// New constructs a Controller. classifier, store and activity must be
// usable; store and activity must be non-nil (a controller with no
// backing store or activity source is a wiring bug).
func New(classifier tenancy.Classifier, store Store, activity ActivityLister, opts ...Option) (*Controller, error) {
	if store == nil || activity == nil {
		return nil, fmt.Errorf("hibernation: controller requires non-nil store and activity lister")
	}
	c := &Controller{
		classifier: classifier,
		store:      store,
		activity:   activity,
		cold:       NoopColdArchiver{},
		subs:       NoopSubscriptionController{},
		logger:     slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		now:        time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// RunOnce performs one reconcile cycle. It is exported so the wiring can
// drive a single cycle (e.g. on startup) and so tests can step the
// controller deterministically.
func (c *Controller) RunOnce(ctx context.Context) error {
	acts, err := c.activity.ListTenantActivity(ctx)
	if err != nil {
		return fmt.Errorf("hibernation: list activity: %w", err)
	}
	recs, err := c.store.List(ctx)
	if err != nil {
		return fmt.Errorf("hibernation: list state: %w", err)
	}
	hibernated := make(map[uuid.UUID]bool, len(recs))
	for _, rec := range recs {
		hibernated[rec.TenantID] = rec.State.Hibernated()
	}

	now := c.now()
	count := 0
	for _, act := range acts {
		if act.ID == uuid.Nil {
			continue
		}
		tier := c.classifier.Classify(now, act.LastActiveAt)
		isHibernated := hibernated[act.ID]
		switch {
		case tier == tenancy.TierDormant && !isHibernated:
			if c.hibernate(ctx, act.ID, tier) {
				count++
			}
		case tier != tenancy.TierDormant && isHibernated:
			c.wake(ctx, act.ID, "tenant left dormant tier: "+tier.String())
		case isHibernated:
			count++
		}
	}
	c.metrics.setHibernatedCount(count)
	return nil
}

// hibernate applies the hibernate actions and, only if they all
// succeed, persists the hibernated state. Returns true when the tenant
// ends the call hibernated. A failed action leaves the tenant active
// (fail-safe) and is retried next cycle.
func (c *Controller) hibernate(ctx context.Context, tenantID uuid.UUID, tier tenancy.Tier) bool {
	if err := c.cold.ArchiveTenant(ctx, tenantID); err != nil {
		c.metrics.incHibernateFailure()
		c.logger.Warn("hibernation: cold archive failed; tenant stays active",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
		return false
	}
	if err := c.subs.Condense(ctx, tenantID); err != nil {
		c.metrics.incHibernateFailure()
		c.logger.Warn("hibernation: nats condense failed; tenant stays active",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
		return false
	}
	reason := "reached " + tier.String() + " tier"
	if _, err := c.store.SetHibernated(ctx, tenantID, reason, c.now()); err != nil {
		c.metrics.incHibernateFailure()
		c.logger.Warn("hibernation: persist hibernated state failed; tenant stays active",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
		return false
	}
	c.metrics.incHibernate()
	c.logger.Info("hibernation: tenant hibernated",
		slog.String("tenant", tenantID.String()), slog.String("reason", reason))
	return true
}

// wake is the controller's backstop wake (the fast path is the
// Coordinator). It resumes subscriptions best-effort and always marks
// the tenant active — the safe direction is more work.
func (c *Controller) wake(ctx context.Context, tenantID uuid.UUID, reason string) {
	if err := c.subs.Resume(ctx, tenantID); err != nil {
		c.logger.Warn("hibernation: nats resume failed; marking active anyway",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
	}
	if _, err := c.store.SetActive(ctx, tenantID, reason, c.now()); err != nil {
		c.logger.Warn("hibernation: persist active state failed",
			slog.String("tenant", tenantID.String()), slog.Any("error", err))
		return
	}
	c.metrics.incWake()
	c.logger.Info("hibernation: tenant woken (controller backstop)",
		slog.String("tenant", tenantID.String()), slog.String("reason", reason))
}

// Run drives RunOnce immediately, then on every tick until ctx is
// cancelled. A cycle error is logged and retried next tick — a failed
// reconcile changes nothing (no partial parking), so the platform keeps
// doing full work for any tenant it could not classify or persist.
func (c *Controller) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	if err := c.RunOnce(ctx); err != nil && ctx.Err() == nil {
		c.logger.Warn("hibernation: reconcile cycle failed", slog.Any("error", err))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.RunOnce(ctx); err != nil && ctx.Err() == nil {
				c.logger.Warn("hibernation: reconcile cycle failed", slog.Any("error", err))
			}
		}
	}
}
