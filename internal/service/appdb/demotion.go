package appdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DemotionSignal enumerates the runtime signals that can demote a
// trusted app. The classifier on the edge / agent emits these via
// NATS; the demotion engine subscribes and turns them into overrides.
type DemotionSignal string

const (
	// SignalThreatFeed — the domain matched a TI / DNS-reputation
	// feed. Global demotion (every tenant) because the signal is
	// not tenant-specific.
	SignalThreatFeed DemotionSignal = "threat_feed"
	// SignalCertPinMismatch — agents reported the served cert
	// chain did not match the expected pin. Global demotion
	// (vendors may have rotated; operator notification flag is
	// raised).
	SignalCertPinMismatch DemotionSignal = "cert_pin_mismatch"
	// SignalIPRangeMismatch — DNS resolved the domain to IPs
	// outside the published ranges. Tenant demotion (some
	// resolvers return CDN-local IPs that differ from upstream).
	SignalIPRangeMismatch DemotionSignal = "ip_range_mismatch"
	// SignalAnomaly — anomaly detector flagged exfiltration
	// patterns. Tenant demotion only.
	SignalAnomaly DemotionSignal = "anomaly"
)

// DemotionEvent is the signal payload. The engine subscribes to a
// channel of these; the producer is responsible for validating that
// `Domain` is a domain string and that `Class` is a desired target
// class (almost always inspect_full).
type DemotionEvent struct {
	// TenantID may be uuid.Nil for global signals (threat feed,
	// cert-pin mismatch). For tenant-scoped signals (anomaly,
	// IP-range mismatch on a specific tenant) it carries the
	// tenant the override should be installed for.
	TenantID uuid.UUID
	// Domain is the affected domain or pattern. The engine
	// resolves it to a global app (by walking app_registry
	// domains) when possible; otherwise it installs a
	// custom_domain override.
	Domain string
	// Signal is the trigger class.
	Signal DemotionSignal
	// TargetClass is the class to demote into. Defaults to
	// inspect_full when zero.
	TargetClass repository.TrafficClass
	// Reason is a human-readable explanation logged into the
	// override and the audit trail.
	Reason string
	// ObservedAt is the wall-clock the signal was generated.
	ObservedAt time.Time
}

// DemotionPolicy controls the engine's behaviour: which signals
// auto-expire, how long, and which apply globally vs. per-tenant.
type DemotionPolicy struct {
	// TTLs maps each signal class to the override expiry. A zero
	// duration means "permanent — operator must remove manually".
	TTLs map[DemotionSignal]time.Duration
	// GlobalSignals lists the signals that apply to every tenant.
	// The engine resolves "global" by enumerating tenants from the
	// tenant repository and installing a per-tenant override on
	// each. (RLS prevents a true cross-tenant override row, and
	// directly mutating the global registry would be too
	// destructive for an automated signal.)
	GlobalSignals map[DemotionSignal]bool
}

// DefaultDemotionPolicy is a conservative default applied when the
// caller does not supply one. Threat-feed and cert-pin mismatches
// are global; IP-range and anomaly are tenant-local.
func DefaultDemotionPolicy() DemotionPolicy {
	return DemotionPolicy{
		TTLs: map[DemotionSignal]time.Duration{
			SignalThreatFeed:      24 * time.Hour,
			SignalCertPinMismatch: 7 * 24 * time.Hour,
			SignalIPRangeMismatch: 6 * time.Hour,
			SignalAnomaly:         48 * time.Hour,
		},
		GlobalSignals: map[DemotionSignal]bool{
			SignalThreatFeed:      true,
			SignalCertPinMismatch: true,
		},
	}
}

// DemotionPublisher publishes a notification to the runtime so all
// affected edges / agents receive the override immediately rather
// than waiting for the next bundle compilation. The default
// publisher is a no-op; production wires a NATS publisher.
type DemotionPublisher interface {
	PublishDemotion(ctx context.Context, tenantID uuid.UUID, ov repository.AppRegistryOverride) error
}

// DemotionEngine subscribes to demotion signals and turns them into
// app_registry_overrides rows. It does not own its event source —
// callers feed events via Apply or via Run + a channel.
type DemotionEngine struct {
	svc       *Service
	tenants   repository.TenantRepository
	publisher DemotionPublisher
	policy    DemotionPolicy

	mu      sync.Mutex
	stopped bool
}

// NewDemotionEngine constructs a DemotionEngine.
func NewDemotionEngine(
	svc *Service,
	tenants repository.TenantRepository,
	publisher DemotionPublisher,
	policy DemotionPolicy,
) *DemotionEngine {
	if policy.TTLs == nil && policy.GlobalSignals == nil {
		policy = DefaultDemotionPolicy()
	}
	return &DemotionEngine{
		svc:       svc,
		tenants:   tenants,
		publisher: publisher,
		policy:    policy,
	}
}

// Apply applies a single demotion event synchronously. Returns
// the list of overrides installed (one per affected tenant), or an
// error if the resolution failed.
func (e *DemotionEngine) Apply(ctx context.Context, ev DemotionEvent) ([]repository.AppRegistryOverride, error) {
	if strings.TrimSpace(ev.Domain) == "" {
		return nil, fmt.Errorf("demotion: empty domain: %w", repository.ErrInvalidArgument)
	}
	if ev.TargetClass == "" {
		ev.TargetClass = repository.TrafficClassInspectFull
	}
	if !ev.TargetClass.IsValid() {
		return nil, fmt.Errorf("demotion: invalid target class %q: %w", ev.TargetClass, repository.ErrInvalidArgument)
	}
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = e.svc.now()
	}
	// Resolve the domain to a global app first; if we can, install
	// app_id-based overrides (cleaner UX). Otherwise install
	// custom_domain overrides so the demotion still takes effect.
	app, appErr := e.resolveApp(ctx, ev.Domain)
	if appErr != nil && !errors.Is(appErr, repository.ErrNotFound) {
		return nil, fmt.Errorf("demotion: resolve app: %w", appErr)
	}

	targets, err := e.resolveTenants(ctx, ev)
	if err != nil {
		return nil, err
	}

	expiresAt := e.expiryFor(ev.Signal, ev.ObservedAt)
	var installed []repository.AppRegistryOverride
	for _, tenantID := range targets {
		ov := repository.AppRegistryOverride{
			TenantID:             tenantID,
			TrafficClassOverride: ev.TargetClass,
			Reason:               e.reasonText(ev),
			ExpiresAt:            expiresAt,
		}
		if app.ID != uuid.Nil {
			id := app.ID
			ov.AppID = &id
		} else {
			ov.CustomDomains = []string{strings.ToLower(strings.TrimSpace(ev.Domain))}
		}
		out, createErr := e.svc.CreateOverride(ctx, tenantID, nil, ov)
		if createErr != nil {
			if errors.Is(createErr, repository.ErrConflict) {
				// Existing override already covers this app for
				// this tenant — leave it alone (operator
				// intent wins). Continue with the next tenant.
				continue
			}
			return installed, fmt.Errorf("demotion: install override for tenant %s: %w", tenantID, createErr)
		}
		installed = append(installed, out)
		if e.publisher != nil {
			if perr := e.publisher.PublishDemotion(ctx, tenantID, out); perr != nil {
				// Publish failures are logged but do NOT abort
				// the run; the bundle compiler will pick up the
				// override on its next cycle and the receivers
				// will pull the new bundle on their next poll.
				e.svc.logger.WarnContext(ctx, "demotion publish failed",
					"tenant_id", tenantID, "override_id", out.ID, "error", perr)
			}
		}
	}
	return installed, nil
}

// Run consumes events from ch until ctx is canceled or ch is
// closed. Errors from Apply are logged; the worker does not stop on
// a single bad event because in production the channel is fed from
// NATS and a poisoned message must not stall the entire engine.
func (e *DemotionEngine) Run(ctx context.Context, ch <-chan DemotionEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if _, err := e.Apply(ctx, ev); err != nil {
				e.svc.logger.ErrorContext(ctx, "demotion apply failed",
					"domain", ev.Domain, "signal", string(ev.Signal), "error", err)
			}
		}
	}
}

// SweepExpired removes any overrides whose ExpiresAt has passed.
// Intended to be called from a periodic ticker.
func (e *DemotionEngine) SweepExpired(ctx context.Context) (int, error) {
	return e.svc.overrides.DeleteExpired(ctx, e.svc.now())
}

func (e *DemotionEngine) resolveApp(ctx context.Context, domain string) (repository.AppRegistry, error) {
	apps, err := e.svc.apps.ListAll(ctx)
	if err != nil {
		return repository.AppRegistry{}, fmt.Errorf("list apps: %w", err)
	}
	lower := strings.ToLower(strings.TrimSpace(domain))
	for _, app := range apps {
		for _, pat := range app.Domains {
			if matchesPattern(lower, pat) {
				return app, nil
			}
		}
	}
	return repository.AppRegistry{}, repository.ErrNotFound
}

func (e *DemotionEngine) resolveTenants(ctx context.Context, ev DemotionEvent) ([]uuid.UUID, error) {
	if e.policy.GlobalSignals[ev.Signal] {
		// Enumerate every active tenant. The enumeration uses an
		// empty cursor so we walk the full list — this is rare
		// (only fires on a threat-feed or cert-pin mismatch) and
		// the tenant population is bounded.
		var (
			out  []uuid.UUID
			page repository.Page
		)
		for {
			res, err := e.tenants.List(ctx, page)
			if err != nil {
				return nil, fmt.Errorf("list tenants: %w", err)
			}
			for _, t := range res.Items {
				if t.Status == repository.TenantStatusActive {
					out = append(out, t.ID)
				}
			}
			if res.NextCursor == "" {
				break
			}
			page.After = res.NextCursor
		}
		return out, nil
	}
	if ev.TenantID == uuid.Nil {
		return nil, fmt.Errorf("demotion: tenant_id required for signal %q: %w", ev.Signal, repository.ErrInvalidArgument)
	}
	return []uuid.UUID{ev.TenantID}, nil
}

func (e *DemotionEngine) expiryFor(sig DemotionSignal, observed time.Time) *time.Time {
	if e.policy.TTLs == nil {
		return nil
	}
	ttl, ok := e.policy.TTLs[sig]
	if !ok || ttl == 0 {
		return nil
	}
	t := observed.Add(ttl)
	return &t
}

func (e *DemotionEngine) reasonText(ev DemotionEvent) string {
	if ev.Reason != "" {
		return ev.Reason
	}
	switch ev.Signal {
	case SignalThreatFeed:
		return "auto-demoted: threat feed hit"
	case SignalCertPinMismatch:
		return "auto-demoted: certificate pin mismatch"
	case SignalIPRangeMismatch:
		return "auto-demoted: DNS resolution outside expected IP range"
	case SignalAnomaly:
		return "auto-demoted: anomaly detector signal"
	}
	return fmt.Sprintf("auto-demoted: %s", ev.Signal)
}

// NoopPublisher is the default DemotionPublisher when NATS is not
// wired (tests, in-memory deployments). Returns nil on every call.
type NoopPublisher struct{}

// PublishDemotion always succeeds.
func (NoopPublisher) PublishDemotion(context.Context, uuid.UUID, repository.AppRegistryOverride) error {
	return nil
}
