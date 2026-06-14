package rollout

// This file adds the NoOps AUTO-PROMOTER on top of the staged-enablement
// state machine in rollout.go / service.go. The base framework is
// deliberately operator-driven: nothing auto-advances, the one automatic
// transition is a monitor-phase rollback toward safety. That is
// production-correct (no surprise enforcement on upgrade) but it is not
// NoOps — a fresh install does nothing until an operator manually opts a
// tenant into monitor and later promotes it to enforce.
//
// The [Autopilot] closes that gap WITHOUT weakening any safety property:
//
//   - It is itself behind a fleet/MSP-level default-OFF gate (it is only
//     constructed and scheduled when the operator turns the autopilot on),
//     so an upgrade never silently starts auto-promoting.
//   - It only ever auto-advances ALONG the existing machine
//     (off -> monitor -> enforce), one step at a time, through the same
//     validated [Service.Transition] path. It never skips the monitor
//     (dry-run) phase.
//   - monitor -> enforce happens ONLY after the capability has dwelt in
//     monitor for a configurable window AND its monitor-phase guardrail
//     metrics (error rate, would-have-block / deny rate) are under a
//     promotion ceiling that is at least as strict as the framework's
//     auto-demote threshold. Because auto-demote runs on every sweep and
//     fires the instant the (looser-or-equal) demote threshold is
//     breached, any in-window breach demotes the capability back to off
//     and RESETS the dwell — so reaching enforce is itself evidence the
//     guardrails held throughout the window.
//   - Demotion stays strictly easier than promotion: demotion needs no
//     dwell and no minimum evidence beyond the demote threshold's own
//     MinSamples, while promotion needs the full dwell window AND a
//     minimum sample count AND an under-ceiling reading. [NewAutopilot]
//     refuses a policy whose promotion ceiling is looser than the demote
//     threshold, so the "demote implies promotion-blocked" invariant is a
//     construction-time guarantee, not a runtime hope.
//
// Every transition the autopilot drives goes through the same audited
// persist path as an operator's, so it is recorded by the [TransitionSink]
// (the production wiring writes those to the audit log) and is fully
// reversible by an operator.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AutopilotActor is the updated_by value recorded for a transition the
// autopilot drives, distinct from an operator subject and from
// [SystemActor] (which the framework reserves for auto-demote rollbacks).
// It makes "who advanced this tenant" auditable: an autopilot enrol /
// promote is attributable to the NoOps autopilot, not to any human.
const AutopilotActor = "autopilot"

// TenantLister enumerates the tenants the autopilot considers each sweep.
// It is declared here (not imported from the persistence layer) so the
// dependency points inward, matching [Repository]; cmd/sng-control adapts
// the concrete TenantRepository to it.
type TenantLister interface {
	// ListActiveTenantIDs returns the ids of every ACTIVE tenant. The
	// autopilot only ever promotes active tenants; suspended/deleted
	// tenants are excluded by the implementation. Implementations page
	// internally and MUST return a non-nil (possibly empty) slice on
	// success.
	ListActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error)
}

// MonitorMetricsSource yields the monitor-phase guardrail metrics the
// autopilot reads to decide whether a capability has earned promotion.
// It returns the same [MonitorMetrics] shape [Service.EvaluateAutoRollback]
// consumes, so a capability that already aggregates its dry-run
// observations can feed both the auto-demote guardrail and the promoter
// from one source (see [MonitorMetricsRecorder]).
type MonitorMetricsSource interface {
	// MonitorMetrics returns the latest monitor-phase observation
	// snapshot for (tenant, capability) and the time it was recorded. A
	// capability with no recorded observations returns the zero
	// MonitorMetrics and a zero time; the autopilot treats that as
	// "insufficient evidence" and does not promote. observedAt lets the
	// promoter discard a snapshot older than the capability's current
	// monitor entry (e.g. left over from a prior monitor period that was
	// rolled back) so stale evidence can never promote.
	MonitorMetrics(ctx context.Context, tenantID uuid.UUID, c Capability) (m MonitorMetrics, observedAt time.Time, err error)
}

// AutopilotObserver receives the autopilot's per-action outcomes so the
// caller can export them as metrics (see cmd/sng-control). It is optional;
// the default is a no-op. Implementations must be safe for concurrent use
// and must not block the sweep.
type AutopilotObserver interface {
	// Enrolled fires when the autopilot advanced a capability
	// off -> monitor for a tenant.
	Enrolled(c Capability)
	// Promoted fires when the autopilot advanced a capability
	// monitor -> enforce for a tenant.
	Promoted(c Capability)
	// Demoted fires when an auto-demote rollback (monitor -> off) ran
	// during a sweep because the demote threshold was breached.
	Demoted(c Capability)
	// PromotionBlocked fires when a monitoring capability was NOT
	// promoted this sweep, with a short machine reason
	// ("dwell" | "insufficient_samples" | "guardrail" | "stale_metrics").
	// It is the signal that proves the guardrail is doing work.
	PromotionBlocked(c Capability, reason string)
}

// NoopAutopilotObserver is the default observer: it records nothing.
type NoopAutopilotObserver struct{}

// Enrolled does nothing.
func (NoopAutopilotObserver) Enrolled(Capability) {}

// Promoted does nothing.
func (NoopAutopilotObserver) Promoted(Capability) {}

// Demoted does nothing.
func (NoopAutopilotObserver) Demoted(Capability) {}

// PromotionBlocked does nothing.
func (NoopAutopilotObserver) PromotionBlocked(Capability, string) {}

// Block reasons reported through [AutopilotObserver.PromotionBlocked].
const (
	blockDwell        = "dwell"
	blockSamples      = "insufficient_samples"
	blockGuardrail    = "guardrail"
	blockStaleMetrics = "stale_metrics"
)

// AutopilotPolicy tunes the NoOps auto-promoter. The zero value promotes
// nothing (empty Capabilities), the conservative default.
type AutopilotPolicy struct {
	// Capabilities is the set the autopilot governs. A capability NOT in
	// this set is never auto-advanced — operators drive it by hand. Empty
	// means the autopilot advances nothing.
	Capabilities []Capability
	// AutoEnrol, when true, advances a capability off -> monitor for a
	// tenant that is unmanaged (no row) or explicitly off. This is what
	// makes a freshly-seeded tenant start dry-running with zero operator
	// clicks. When false the autopilot only promotes monitor -> enforce
	// for tenants an operator already moved into monitor — the most
	// conservative posture.
	AutoEnrol bool
	// DwellWindow is the minimum time a capability must have been in
	// monitor (measured from the record's UpdatedAt — its monitor entry)
	// before it is eligible for monitor -> enforce. A value <= 0 disables
	// promotion entirely (enrol-only): the autopilot will dry-run
	// tenants but never auto-enforce.
	DwellWindow time.Duration
	// MinSamples is the minimum number of monitor observations required
	// as promotion evidence. It must be >= the demote threshold's
	// MinSamples so demotion never needs more evidence than promotion.
	// Values < 1 are treated as 1.
	MinSamples int
	// PromotionGuardrail is the metric ceiling that must hold for a
	// promotion: a monitor reading that BREACHES it blocks promotion. It
	// must be at least as strict as the [Service] demote threshold (every
	// configured rate <= the demote rate), enforced by [NewAutopilot], so
	// that any reading which would auto-demote also blocks promotion —
	// "no path can auto-promote past a breached guardrail."
	PromotionGuardrail Threshold
	// Exclusions is the per-tenant opt-out set: a (tenant, capability) the
	// autopilot leaves entirely alone — it never auto-enrols, promotes or
	// auto-demotes it, so an operator keeps that tenant off (or under
	// manual control) WITHOUT disabling the autopilot fleet-wide. The
	// zero value excludes nothing. The capability's own monitor-phase
	// auto-rollback safety net (driven by the capability's sweep, not the
	// autopilot) is independent and still runs, so excluding a tenant
	// never removes a safety guardrail — it only stops the autopilot from
	// advancing it.
	Exclusions AutopilotExclusions
}

// AutopilotExclusions is the per-tenant / per-(tenant,capability) opt-out
// set the autopilot consults before it touches a tenant. An operator
// configures it (fleet-level, e.g. ROLLOUT_AUTOPILOT_EXCLUDE) to keep a
// specific tenant off while the rest of the fleet auto-promotes. The zero
// value is valid and excludes nothing; it is safe for concurrent reads.
type AutopilotExclusions struct {
	// tenants holds tenants excluded for ALL capabilities.
	tenants map[uuid.UUID]struct{}
	// pairs holds tenants excluded for a SPECIFIC capability only.
	pairs map[exclusionKey]struct{}
}

type exclusionKey struct {
	tenant     uuid.UUID
	capability Capability
}

// NewAutopilotExclusions builds an exclusion set. wholeTenants are
// excluded for every capability; pairs exclude a tenant for one
// capability only. A nil/empty input yields an empty set (excludes
// nothing). Nil tenant ids and invalid capabilities are ignored.
func NewAutopilotExclusions(wholeTenants []uuid.UUID, pairs []TenantCapability) AutopilotExclusions {
	ex := AutopilotExclusions{}
	for _, id := range wholeTenants {
		if id == uuid.Nil {
			continue
		}
		if ex.tenants == nil {
			ex.tenants = make(map[uuid.UUID]struct{})
		}
		ex.tenants[id] = struct{}{}
	}
	for _, p := range pairs {
		if p.TenantID == uuid.Nil || !p.Capability.Valid() {
			continue
		}
		if ex.pairs == nil {
			ex.pairs = make(map[exclusionKey]struct{})
		}
		ex.pairs[exclusionKey{tenant: p.TenantID, capability: p.Capability}] = struct{}{}
	}
	return ex
}

// TenantCapability names a single (tenant, capability) pair, used to
// build a per-capability [AutopilotExclusions] entry.
type TenantCapability struct {
	TenantID   uuid.UUID
	Capability Capability
}

// Excludes reports whether the autopilot must leave (tenant, capability)
// alone: true when the tenant is excluded for all capabilities or for
// this specific one. The zero value never excludes.
func (e AutopilotExclusions) Excludes(tenantID uuid.UUID, c Capability) bool {
	if len(e.tenants) > 0 {
		if _, ok := e.tenants[tenantID]; ok {
			return true
		}
	}
	if len(e.pairs) > 0 {
		if _, ok := e.pairs[exclusionKey{tenant: tenantID, capability: c}]; ok {
			return true
		}
	}
	return false
}

// Empty reports whether the set excludes nothing.
func (e AutopilotExclusions) Empty() bool {
	return len(e.tenants) == 0 && len(e.pairs) == 0
}

// Autopilot is the scheduled, leader-only NoOps promoter. It is safe for
// concurrent use insofar as the injected [Service]/[TenantLister]/
// [MonitorMetricsSource] are; a single instance is normally driven by one
// leader goroutine via Run.
type Autopilot struct {
	svc      *Service
	tenants  TenantLister
	source   MonitorMetricsSource
	policy   AutopilotPolicy
	observer AutopilotObserver
	logger   *slog.Logger
	now      func() time.Time
}

// AutopilotOption configures an [Autopilot].
type AutopilotOption func(*Autopilot)

// WithAutopilotObserver injects the metrics observer. Defaults to
// [NoopAutopilotObserver].
func WithAutopilotObserver(o AutopilotObserver) AutopilotOption {
	return func(a *Autopilot) {
		if o != nil {
			a.observer = o
		}
	}
}

// WithAutopilotLogger injects a structured logger. Defaults to the
// service's logger.
func WithAutopilotLogger(l *slog.Logger) AutopilotOption {
	return func(a *Autopilot) {
		if l != nil {
			a.logger = l
		}
	}
}

// WithAutopilotClock injects the time source, for deterministic tests.
// Defaults to the service's clock.
func WithAutopilotClock(now func() time.Time) AutopilotOption {
	return func(a *Autopilot) {
		if now != nil {
			a.now = now
		}
	}
}

// Autopilot validation errors.
var (
	// ErrAutopilotConfig is returned by [NewAutopilot] for a nil
	// dependency or a policy that cannot be made safe.
	ErrAutopilotConfig = fmt.Errorf("%w: invalid autopilot configuration", repository.ErrInvalidArgument)
)

// NewAutopilot builds an autopilot over svc, tenants and source. It
// rejects:
//   - a nil svc / tenants / source;
//   - an unknown capability in policy.Capabilities;
//   - a promotion-enabled policy (DwellWindow > 0) whose demote threshold
//     is disabled, or whose PromotionGuardrail is looser than the demote
//     threshold or unconfigured. These checks make "demotion is strictly
//     easier than promotion" and "a demote-worthy reading also blocks
//     promotion" construction-time invariants.
func NewAutopilot(svc *Service, tenants TenantLister, source MonitorMetricsSource, policy AutopilotPolicy, opts ...AutopilotOption) (*Autopilot, error) {
	if svc == nil {
		return nil, fmt.Errorf("%w: nil service", ErrAutopilotConfig)
	}
	if tenants == nil {
		return nil, fmt.Errorf("%w: nil tenant lister", ErrAutopilotConfig)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: nil monitor-metrics source", ErrAutopilotConfig)
	}
	for _, c := range policy.Capabilities {
		if !c.Valid() {
			return nil, fmt.Errorf("%w: unknown capability %q", ErrAutopilotConfig, c)
		}
	}
	if policy.DwellWindow > 0 {
		demote := svc.Threshold()
		if demote.MaxErrorRate <= 0 && demote.MaxDenyRate <= 0 {
			return nil, fmt.Errorf("%w: promotion is enabled but the service auto-demote threshold is disabled; "+
				"promotion must never run without a demotion safety net", ErrAutopilotConfig)
		}
		if err := promotionGuardrailAtLeastAsStrict(policy.PromotionGuardrail, demote); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAutopilotConfig, err)
		}
		if policy.MinSamples < demote.MinSamples {
			return nil, fmt.Errorf("%w: promotion MinSamples %d must be >= demote MinSamples %d so demotion never needs more evidence than promotion",
				ErrAutopilotConfig, policy.MinSamples, demote.MinSamples)
		}
	}
	a := &Autopilot{
		svc:      svc,
		tenants:  tenants,
		source:   source,
		policy:   policy,
		observer: NoopAutopilotObserver{},
		logger:   svc.logger,
		now:      svc.now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// promotionGuardrailAtLeastAsStrict verifies that every demote-threshold
// rate the framework enforces is also enforced by the promotion ceiling
// at an equal-or-lower value, so any reading that breaches the demote
// threshold (and thus auto-demotes) also breaches the promotion ceiling
// (and thus blocks promotion). A configured demote rate with no
// corresponding promotion rate, or a looser promotion rate, is rejected.
func promotionGuardrailAtLeastAsStrict(promo, demote Threshold) error {
	if demote.MaxErrorRate > 0 {
		if promo.MaxErrorRate <= 0 || promo.MaxErrorRate > demote.MaxErrorRate {
			return fmt.Errorf("promotion MaxErrorRate %.4f must be set and <= demote MaxErrorRate %.4f",
				promo.MaxErrorRate, demote.MaxErrorRate)
		}
	}
	if demote.MaxDenyRate > 0 {
		if promo.MaxDenyRate <= 0 || promo.MaxDenyRate > demote.MaxDenyRate {
			return fmt.Errorf("promotion MaxDenyRate %.4f must be set and <= demote MaxDenyRate %.4f",
				promo.MaxDenyRate, demote.MaxDenyRate)
		}
	}
	if promo.MaxErrorRate <= 0 && promo.MaxDenyRate <= 0 {
		return errors.New("promotion guardrail is unconfigured (no error-rate or deny-rate ceiling)")
	}
	return nil
}

// Sweep runs one full pass across every active tenant and the governed
// capabilities, advancing each along the state machine where it is due.
// It is best-effort: a per-tenant / per-capability failure is logged and
// the sweep continues, so one tenant's error never stalls the fleet. It
// returns the first error encountered (for visibility), or nil.
//
// Sweep is idempotent: a capability already in its target state is left
// alone, and dwell/guardrail checks are pure functions of the persisted
// record plus the current metric snapshot, so re-running a sweep performs
// no extra transitions.
func (a *Autopilot) Sweep(ctx context.Context) error {
	if len(a.policy.Capabilities) == 0 {
		return nil // nothing governed; conservative default
	}
	ids, err := a.tenants.ListActiveTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("autopilot: list active tenants: %w", err)
	}
	var firstErr error
	for _, id := range ids {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		for _, c := range a.policy.Capabilities {
			if rerr := a.reconcile(ctx, id, c); rerr != nil && firstErr == nil {
				firstErr = rerr
			}
		}
	}
	return firstErr
}

// reconcile advances a single (tenant, capability) by at most one step:
// off -> monitor (enrol) or monitor -> enforce (promote). It applies
// auto-demote BEFORE considering promotion, so a breach during monitor
// demotes and blocks promotion in the same pass.
func (a *Autopilot) reconcile(ctx context.Context, tenantID uuid.UUID, c Capability) error {
	// Per-tenant opt-out: an excluded (tenant, capability) is left
	// entirely alone — no enrol, no promote, no autopilot-driven
	// auto-demote — so an operator can keep one tenant off without
	// disabling the autopilot fleet-wide. The capability's own
	// monitor-phase auto-rollback safety net is independent of the
	// autopilot and still runs, so this never removes a guardrail.
	if a.policy.Exclusions.Excludes(tenantID, c) {
		return nil
	}

	cur, err := a.svc.Get(ctx, tenantID, c)
	if err != nil {
		a.logger.WarnContext(ctx, "autopilot: read state failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
		return err
	}

	switch cur.State {
	case StateOff:
		if !a.policy.AutoEnrol {
			return nil
		}
		return a.enrol(ctx, tenantID, c)
	case StateMonitor:
		return a.maybePromote(ctx, tenantID, c, cur)
	default:
		// StateEnforce (already at the protective terminal posture) or an
		// unknown state: nothing for the promoter to do.
		return nil
	}
}

// enrol advances off -> monitor so a tenant begins dry-running the
// capability with zero operator action.
func (a *Autopilot) enrol(ctx context.Context, tenantID uuid.UUID, c Capability) error {
	_, err := a.svc.Transition(ctx, tenantID, c, TransitionInput{
		To:     StateMonitor,
		Actor:  AutopilotActor,
		Reason: "autopilot: auto-enrolled off->monitor (dry-run; no enforcement)",
	})
	if err != nil {
		a.logger.WarnContext(ctx, "autopilot: enrol failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
		return err
	}
	a.observer.Enrolled(c)
	a.logger.InfoContext(ctx, "autopilot: enrolled capability to monitor",
		slog.String("tenant_id", tenantID.String()),
		slog.String("capability", string(c)))
	return nil
}

// maybePromote runs the demote-then-promote logic for a monitoring
// capability. Demotion always takes priority and is the easier path.
func (a *Autopilot) maybePromote(ctx context.Context, tenantID uuid.UUID, c Capability, cur Record) error {
	m, observedAt, err := a.source.MonitorMetrics(ctx, tenantID, c)
	if err != nil {
		// Fail safe: an unreadable metric source must never promote. It
		// also must not block the existing auto-demote, but we have no
		// metrics to evaluate, so leave the capability where it is.
		a.logger.WarnContext(ctx, "autopilot: monitor metrics unreadable; not promoting",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
		a.observer.PromotionBlocked(c, blockStaleMetrics)
		return err
	}

	// A snapshot recorded before this monitor period began (e.g. left over
	// from a prior monitor that ended in auto-rollback, or none recorded
	// yet) is not evidence for the current period. It must gate the
	// auto-demote path as well as promotion: acting on a stale breaching
	// snapshot would re-demote a freshly re-enrolled tenant on every sweep
	// (enrol->demote->enrol oscillation) until live metrics overwrite it.
	fresh := !observedAt.IsZero() && !observedAt.Before(cur.UpdatedAt)

	// Auto-demote first, on fresh evidence only: if the (looser-or-equal)
	// demote threshold is breached, roll back to off and stop. This
	// guarantees a live breach during monitor demotes and blocks promotion
	// in the same pass, while a stale snapshot cannot trigger a rollback.
	if fresh {
		if _, rolled, derr := a.svc.EvaluateAutoRollback(ctx, tenantID, c, m); derr != nil {
			a.logger.WarnContext(ctx, "autopilot: auto-demote evaluation failed",
				slog.String("tenant_id", tenantID.String()),
				slog.String("capability", string(c)),
				slog.Any("error", derr))
			return derr
		} else if rolled {
			a.observer.Demoted(c)
			return nil
		}
	}

	if a.policy.DwellWindow <= 0 {
		return nil // promotion disabled: enrol-only autopilot
	}

	// Stale evidence blocks promotion (same freshness gate as the
	// auto-demote above): the capability stays in monitor (dry-run, no
	// enforcement) until a live snapshot for this period is recorded.
	if !fresh {
		a.observer.PromotionBlocked(c, blockStaleMetrics)
		return nil
	}
	// Dwell: the capability must have been monitoring for the full window.
	if a.now().Sub(cur.UpdatedAt) < a.policy.DwellWindow {
		a.observer.PromotionBlocked(c, blockDwell)
		return nil
	}
	// Evidence floor: enough observations to make the rate meaningful.
	if m.Samples < a.minSamples() {
		a.observer.PromotionBlocked(c, blockSamples)
		return nil
	}
	// Guardrail: the reading must be under the promotion ceiling.
	if reason, breached := m.Breach(a.policy.PromotionGuardrail); breached {
		a.observer.PromotionBlocked(c, blockGuardrail)
		a.logger.InfoContext(ctx, "autopilot: promotion withheld; guardrail breached",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.String("reason", reason))
		return nil
	}

	reason := fmt.Sprintf(
		"autopilot: promoted monitor->enforce after %s dwell; guardrails held (samples=%d error_rate=%.4f deny_rate=%.4f)",
		a.policy.DwellWindow, m.Samples, m.ErrorRate(), m.DenyRate())
	if _, err := a.svc.Transition(ctx, tenantID, c, TransitionInput{
		To:     StateEnforce,
		Actor:  AutopilotActor,
		Reason: reason,
	}); err != nil {
		a.logger.WarnContext(ctx, "autopilot: promote failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
		return err
	}
	a.observer.Promoted(c)
	a.logger.InfoContext(ctx, "autopilot: promoted capability to enforce",
		slog.String("tenant_id", tenantID.String()),
		slog.String("capability", string(c)),
		slog.Int("samples", m.Samples))
	return nil
}

// minSamples returns the configured promotion evidence floor, treating a
// value < 1 as 1.
func (a *Autopilot) minSamples() int {
	if a.policy.MinSamples < 1 {
		return 1
	}
	return a.policy.MinSamples
}

// Run drives Sweep on a ticker until ctx is cancelled. It sweeps once
// immediately on entry — so a leader that has just taken over reconciles
// without waiting a full interval — then re-sweeps every interval. It is
// intended to be wrapped in the leader elector's RunIfLeader so it runs on
// exactly one replica. A non-positive interval falls back to one hour.
func (a *Autopilot) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	sweep := func() {
		if err := a.Sweep(ctx); err != nil && ctx.Err() == nil {
			a.logger.WarnContext(ctx, "autopilot: sweep pass failed", slog.Any("error", err))
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// MonitorMetricsStore is an OPTIONAL durable backing for a
// [MonitorMetricsRecorder]. When wired, the recorder write-throughs each
// snapshot to it and, on an in-memory cache miss, hydrates from it — so
// the monitor-phase promotion EVIDENCE (and therefore the dwell clock it
// represents) survives a leader failover instead of resetting to "no
// evidence" on the new leader. Implementations are tenant-scoped (one
// latest snapshot per tenant+capability) and safe for concurrent use.
//
// It never weakens a safety property: the autopilot still discards any
// snapshot older than the capability's current monitor entry (the
// freshness gate), so a persisted snapshot can only ever SPEED a safe
// promotion that the dwell + guardrail already justify, never cause an
// unsafe one.
type MonitorMetricsStore interface {
	// PutSnapshot durably records the latest snapshot for (tenant,
	// capability), stamped observedAt (the recorder's record time).
	PutSnapshot(ctx context.Context, tenantID uuid.UUID, c Capability, m MonitorMetrics, observedAt time.Time) error
	// GetSnapshot returns the stored snapshot for (tenant, capability).
	// found is false (and err nil) when none is stored — the caller
	// treats that as "no evidence".
	GetSnapshot(ctx context.Context, tenantID uuid.UUID, c Capability) (m MonitorMetrics, observedAt time.Time, found bool, err error)
}

// MonitorMetricsRecorder is a [MonitorMetricsSource] that capabilities
// feed with the dry-run observations they already compute each monitor
// pass (see internal/service/identity idp_sync, which builds a
// [MonitorMetrics] every sweep). It keeps an in-memory cache of the
// LATEST snapshot per (tenant, capability) with the time it was recorded;
// the autopilot reads the snapshot and discards it if it predates the
// capability's current monitor entry. It is safe for concurrent use.
//
// Without a store it is a single-process cache: a snapshot lost to a
// restart or leader failover only DELAYS a promotion (the capability
// stays safely in monitor), it never causes an unsafe one. Wiring a
// [MonitorMetricsStore] via [WithMonitorMetricsStore] makes it
// write-through and lazily hydrate on a cache miss, so a new leader
// rebuilds the evidence instead of waiting for it to re-accumulate.
type MonitorMetricsRecorder struct {
	mu   sync.RWMutex
	rows map[monitorKey]monitorSnapshot
	now  func() time.Time

	// store, when non-nil, durably backs the cache so evidence survives a
	// leader failover. Reads/writes against it are best-effort: a store
	// error never blocks recording (the in-memory cache is always the
	// authoritative fast path) and never promotes on its own.
	store        MonitorMetricsStore
	storeTimeout time.Duration
	logger       *slog.Logger
}

type monitorKey struct {
	tenant     uuid.UUID
	capability Capability
}

type monitorSnapshot struct {
	metrics    MonitorMetrics
	observedAt time.Time
}

// RecorderOption configures a [MonitorMetricsRecorder].
type RecorderOption func(*MonitorMetricsRecorder)

// WithMonitorMetricsStore wires a durable backing store so monitor
// evidence survives a leader failover (see [MonitorMetricsStore]). A nil
// store is ignored (the recorder stays an in-memory cache).
func WithMonitorMetricsStore(store MonitorMetricsStore) RecorderOption {
	return func(r *MonitorMetricsRecorder) {
		if store != nil {
			r.store = store
		}
	}
}

// WithRecorderStoreTimeout bounds each best-effort store call made from
// the recorder's no-context Record path. Values <= 0 keep the default.
func WithRecorderStoreTimeout(d time.Duration) RecorderOption {
	return func(r *MonitorMetricsRecorder) {
		if d > 0 {
			r.storeTimeout = d
		}
	}
}

// WithRecorderLogger injects a structured logger for best-effort store
// failures. Defaults to slog.Default().
func WithRecorderLogger(l *slog.Logger) RecorderOption {
	return func(r *MonitorMetricsRecorder) {
		if l != nil {
			r.logger = l
		}
	}
}

const defaultRecorderStoreTimeout = 5 * time.Second

// NewMonitorMetricsRecorder returns an empty recorder. now may be nil
// (defaults to time.Now UTC). Pass [WithMonitorMetricsStore] to back it
// with a durable store that survives leader failover.
func NewMonitorMetricsRecorder(now func() time.Time, opts ...RecorderOption) *MonitorMetricsRecorder {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	r := &MonitorMetricsRecorder{
		rows:         make(map[monitorKey]monitorSnapshot),
		now:          now,
		storeTimeout: defaultRecorderStoreTimeout,
		logger:       slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

var _ MonitorMetricsSource = (*MonitorMetricsRecorder)(nil)

// Record stores the latest monitor-phase metric snapshot for (tenant,
// capability), stamped with the current time. A capability calls it once
// per dry-run pass with that pass's observed metrics. A nil-tenant or
// invalid capability is ignored. When a store is wired, the snapshot is
// also write-through persisted (best-effort) so it survives a failover.
func (r *MonitorMetricsRecorder) Record(tenantID uuid.UUID, c Capability, m MonitorMetrics) {
	if tenantID == uuid.Nil || !c.Valid() {
		return
	}
	observedAt := r.now()
	r.mu.Lock()
	r.rows[monitorKey{tenant: tenantID, capability: c}] = monitorSnapshot{metrics: m, observedAt: observedAt}
	r.mu.Unlock()

	if r.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.storeTimeout)
	defer cancel()
	if err := r.store.PutSnapshot(ctx, tenantID, c, m, observedAt); err != nil {
		r.logger.WarnContext(ctx, "rollout: persist monitor evidence failed (cache still authoritative)",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
	}
}

// MonitorMetrics implements [MonitorMetricsSource]. It serves the
// in-memory cache first; on a miss (e.g. just after a leader failover,
// before the capability's next dry-run pass re-records) it hydrates from
// the wired store so the new leader sees the evidence the previous leader
// accumulated instead of starting empty.
func (r *MonitorMetricsRecorder) MonitorMetrics(ctx context.Context, tenantID uuid.UUID, c Capability) (MonitorMetrics, time.Time, error) {
	r.mu.RLock()
	snap, ok := r.rows[monitorKey{tenant: tenantID, capability: c}]
	r.mu.RUnlock()
	if ok {
		return snap.metrics, snap.observedAt, nil
	}
	if r.store == nil {
		return MonitorMetrics{}, time.Time{}, nil
	}
	return r.hydrate(ctx, tenantID, c)
}

// hydrate loads (tenant, capability) from the store on a cache miss and
// populates the cache so subsequent reads stay in-process. A store error
// is returned to the caller (the autopilot treats it as fail-safe: an
// unreadable source never promotes); a "not found" is the zero snapshot.
func (r *MonitorMetricsRecorder) hydrate(ctx context.Context, tenantID uuid.UUID, c Capability) (MonitorMetrics, time.Time, error) {
	m, observedAt, found, err := r.store.GetSnapshot(ctx, tenantID, c)
	if err != nil {
		return MonitorMetrics{}, time.Time{}, fmt.Errorf("rollout: hydrate monitor evidence: %w", err)
	}
	if !found {
		return MonitorMetrics{}, time.Time{}, nil
	}
	r.mu.Lock()
	// Don't clobber a fresher snapshot a concurrent Record may have set
	// between our cache miss and here.
	key := monitorKey{tenant: tenantID, capability: c}
	if cur, ok := r.rows[key]; !ok || observedAt.After(cur.observedAt) {
		r.rows[key] = monitorSnapshot{metrics: m, observedAt: observedAt}
	} else {
		m, observedAt = cur.metrics, cur.observedAt
	}
	r.mu.Unlock()
	return m, observedAt, nil
}

// Forget drops any recorded snapshot for (tenant, capability). It is
// optional housekeeping — a transition sink can call it so a rolled-back
// or promoted capability does not retain stale evidence — but correctness
// does not depend on it (the promoter already discards snapshots older
// than the current monitor entry). It only clears the in-memory cache;
// the durable store (if any) keeps its last snapshot, which the freshness
// gate discards once the capability re-enters monitor.
func (r *MonitorMetricsRecorder) Forget(tenantID uuid.UUID, c Capability) {
	r.mu.Lock()
	delete(r.rows, monitorKey{tenant: tenantID, capability: c})
	r.mu.Unlock()
}

// CapabilitySourceMux is a [MonitorMetricsSource] that routes each
// capability to its OWN evidence source, falling back to a default for
// any capability without a specific one. It lets the single autopilot
// govern capabilities whose monitor evidence comes from different places
// — e.g. idp_directory_sync and noops_autoenforce feed an in-process
// [MonitorMetricsRecorder], while a future edge-sourced capability
// (clamav_swg, whose dry-run runs at the SWG edge) plugs its own
// telemetry-backed source in here — without the autopilot needing to know
// which is which. A capability with neither a registered source nor a
// default yields the zero snapshot ("no evidence"), so it simply never
// auto-promotes (fail-safe). It is safe for concurrent use once built.
type CapabilitySourceMux struct {
	byCapability map[Capability]MonitorMetricsSource
	fallback     MonitorMetricsSource
}

// NewCapabilitySourceMux builds a mux whose unregistered capabilities use
// fallback (which may be nil — those capabilities then never promote).
func NewCapabilitySourceMux(fallback MonitorMetricsSource) *CapabilitySourceMux {
	return &CapabilitySourceMux{
		byCapability: make(map[Capability]MonitorMetricsSource),
		fallback:     fallback,
	}
}

var _ MonitorMetricsSource = (*CapabilitySourceMux)(nil)

// Register routes capability c to source. A later Register for the same
// capability replaces the earlier one. A nil source or invalid capability
// is ignored. Returns the receiver for chaining at construction.
func (m *CapabilitySourceMux) Register(c Capability, source MonitorMetricsSource) *CapabilitySourceMux {
	if source != nil && c.Valid() {
		m.byCapability[c] = source
	}
	return m
}

// MonitorMetrics implements [MonitorMetricsSource], dispatching to the
// registered source for c (or the fallback). With no source for c and no
// fallback it returns the zero snapshot, which the autopilot reads as
// "insufficient evidence" and never promotes.
func (m *CapabilitySourceMux) MonitorMetrics(ctx context.Context, tenantID uuid.UUID, c Capability) (MonitorMetrics, time.Time, error) {
	if src, ok := m.byCapability[c]; ok {
		return src.MonitorMetrics(ctx, tenantID, c)
	}
	if m.fallback != nil {
		return m.fallback.MonitorMetrics(ctx, tenantID, c)
	}
	return MonitorMetrics{}, time.Time{}, nil
}
