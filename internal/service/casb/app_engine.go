package casb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// AutoEnforceGate is the staged-enablement seam for the NoOps
// auto-enforce capability (#172, rollout.CapabilityNoOpsAutoEnforce).
// The engine consults it before applying any auto action so flipping
// auto-enforce for a tenant is a rehearsed monitor -> enforce
// progression rather than a binary flag:
//
//   - enforce — the engine applies the auto action (current behavior).
//   - monitor — dry-run: the engine records the would-have auto action
//     as a recommendation and takes NO enforcement action.
//   - off     — auto-enforce is disabled; the engine recommends only.
//
// The signature matches *rollout.Service.GateState, which returns the
// state plus whether the tenant is explicitly MANAGED by the framework.
// An UNMANAGED tenant (no rollout row) keeps the legacy behavior so
// wiring the gate never silently disables auto-enforce for tenants that
// were already protected by the config flag — they stay auto-enforcing
// until an operator opts them into the staged progression. GateState
// fails closed to (off, managed) on any read error, so an unreadable
// rollout state can never silently auto-enforce. A nil gate preserves the
// legacy behavior unconditionally.
type AutoEnforceGate interface {
	GateState(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.State, bool)
}

// AppNoOpsEngine is the per-tenant NoOps pipeline. For each discovered
// app it: (1) classifies it deterministically (optionally AI-refined),
// (2) persists the classification, (3) decides an action from the
// tenant's smart-default policy — auto-enforcing only high-confidence,
// high-risk, unsanctioned apps with the non-blocking Protect verb and
// recommending everything else — and (4) writes an immutable audit row
// (and a global audit-log entry when wired).
//
// It plugs into shadow-IT discovery two ways: ShadowITDiscoverer calls
// OnAppDiscovered after each flush upsert (the "act promptly on new
// discoveries" path), and Reconcile sweeps every tenant's full
// inventory on a schedule (the "catch drift / newly-risky apps" path).
//
// Concurrency: the engine is stateless beyond its dependencies and
// safe for concurrent use; all per-tenant state lives in the store,
// which serialises its own access.
type AppNoOpsEngine struct {
	store    NoOpsStore
	apps     repository.CASBDiscoveredAppRepository
	tenants  repository.TenantRepository
	enforcer AppEnforcer                   // optional; nil => recommend-only
	refiner  ClassificationRefiner         // optional; nil => heuristic-only
	audit    repository.AuditLogRepository // optional; nil => no global audit
	// rolloutGate gates the NoOps auto-enforce capability through the
	// staged-enablement framework. Optional: nil preserves the legacy
	// behavior in which the global config flag alone governs auto-enforce
	// (see AutoEnforceGate).
	rolloutGate AutoEnforceGate
	logger      *slog.Logger
	nowFunc     func() time.Time

	// refineTimeout bounds a single AI-refinement call so a slow model
	// never stalls the pipeline. Zero selects defaultRefineTimeout.
	refineTimeout time.Duration

	// sweep, when set (via WithDormancyPlanner), makes the periodic
	// Reconcile sweep activity-tiered via the shared tenancy.TieredSweep
	// helper: active tenants are re-evaluated every cycle, idle/dormant
	// ones at a reduced cadence, instead of reconciling all ~5000
	// tenants' inventories every cycle. nil keeps the legacy "every
	// active tenant every cycle" fan-out. Drift detection stays bounded
	// because cycle 0 sweeps everyone and the planner caps how stale any
	// tier's reconcile can get. The TieredSweep owns the monotonic cycle
	// counter and exports the sweep_tenants_visited metric.
	sweep *tenancy.TieredSweep
}

const defaultRefineTimeout = 3 * time.Second

// NewAppNoOpsEngine constructs the engine. store is required; apps and
// tenants are required only for the Reconcile sweep (OnAppDiscovered
// works without them). enforcer, refiner and audit are all optional.
func NewAppNoOpsEngine(
	store NoOpsStore,
	apps repository.CASBDiscoveredAppRepository,
	tenants repository.TenantRepository,
	logger *slog.Logger,
) *AppNoOpsEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &AppNoOpsEngine{
		store:         store,
		apps:          apps,
		tenants:       tenants,
		logger:        logger,
		nowFunc:       func() time.Time { return time.Now().UTC() },
		refineTimeout: defaultRefineTimeout,
	}
}

// SetClock overrides the wall clock for tests.
func (e *AppNoOpsEngine) SetClock(f func() time.Time) {
	if f != nil {
		e.nowFunc = f
	}
}

// SetEnforcer wires the enforcement primitive (e.g. *appdb.Service).
// When unset the engine only recommends — there is no hard dependency
// on the enforcement plane.
func (e *AppNoOpsEngine) SetEnforcer(enf AppEnforcer) { e.enforcer = enf }

// SetRefiner wires the optional AI refinement hook.
func (e *AppNoOpsEngine) SetRefiner(r ClassificationRefiner) { e.refiner = r }

// SetAuditLog wires the optional global audit-log sink so every NoOps
// action is also recorded in the platform-wide audit trail.
func (e *AppNoOpsEngine) SetAuditLog(a repository.AuditLogRepository) { e.audit = a }

// SetRolloutGate wires the staged-enablement gate for the NoOps
// auto-enforce capability. When set, the engine applies an auto action
// only for tenants whose rollout state is enforce; monitor dry-runs it
// and off disables it (see AutoEnforceGate). A nil gate is a no-op
// (legacy behavior retained), so wiring is fail-safe.
func (e *AppNoOpsEngine) SetRolloutGate(g AutoEnforceGate) { e.rolloutGate = g }

// WithDormancyPlanner makes the periodic Reconcile sweep activity-tiered
// using the shared tenancy.TieredSweep helper: active tenants are
// re-evaluated every cycle, idle ones at IdleEvery cadence, dormant ones
// at DormantEvery. The status filter is unchanged — only active tenants
// are ever reconciled — so this strictly removes redundant re-evaluation
// of quiet tenants' inventories. A nil sweep is a no-op (legacy
// every-active-tenant fan-out retained), so wiring is fail-safe.
// Returns the receiver for chaining at construction.
func (e *AppNoOpsEngine) WithDormancyPlanner(sweep *tenancy.TieredSweep) *AppNoOpsEngine {
	if sweep != nil {
		e.sweep = sweep
	}
	return e
}

// OnAppDiscovered implements AppDiscoveryHook: the shadow-IT flush
// calls it once per persisted app. It runs the full classify ->
// decide -> act -> audit pipeline for that single (tenant, app). It
// never returns an error: failures are logged and isolated so one app
// cannot abort a flush or another app's processing.
func (e *AppNoOpsEngine) OnAppDiscovered(ctx context.Context, tenantID uuid.UUID, app repository.CASBDiscoveredApp, meta AppDiscoveryMeta) {
	view := DiscoveredAppView{
		Name:          app.Name,
		Vendor:        app.Vendor,
		Category:      app.Category,
		BaselineRisk:  derefInt(app.RiskScore),
		ActiveDevices: derefInt(app.ActiveDeviceCount),
		HasConnector:  meta.HasConnector,
		Domains:       meta.Domains,
	}
	if err := e.process(ctx, tenantID, view, e.autoEnforceDecision(ctx, tenantID)); err != nil {
		e.logger.WarnContext(ctx, "casb: noops process failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("app", app.Name),
			slog.Any("error", err))
	}
}

// ReconcileTenant runs the pipeline across a tenant's entire discovered
// inventory. Used by the periodic sweep and by operators forcing a
// re-evaluation. Per-app failures are logged and skipped; the first
// error is returned so a persistent fault is visible.
func (e *AppNoOpsEngine) ReconcileTenant(ctx context.Context, tenantID uuid.UUID) error {
	if e.apps == nil {
		return fmt.Errorf("casb: ReconcileTenant requires a discovered-app repository")
	}
	apps, err := e.apps.List(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("casb: list discovered apps: %w", err)
	}
	// Resolve the staged-enablement decision once per tenant rather than
	// per app: the rollout state is tenant-wide, so a full-inventory sweep
	// (potentially thousands of apps) needs a single gate read.
	autoMode := e.autoEnforceDecision(ctx, tenantID)
	var firstErr error
	for _, app := range apps {
		if err := ctx.Err(); err != nil {
			return err
		}
		domains, hasConnector := catalogMetaFor(app.Name)
		view := DiscoveredAppView{
			Name:          app.Name,
			Vendor:        app.Vendor,
			Category:      app.Category,
			BaselineRisk:  derefInt(app.RiskScore),
			ActiveDevices: derefInt(app.ActiveDeviceCount),
			HasConnector:  hasConnector,
			Domains:       domains,
		}
		if err := e.process(ctx, tenantID, view, autoMode); err != nil {
			e.logger.WarnContext(ctx, "casb: noops reconcile app failed",
				slog.String("tenant_id", tenantID.String()),
				slog.String("app", app.Name),
				slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Reconcile sweeps active tenants' inventories once. Intended to be
// called on a schedule. Tenants are enumerated with the same bounded
// pagination demotion.go uses.
//
// When a dormancy planner is configured (WithDormancyPlanner), the
// sweep is activity-tiered: each active tenant is classified by its
// last_active_at and skipped this cycle if its tier is not yet due,
// collapsing the dominant avoidable cost of re-classifying thousands of
// quiet trial tenants' inventories every interval. Cycle 0 (the first
// sweep after start) visits every tenant, and the planner bounds how
// stale any tier's reconcile can get, so drift detection is preserved.
func (e *AppNoOpsEngine) Reconcile(ctx context.Context) error {
	if e.tenants == nil {
		return fmt.Errorf("casb: Reconcile requires a tenant repository")
	}
	var (
		firstErr error
		page     repository.Page
		active   int
	)
	// The TieredSweep owns the 0-based monotonic cycle counter; the
	// first sweep is cycle 0 (full visit). A nil sweep keeps the legacy
	// every-active-tenant fan-out.
	var cyc *tenancy.SweepCycle
	if e.sweep != nil {
		cyc = e.sweep.Begin(e.nowFunc())
		// Publish the per-tier tallies on every return path — including a
		// mid-sweep tenant-list error — so a transient failure never
		// silently drops this cycle's observability (Begin already
		// consumed the cycle number, so the partial counts are the
		// honest record of the work that did happen).
		defer func() {
			cyc.Finish()
			if summary := cyc.Summary(); summary.Skipped > 0 {
				e.logger.DebugContext(ctx, "casb: activity-tiered reconcile sweep",
					slog.Int64("cycle", summary.Cycle),
					slog.Int("active", active),
					slog.Int("visited", summary.Visited),
					slog.Int("skipped", summary.Skipped))
			}
		}()
	}
	for {
		res, err := e.tenants.List(ctx, page)
		if err != nil {
			return fmt.Errorf("casb: list tenants: %w", err)
		}
		for _, t := range res.Items {
			if t.Status != repository.TenantStatusActive {
				continue
			}
			active++
			// Only active-status tenants reach the tier gate, so the
			// metric's tally reflects the activity-tier distribution
			// among reconcilable tenants.
			if cyc != nil && !cyc.Visit(t.LastActiveAt) {
				continue
			}
			if err := e.ReconcileTenant(ctx, t.ID); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return firstErr
}

// process is the single-app pipeline shared by both entry points.
// autoMode is the tenant's staged-enablement decision, resolved once by
// the caller (per discovered app for the discovery hook, once per tenant
// for the inventory sweep) so a full-inventory reconcile does not re-read
// the rollout gate for every app.
func (e *AppNoOpsEngine) process(ctx context.Context, tenantID uuid.UUID, view DiscoveredAppView, autoMode autoEnforceMode) error {
	if tenantID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	cls := e.classify(ctx, tenantID, view)
	if _, err := e.store.UpsertClassification(ctx, tenantID, cls); err != nil {
		return fmt.Errorf("upsert classification: %w", err)
	}

	policy := e.policyFor(ctx, tenantID)
	verb, mode, reason := decideAction(cls, policy)
	if verb == ActionNone {
		return nil // monitor-only; nothing to record
	}

	action := CASBAppAction{
		TenantID:     tenantID,
		AppName:      cls.AppName,
		Category:     cls.Category,
		Enforcement:  verb,
		TrafficClass: verb.TrafficClass(),
		Mode:         mode,
		RiskScore:    cls.RiskScore,
		Confidence:   cls.Confidence,
		Sanction:     cls.Sanction,
		Reason:       reason,
		CreatedAt:    e.nowFunc(),
	}

	if mode == ActionModeAuto {
		switch autoMode {
		case autoEnforceApply:
			applied, finalReason := e.enforce(ctx, tenantID, view, verb, reason)
			action.Applied = applied
			action.Reason = finalReason
			if !applied && e.enforcer == nil {
				// No enforcement plane wired: degrade to a recommendation
				// rather than claiming an auto action that never happened.
				action.Mode = ActionModeRecommend
			}
		case autoEnforceDryRun:
			// rollout=monitor: emit the would-have verdict but take no
			// enforcement action. Recorded as a recommendation so no
			// downstream consumer mistakes it for an applied action.
			action.Mode = ActionModeRecommend
			action.Applied = false
			action.Reason = reason + " [rollout=monitor dry-run: would auto-apply; enforcement withheld]"
		case autoEnforceDisabled:
			// rollout=off or unreadable (fail-closed): auto-enforce is
			// not in effect for this tenant; recommend only.
			action.Mode = ActionModeRecommend
			action.Applied = false
			action.Reason = reason + " [rollout=off: auto-enforce disabled; recommendation only]"
		}
	}

	saved, err := e.store.AppendAction(ctx, tenantID, action)
	if err != nil {
		return fmt.Errorf("append action: %w", err)
	}
	e.auditGlobal(ctx, tenantID, saved)
	return nil
}

// autoEnforceMode is the resolved staged-enablement decision for a
// would-be auto action.
type autoEnforceMode int

const (
	// autoEnforceApply applies the auto action (rollout=enforce, or no
	// gate wired — the legacy behavior).
	autoEnforceApply autoEnforceMode = iota
	// autoEnforceDryRun records the would-have action but enforces
	// nothing (rollout=monitor).
	autoEnforceDryRun
	// autoEnforceDisabled recommends only (rollout=off or unreadable).
	autoEnforceDisabled
)

// autoEnforceDecision resolves whether a would-be auto action may be
// applied for this tenant, consulting the staged-enablement gate. With
// no gate wired — or for a tenant the framework does not yet manage (no
// rollout row) — it returns autoEnforceApply so the legacy config-flag
// behavior is preserved exactly, and wiring the gate never silently
// disables auto-enforce for an already-protected tenant. For a MANAGED
// tenant it maps the rollout state for CapabilityNoOpsAutoEnforce onto
// the three outcomes, failing closed to autoEnforceDisabled for
// off/unreadable state.
func (e *AppNoOpsEngine) autoEnforceDecision(ctx context.Context, tenantID uuid.UUID) autoEnforceMode {
	if e.rolloutGate == nil {
		return autoEnforceApply
	}
	state, managed := e.rolloutGate.GateState(ctx, tenantID, rollout.CapabilityNoOpsAutoEnforce)
	if !managed {
		// Tenant not opted into staged rollout: keep legacy auto-enforce.
		return autoEnforceApply
	}
	switch state {
	case rollout.StateEnforce:
		return autoEnforceApply
	case rollout.StateMonitor:
		return autoEnforceDryRun
	default:
		return autoEnforceDisabled
	}
}

// classify runs the deterministic classifier and, when a refiner is
// wired, attempts to refine it under a bounded context — falling back
// to the deterministic result on any error so the AI service is never
// a hard dependency.
func (e *AppNoOpsEngine) classify(ctx context.Context, tenantID uuid.UUID, view DiscoveredAppView) AppClassification {
	base := classifyApp(tenantID, view)
	base.ClassifiedAt = e.nowFunc()
	if e.refiner == nil {
		return base
	}
	rctx := ctx
	if e.refineTimeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, e.refineTimeout)
		defer cancel()
	}
	refined, err := e.refiner.Refine(rctx, view, base)
	if err != nil {
		e.logger.WarnContext(ctx, "casb: classification refine failed; using heuristic",
			slog.String("tenant_id", tenantID.String()),
			slog.String("app", view.Name),
			slog.Any("error", err))
		return base
	}
	// Trust the refiner's verdict but keep our invariants: clamp the
	// scores, preserve identity, stamp the source and time.
	refined.TenantID = tenantID
	refined.AppName = base.AppName
	refined.RiskScore = clampScore(refined.RiskScore)
	refined.Confidence = clampScore(refined.Confidence)
	if !refined.Sanction.IsValid() {
		refined.Sanction = base.Sanction
	}
	if refined.Category == "" {
		refined.Category = base.Category
	}
	refined.Source = ClassificationSourceAIRefined
	refined.ClassifiedAt = e.nowFunc()
	return refined
}

// policyFor loads the tenant's action policy, falling back to the smart
// default when none is stored or the lookup fails (fail-safe: a policy
// read error must not silently disable safety, so the default — which
// permits auto-enforce only in the narrow high-confidence window —
// applies).
func (e *AppNoOpsEngine) policyFor(ctx context.Context, tenantID uuid.UUID) ActionPolicy {
	p, err := e.store.GetActionPolicy(ctx, tenantID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			e.logger.WarnContext(ctx, "casb: action policy lookup failed; using default",
				slog.String("tenant_id", tenantID.String()),
				slog.Any("error", err))
		}
		return DefaultActionPolicy(tenantID)
	}
	return p
}

// enforce applies an auto action through the enforcement primitive.
// Returns whether protection is in effect and the final reason text
// (annotated with the outcome). A nil enforcer or an enforcement error
// yields applied=false; the caller degrades accordingly.
func (e *AppNoOpsEngine) enforce(ctx context.Context, tenantID uuid.UUID, view DiscoveredAppView, verb ActionEnforcement, reason string) (bool, string) {
	if e.enforcer == nil {
		return false, reason + " [no enforcer wired: recommendation only]"
	}
	target := verb.TrafficClass()
	domains := wildcardDomains(view.Domains)
	if len(domains) == 0 {
		return false, reason + " [no domains known: cannot scope enforcement]"
	}
	probe := firstNonEmpty(view.Domains)
	created, err := e.enforcer.EnsureProtection(ctx, tenantID, nil, probe, domains, target, reason)
	if err != nil {
		e.logger.WarnContext(ctx, "casb: noops auto-enforce failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("app", view.Name),
			slog.Any("error", err))
		return false, reason + " [enforcement failed: " + err.Error() + "]"
	}
	if created {
		return true, reason + " [auto-applied " + string(target) + " override]"
	}
	// No override was written because an explicit rule already provides
	// at least `target` protection. Report applied=false: the engine
	// took no enforcement action this cycle, so the audit row records a
	// recommendation-equivalent rather than an auto-applied change (see
	// the Applied contract in repository.CASBAppAction).
	return false, reason + " [already at least " + string(target) + "; no change]"
}

// decideAction is the pure decision function: given a classification
// and the tenant's policy it returns the enforcement verb, whether to
// apply it automatically or recommend it, and a human-readable reason.
//
// Smart-default policy:
//   - risk < DefaultActionMinRisk (30): no action (monitor only).
//   - sanctioned apps (tenant adopted them) are never throttled or
//     blocked; sensitive ones get a route recommendation, others none.
//   - otherwise the verb is chosen by risk band: >=70 enforce (block),
//     50-69 protect (inspect_full), 30-49 throttle (inspect_lite).
//   - ONLY protect is auto-eligible, and only when the policy permits
//     it, the app is unsanctioned, and risk+confidence clear the bars.
//     Everything else is a recommendation.
func decideAction(c AppClassification, policy ActionPolicy) (ActionEnforcement, ActionMode, string) {
	if c.RiskScore < riskBandThrottle {
		return ActionNone, ActionModeRecommend, ""
	}

	if c.Sanction == SanctionSanctioned {
		if isSensitiveCategory(c.Category) {
			return ActionRoute, ActionModeRecommend,
				fmt.Sprintf("sanctioned %s app (risk %d): recommend routing via tunnel_private",
					c.Category, c.RiskScore)
		}
		return ActionNone, ActionModeRecommend, ""
	}

	var verb ActionEnforcement
	switch {
	case c.RiskScore >= riskBandEnforce:
		verb = ActionEnforce
	case c.RiskScore >= riskBandProtect:
		verb = ActionProtect
	default:
		verb = ActionThrottle
	}

	autoEligible := policy.AutoEnforceEnabled &&
		verb == ActionProtect &&
		c.Sanction == SanctionUnsanctioned &&
		c.RiskScore >= policy.MinRisk &&
		c.Confidence >= policy.MinConfidence
	if autoEligible {
		return verb, ActionModeAuto,
			fmt.Sprintf("unsanctioned %s app, risk %d / confidence %d clear auto bars (>=%d / >=%d): auto-protect via inspect_full",
				c.Category, c.RiskScore, c.Confidence, policy.MinRisk, policy.MinConfidence)
	}

	return verb, ActionModeRecommend, recommendReason(verb, c)
}

func recommendReason(verb ActionEnforcement, c AppClassification) string {
	switch verb {
	case ActionEnforce:
		return fmt.Sprintf("high-risk %s app (risk %d): recommend blocking — auto-block withheld as destructive",
			c.Category, c.RiskScore)
	case ActionProtect:
		return fmt.Sprintf("%s %s app (risk %d / confidence %d): recommend inspect_full",
			c.Sanction, c.Category, c.RiskScore, c.Confidence)
	case ActionThrottle:
		return fmt.Sprintf("%s %s app (risk %d): recommend inspect_lite",
			c.Sanction, c.Category, c.RiskScore)
	}
	return ""
}

// isSensitiveCategory marks categories whose sanctioned use still
// warrants a private-overlay routing recommendation. It normalizes its
// input so the verdict holds regardless of casing/whitespace — the
// deterministic classifier already stores a normalized category, but an
// AI refiner can set an arbitrary one, and this comparison must not
// silently fall through to ActionNone on a cosmetic mismatch.
func isSensitiveCategory(category string) bool {
	switch strings.TrimSpace(strings.ToLower(category)) {
	case "identity", "code_repository", "itsm", "hcm", "cloud_iaas":
		return true
	}
	return false
}

func (e *AppNoOpsEngine) auditGlobal(ctx context.Context, tenantID uuid.UUID, a CASBAppAction) {
	if e.audit == nil {
		return
	}
	action := "casb.app_noops_recommend"
	if a.Mode == ActionModeAuto {
		action = "casb.app_noops_auto"
	}
	details, _ := json.Marshal(map[string]any{
		"app_name":      a.AppName,
		"category":      a.Category,
		"enforcement":   string(a.Enforcement),
		"traffic_class": string(a.TrafficClass),
		"mode":          string(a.Mode),
		"risk_score":    a.RiskScore,
		"confidence":    a.Confidence,
		"sanction":      string(a.Sanction),
		"applied":       a.Applied,
		"reason":        a.Reason,
	})
	id := a.ID
	if _, err := e.audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID:     tenantID,
		Action:       action,
		ResourceType: "casb_discovered_app",
		ResourceID:   &id,
		Details:      details,
	}); err != nil {
		e.logger.WarnContext(ctx, "casb: noops audit append failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("action", action),
			slog.Any("error", err))
	}
}

// --- helpers --------------------------------------------------------------

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// wildcardDomains turns registrable suffixes into override patterns
// that cover the apex and every subdomain ("slack.com" -> "*.slack.com",
// which appdb's matcher treats as matching both "slack.com" and
// "x.slack.com"). Deduplicated, order-preserving.
func wildcardDomains(suffixes []string) []string {
	if len(suffixes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(suffixes))
	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		if s == "" {
			continue
		}
		pat := "*." + s
		if _, dup := seen[pat]; dup {
			continue
		}
		seen[pat] = struct{}{}
		out = append(out, pat)
	}
	return out
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
