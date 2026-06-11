package casb

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// NoOps shadow-IT app handling.
//
// This file declares the domain types and persistence/enforcement
// boundaries for the per-tenant "NoOps" pipeline that turns a freshly
// discovered shadow-IT app into a classification, an action
// (recommended or automatically enforced), an immutable audit row and
// a periodic per-tenant digest.
//
// Layering: the persisted row DTOs live in internal/repository
// (casb_app_action.go) next to the other CASB row types, so the
// postgres and memory backends persist them without importing this
// service package (which would cycle: casb -> policy -> middleware ->
// postgres -> casb). The store INTERFACE is declared here, where it is
// consumed — the idiomatic Go shape. The deferred wiring task that owns
// repository/interfaces.go + main.go can later promote NoOpsStore into
// repository/interfaces.go unchanged; nothing here blocks that.

// The persisted row DTOs live in internal/repository (alongside the
// other CASB row types) so the postgres and memory backends can persist
// them without importing this service package — doing so would form an
// import cycle (casb -> policy -> middleware -> postgres -> casb). They
// are re-exported here as aliases so service code keeps one vocabulary
// and the public casb API is unchanged. The store INTERFACE stays here,
// where it is consumed, which is the idiomatic Go shape regardless.
type (
	SanctionState     = repository.SanctionState
	AppClassification = repository.AppClassification
	ActionMode        = repository.ActionMode
	ActionEnforcement = repository.ActionEnforcement
	CASBAppAction     = repository.CASBAppAction
	ActionPolicy      = repository.ActionPolicy
	DigestState       = repository.DigestState
)

const (
	SanctionSanctioned   = repository.SanctionSanctioned
	SanctionTolerated    = repository.SanctionTolerated
	SanctionUnsanctioned = repository.SanctionUnsanctioned

	ClassificationSourceHeuristic = repository.ClassificationSourceHeuristic
	ClassificationSourceAIRefined = repository.ClassificationSourceAIRefined

	ActionModeAuto      = repository.ActionModeAuto
	ActionModeRecommend = repository.ActionModeRecommend

	ActionNone     = repository.ActionNone
	ActionThrottle = repository.ActionThrottle
	ActionProtect  = repository.ActionProtect
	ActionRoute    = repository.ActionRoute
	ActionEnforce  = repository.ActionEnforce
)

// Default smart-default action policy. See ActionPolicy.
//
// The auto window is deliberately narrow: only a high-confidence,
// genuinely-risky, unsanctioned app whose only auto-eligible verb is
// the non-blocking Protect (inspect_full) is ever touched without an
// operator. Riskier verdicts (block) and lower-confidence ones become
// recommendations.
const (
	DefaultAutoActionMinRisk       = 60
	DefaultAutoActionMinConfidence = 80
	// DefaultActionMinRisk is the floor below which the engine emits no
	// action at all (the app stays monitor-only in the inventory).
	DefaultActionMinRisk = 30
)

// Risk-band cutoffs that select the enforcement verb. Kept as a single
// source of truth for the engine and its tests.
const (
	riskBandEnforce  = 70 // >= -> enforce (block), recommend-only
	riskBandProtect  = 50 // >= -> protect (inspect_full), auto-eligible
	riskBandThrottle = DefaultActionMinRisk
)

// DefaultActionPolicy returns the smart-default policy for a tenant
// that has not customised one.
func DefaultActionPolicy(tenantID uuid.UUID) ActionPolicy {
	return ActionPolicy{
		TenantID:           tenantID,
		AutoEnforceEnabled: true,
		MinRisk:            DefaultAutoActionMinRisk,
		MinConfidence:      DefaultAutoActionMinConfidence,
	}
}

// NoOpsStore is the persistence boundary for the NoOps pipeline. It
// owns the three migration-061 tables (classifications, action
// policies, audit actions) and the digest cursor. Every method is
// tenant-scoped; the postgres implementation runs each call inside the
// RLS transaction so a tenant can never read another's rows, and the
// memory implementation mirrors that by filtering on tenant_id.
type NoOpsStore interface {
	// Classifications.
	UpsertClassification(ctx context.Context, tenantID uuid.UUID, c AppClassification) (AppClassification, error)
	GetClassification(ctx context.Context, tenantID uuid.UUID, appName string) (AppClassification, error)
	ListClassifications(ctx context.Context, tenantID uuid.UUID) ([]AppClassification, error)

	// Per-tenant action policy. GetActionPolicy returns ErrNotFound
	// when the tenant has not customised one, so callers fall back to
	// DefaultActionPolicy.
	GetActionPolicy(ctx context.Context, tenantID uuid.UUID) (ActionPolicy, error)
	UpsertActionPolicy(ctx context.Context, tenantID uuid.UUID, p ActionPolicy) (ActionPolicy, error)

	// Audit trail. AppendAction is append-only.
	AppendAction(ctx context.Context, tenantID uuid.UUID, a CASBAppAction) (CASBAppAction, error)
	// ListActionsSince returns actions created strictly after `since`,
	// oldest first, for the digest builder.
	ListActionsSince(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]CASBAppAction, error)
	// ListActions returns the most recent actions (newest first),
	// capped at limit, for the operator console.
	ListActions(ctx context.Context, tenantID uuid.UUID, limit int) ([]CASBAppAction, error)

	// Digest cursor. GetDigestState returns ErrNotFound when no digest
	// has run for the tenant yet.
	GetDigestState(ctx context.Context, tenantID uuid.UUID) (DigestState, error)
	UpsertDigestState(ctx context.Context, tenantID uuid.UUID, st DigestState) (DigestState, error)
}

// AppEnforcer is the narrow enforcement primitive the action engine
// needs from appdb. *appdb.Service satisfies it structurally
// (EnsureProtection), so casb does not import appdb. The engine treats
// a nil enforcer as "recommend-only" — there is no hard dependency on
// the enforcement plane, so the NoOps pipeline degrades to pure
// recommendations rather than failing when appdb is not wired.
type AppEnforcer interface {
	// EnsureProtection idempotently installs a tenant override steering
	// `domains` to `target`, but ONLY when that tightens the current
	// effective class (fail-safe: automation may add inspection, never
	// remove it). `probe` is a representative concrete host used to
	// resolve the current class. Returns created=false when the app is
	// already at least as protected as target.
	EnsureProtection(
		ctx context.Context,
		tenantID uuid.UUID,
		actorID *uuid.UUID,
		probe string,
		domains []string,
		target repository.TrafficClass,
		reason string,
	) (created bool, err error)
}

// ClassificationRefiner is the OPTIONAL hook to refine a deterministic
// classification via the AI service. The engine calls it only when one
// is configured, bounds it with the caller's context, and on any error
// keeps the deterministic result — so the AI service is never a hard
// dependency and never blocks the pipeline.
type ClassificationRefiner interface {
	Refine(ctx context.Context, view DiscoveredAppView, base AppClassification) (AppClassification, error)
}
