package repository

import (
	"time"

	"github.com/google/uuid"
)

// CASB NoOps app-handling row types.
//
// These are the persisted DTOs for the per-tenant NoOps pipeline that
// classifies shadow-IT apps and records the action (recommended or
// auto-enforced) taken on each. They live here, alongside the other
// CASB row types (CASBDiscoveredApp et al.), so the postgres and memory
// backends can persist them without importing the casb service package
// — the service package would otherwise form an import cycle
// (casb -> policy -> middleware -> postgres). The casb package
// re-exports these as aliases so service code keeps a single vocabulary.
// The store interface itself is declared in the casb service package
// (where it is consumed), per the deferred-wiring constraints.

// SanctionState is the recommended posture for a discovered app.
//
//   - sanctioned:   the tenant deliberately adopted the app (e.g. it has
//     a first-class CASB connector); automation leaves it alone.
//   - tolerated:    a known, moderate-risk SaaS with no connector; the
//     pipeline may recommend inspection but does not auto-enforce.
//   - unsanctioned: a higher-risk app the tenant likely does not know is
//     in use — the only state eligible for automatic enforcement.
type SanctionState string

const (
	SanctionSanctioned   SanctionState = "sanctioned"
	SanctionTolerated    SanctionState = "tolerated"
	SanctionUnsanctioned SanctionState = "unsanctioned"
)

// IsValid reports whether s is a known sanction state.
func (s SanctionState) IsValid() bool {
	switch s {
	case SanctionSanctioned, SanctionTolerated, SanctionUnsanctioned:
		return true
	}
	return false
}

// Classification provenance.
const (
	ClassificationSourceHeuristic = "heuristic"
	ClassificationSourceAIRefined = "ai_refined"
)

// AppClassification is the deterministic (optionally AI-refined) verdict
// for one discovered app within one tenant, keyed by (tenant, app name).
type AppClassification struct {
	TenantID     uuid.UUID     `json:"tenant_id"`
	AppName      string        `json:"app_name"`
	Category     string        `json:"category"`
	RiskScore    int           `json:"risk_score"` // 0-100
	Sanction     SanctionState `json:"sanction"`
	Confidence   int           `json:"confidence"` // 0-100
	Source       string        `json:"source"`     // heuristic | ai_refined
	Rationale    string        `json:"rationale"`
	ClassifiedAt time.Time     `json:"classified_at"`
}

// ActionMode distinguishes an automatically-applied action from a
// recommendation an operator must confirm.
type ActionMode string

const (
	ActionModeAuto      ActionMode = "auto"
	ActionModeRecommend ActionMode = "recommend"
)

// ActionEnforcement is the NoOps action verb. Each maps to exactly one
// traffic class the appdb enforcement primitives understand.
type ActionEnforcement string

const (
	// ActionNone — risk below the action floor; monitor only.
	ActionNone ActionEnforcement = "none"
	// ActionThrottle — demote trust to inspect_lite. Recommend-only.
	ActionThrottle ActionEnforcement = "throttle"
	// ActionProtect — full SWG via inspect_full. The only auto-eligible
	// verb: it adds inspection without denying access.
	ActionProtect ActionEnforcement = "protect"
	// ActionRoute — steer through the tenant-private mTLS overlay
	// (tunnel_private). Recommend-only.
	ActionRoute ActionEnforcement = "route"
	// ActionEnforce — block at the earliest enforcement point.
	// Recommend-only: auto-blocking a SaaS app would break the business.
	ActionEnforce ActionEnforcement = "enforce"
)

// TrafficClass returns the traffic class this enforcement verb installs,
// or "" for ActionNone.
func (a ActionEnforcement) TrafficClass() TrafficClass {
	switch a {
	case ActionThrottle:
		return TrafficClassInspectLite
	case ActionProtect:
		return TrafficClassInspectFull
	case ActionRoute:
		return TrafficClassTunnelPrivate
	case ActionEnforce:
		return TrafficClassBlock
	}
	return ""
}

// CASBAppAction is one immutable row in the NoOps audit trail: a single
// automatic or recommended action the engine emitted for a discovered
// app. Rows are append-only — a later reconcile that changes the verdict
// writes a new row rather than mutating an old one.
type CASBAppAction struct {
	ID           uuid.UUID         `json:"id"`
	TenantID     uuid.UUID         `json:"tenant_id"`
	AppName      string            `json:"app_name"`
	Category     string            `json:"category"`
	Enforcement  ActionEnforcement `json:"enforcement"`
	TrafficClass TrafficClass      `json:"traffic_class"`
	Mode         ActionMode        `json:"mode"`
	RiskScore    int               `json:"risk_score"`
	Confidence   int               `json:"confidence"`
	Sanction     SanctionState     `json:"sanction"`
	// Applied is true only when Mode==auto AND the enforcement primitive
	// installed (or confirmed) a tightening override. A recommendation,
	// or an auto action that no-op'd because the app was already at least
	// as protected, is false.
	Applied   bool      `json:"applied"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// ActionPolicy is the per-tenant smart-default policy that gates
// automatic enforcement. A tenant with no stored policy uses the
// engine's DefaultActionPolicy.
type ActionPolicy struct {
	TenantID uuid.UUID `json:"tenant_id"`
	// AutoEnforceEnabled is the master switch. When false the engine
	// only ever recommends.
	AutoEnforceEnabled bool `json:"auto_enforce_enabled"`
	// MinRisk / MinConfidence are the auto-enforcement bars; an action
	// is applied automatically only when the classification clears both
	// (and the chosen verb is auto-eligible).
	MinRisk       int       `json:"min_risk"`
	MinConfidence int       `json:"min_confidence"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// DigestState tracks how far the per-tenant digest has been emitted so
// the next digest only summarises actions since the last one.
type DigestState struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	LastDigestAt  time.Time `json:"last_digest_at"`
	LastActionsAt time.Time `json:"last_actions_at"`
}
