// Package rollout is the per-tenant, per-capability STAGED-ENABLEMENT
// (rollout) framework for the platform's default-OFF capability gates.
//
// # Why
//
// Several capabilities ship default-OFF and were historically flipped by
// a single binary config flag: the ClamAV SWG ext-authz listener
// (clamav_swg), the shadow-IT NoOps auto-enforce pipeline
// (noops_autoenforce), and the IdP directory sync (idp_directory_sync).
// Flipping such a flag took a capability straight from "does nothing" to
// "fully enforcing" for a tenant with no observable in-between — a risky,
// un-rehearsed change for a security control that can deny traffic or
// off-board users.
//
// This package replaces that binary flip with a small state machine that
// each capability advances through deliberately:
//
//		off  ->  monitor  ->  enforce
//
//	  - off      — the default. The capability does not evaluate and does
//	               NOT enforce.
//	  - monitor  — dry-run. The capability evaluates and emits telemetry /
//	               "would-have" verdicts but takes NO enforcement action.
//	  - enforce  — full enforcement.
//
// # Honesty contract
//
// The default state for EVERY tenant/capability is [StateOff]: a tenant
// with no persisted row reads back as off. Nothing in this package
// auto-advances a capability — advancement is only ever an explicit
// operator transition. The one automatic transition is a rollback
// (monitor/enforce -> off) triggered when monitor-phase metrics breach a
// configured threshold; the framework only ever moves a capability
// toward safety on its own, never toward enforcement. Every gate that
// reads this state MUST fail closed to off when the state is unreadable
// (see [Service.EffectiveState]).
//
// # Dependency inversion
//
// The package declares the [Repository] interface it needs and depends
// on nothing in the persistence layer; the Postgres and in-memory
// implementations live in internal/repository/{postgres,memory} and
// depend on this package, so the service stays unit-testable with no
// database.
package rollout

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// State is one phase of a capability's staged enablement. The three
// states are strictly ordered (off < monitor < enforce) so the state
// machine can tell an advance from a rollback.
type State string

const (
	// StateOff is the default: the capability neither evaluates nor
	// enforces. A tenant/capability with no persisted row is off.
	StateOff State = "off"
	// StateMonitor is dry-run: the capability evaluates and emits
	// "would-have" telemetry but takes no enforcement action.
	StateMonitor State = "monitor"
	// StateEnforce is full enforcement.
	StateEnforce State = "enforce"
)

// Valid reports whether s is one of the three known states.
func (s State) Valid() bool {
	switch s {
	case StateOff, StateMonitor, StateEnforce:
		return true
	default:
		return false
	}
}

// rank returns a monotonic ordering for the state (off=0 … enforce=2),
// or -1 for an unknown state so it never compares as more advanced than
// a real one. It is the basis for distinguishing an advance from a
// rollback.
func (s State) rank() int {
	switch s {
	case StateOff:
		return 0
	case StateMonitor:
		return 1
	case StateEnforce:
		return 2
	default:
		return -1
	}
}

// Enforces reports whether the capability actually enforces in this
// state. Only [StateEnforce] does.
func (s State) Enforces() bool { return s == StateEnforce }

// Evaluates reports whether the capability runs its evaluation at all in
// this state (monitor dry-runs it; enforce runs and acts on it). Off
// does neither.
func (s State) Evaluates() bool { return s == StateMonitor || s == StateEnforce }

// Capability identifies a default-OFF gate governed by the rollout
// framework. New capabilities are added here (and to [AllCapabilities]);
// no schema migration is required — the persistence layer stores the
// capability as an opaque key.
type Capability string

const (
	// CapabilityClamAVSWG is the ClamAV Secure Web Gateway ext-authz
	// listener (PR #178): per-request content scanning at the SWG.
	CapabilityClamAVSWG Capability = "clamav_swg"
	// CapabilityNoOpsAutoEnforce is the shadow-IT NoOps auto-enforce
	// pipeline (PR #172): automatically applying the narrow auto action
	// to a discovered app rather than only recommending it.
	CapabilityNoOpsAutoEnforce Capability = "noops_autoenforce"
	// CapabilityIDPDirectorySync is the IdP directory sync (PR #177):
	// provisioning and off-boarding local users from a tenant's upstream
	// directory.
	CapabilityIDPDirectorySync Capability = "idp_directory_sync"
	// CapabilityMarginAutopilot is the margin/cost autopilot (WS-7): the
	// metering engine's NoOps actions that act on underwater, over-budget
	// and anomalous tenants. Unlike the other gates it governs only the
	// engine's narrow DESTRUCTIVE auto-action (pinning a trial's hard
	// budget cap); recommendation + audit always run regardless of state,
	// so off (the default) is recommend-only rather than do-nothing.
	CapabilityMarginAutopilot Capability = "margin_autopilot"
)

// AllCapabilities returns every capability the framework governs, in a
// stable order. It is the source of truth for "list every capability's
// state for a tenant", so a capability with no persisted row is still
// reported (as off).
func AllCapabilities() []Capability {
	return []Capability{
		CapabilityClamAVSWG,
		CapabilityNoOpsAutoEnforce,
		CapabilityIDPDirectorySync,
		CapabilityMarginAutopilot,
	}
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	switch c {
	case CapabilityClamAVSWG, CapabilityNoOpsAutoEnforce, CapabilityIDPDirectorySync, CapabilityMarginAutopilot:
		return true
	default:
		return false
	}
}

// SystemActor is the updated_by value recorded when the framework itself
// drives a transition (an automatic monitor-phase rollback), as opposed
// to an operator-initiated one.
const SystemActor = "system"

// Record is the persisted rollout state for one (tenant, capability).
// It is the shape shared across the service and repository layers.
type Record struct {
	// TenantID scopes the record; RLS enforces isolation in Postgres and
	// explicit filtering does so in the memory repo.
	TenantID uuid.UUID
	// Capability is the governed gate.
	Capability Capability
	// State is the current rollout phase.
	State State
	// Reason is the human-readable detail for the most recent
	// transition (operator note or auto-rollback trigger), empty on a
	// never-transitioned default record.
	Reason string
	// UpdatedBy is the actor that drove the most recent transition (an
	// operator id/subject, or [SystemActor] for an auto-rollback), empty
	// on a default record.
	UpdatedBy string
	// CreatedAt / UpdatedAt are set by the repository.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// defaultRecord is the off-by-default record returned for a tenant /
// capability that has never been transitioned. It is what every gate
// reads when no row exists — the fail-closed baseline.
func defaultRecord(tenantID uuid.UUID, c Capability) Record {
	return Record{TenantID: tenantID, Capability: c, State: StateOff}
}

// Transition validation errors. They wrap repository.ErrInvalidArgument
// so handlers map them to 400 via the standard WriteRepositoryError
// path, while still being distinguishable with errors.Is for tests and
// callers.
var (
	// ErrInvalidState is returned when a target/observed state is not one
	// of the three known states.
	ErrInvalidState = fmt.Errorf("%w: invalid rollout state", repository.ErrInvalidArgument)
	// ErrInvalidCapability is returned for an unknown capability.
	ErrInvalidCapability = fmt.Errorf("%w: unknown capability", repository.ErrInvalidArgument)
	// ErrNoOpTransition is returned when the target state equals the
	// current state: a transition must change the state.
	ErrNoOpTransition = fmt.Errorf("%w: target state equals current state", repository.ErrInvalidArgument)
	// ErrSkipNotAllowed is returned when an advance would skip the
	// monitor phase (off -> enforce) without the explicit allow-skip
	// override. This is the core guardrail: enforcement is only reached
	// by passing through a monitor (dry-run) phase first.
	ErrSkipNotAllowed = fmt.Errorf("%w: advancing off->enforce skips the required monitor phase; pass allow_skip to override", repository.ErrInvalidArgument)
)

// validateTransition reports whether moving from -> to is permitted.
//
// Rules:
//   - both states must be valid and differ (no no-op transition).
//   - a ROLLBACK (to a lower-ranked state) is always allowed — moving a
//     capability toward safety never needs permission.
//   - an ADVANCE by one step (off->monitor, monitor->enforce) is allowed.
//   - an ADVANCE that skips a step (off->enforce) is rejected unless
//     allowSkip is set: enforcement must be rehearsed in monitor first.
func validateTransition(from, to State, allowSkip bool) error {
	if !from.Valid() || !to.Valid() {
		return ErrInvalidState
	}
	if from == to {
		return ErrNoOpTransition
	}
	if to.rank() < from.rank() {
		return nil // rollback: always permitted
	}
	if to.rank()-from.rank() == 1 {
		return nil // single-step advance
	}
	// Multi-step advance (off -> enforce): only with the explicit override.
	if allowSkip {
		return nil
	}
	return ErrSkipNotAllowed
}
