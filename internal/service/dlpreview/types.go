// Package dlpreview is the human-in-the-loop (HITL) review queue for
// DLP events the endpoint engine flags but does not block.
//
// The endpoint AI-app exfiltration signal (crates/sng-dlp, `ai_app`) is
// coach-first: it monitors/coaches by default and only blocks on an
// explicit high-confidence opt-in. Everything it flags but does not
// block is a candidate for human judgement. Those events are enqueued
// here, scoped per tenant, and a reviewer approves, blocks, or dismisses
// each one. A non-blocking digest summarises the backlog for operators
// without taking any enforcement action (NoOps).
//
// # Privacy
//
// The queue stores ONLY redacted aggregates: the destination app id, a
// severity and confidence, and a list of finding *summaries*
// (kind/label/count/severity). It never stores the matched bytes, the
// surrounding content, the upload URL's path/query, or any other raw
// payload — mirroring the redaction invariant the Rust signal enforces.
// The type system makes this hard to violate: [EnqueueInput] accepts
// only [FindingAggregate] values, which have no field for raw content.
//
// # Dependency inversion
//
// This package declares the [Repository] and [AuditSink] interfaces it
// needs and depends on nothing in the persistence layer. The Postgres
// and in-memory implementations live in internal/repository/{postgres,
// memory} and depend on this package, not the other way around, so the
// service stays unit-testable against the memory repo with no database.
package dlpreview

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ReviewState is the lifecycle state of a queued event. A new event is
// [StatePending]; it transitions exactly once to one of the terminal
// states.
type ReviewState string

const (
	// StatePending is the initial state: awaiting a human decision.
	StatePending ReviewState = "pending"
	// StateApproved means a reviewer judged the upload acceptable
	// (a false positive or a sanctioned transfer).
	StateApproved ReviewState = "approved"
	// StateBlocked means a reviewer confirmed the upload is a real
	// exposure that should have been (or going forward should be)
	// blocked.
	StateBlocked ReviewState = "blocked"
	// StateDismissed means the event needs no action (noise, duplicate,
	// out of scope) without asserting it was or wasn't a true positive.
	StateDismissed ReviewState = "dismissed"
)

// Valid reports whether s is one of the four known states.
func (s ReviewState) Valid() bool {
	switch s {
	case StatePending, StateApproved, StateBlocked, StateDismissed:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether s is a decided (non-pending) state.
func (s ReviewState) IsTerminal() bool {
	return s.Valid() && s != StatePending
}

// Severity mirrors the Rust DLP severity ladder. Ordering matters for
// the digest, so it is exposed via [Severity.Rank].
type Severity string

const (
	// SeverityLow is informational (e.g. an email address to a chatbot).
	SeverityLow Severity = "low"
	// SeverityMedium is a moderate exposure (e.g. a national id number).
	SeverityMedium Severity = "medium"
	// SeverityHigh is a serious exposure (e.g. a keyed credential or a
	// confidential banner).
	SeverityHigh Severity = "high"
	// SeverityCritical is the most severe (e.g. a private key block).
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Rank returns a monotonic rank (low=0 … critical=3) for ordering and
// "max severity" aggregation. An unknown severity ranks below low so it
// never masquerades as more severe than it is.
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 0
	case SeverityMedium:
		return 1
	case SeverityHigh:
		return 2
	case SeverityCritical:
		return 3
	default:
		return -1
	}
}

// FindingKind classifies what a finding aggregate is about. It mirrors
// the Rust `FindingKind` so the redacted evidence round-trips.
type FindingKind string

const (
	// FindingPII is personally identifiable information.
	FindingPII FindingKind = "pii"
	// FindingSecret is credential material (API keys, tokens, …).
	FindingSecret FindingKind = "secret"
	// FindingConfidential is a company-confidential banner/marker.
	FindingConfidential FindingKind = "confidential"
)

// FindingAggregate is a redacted, aggregate description of one class of
// finding inside a flagged upload. It deliberately carries NO matched
// bytes, offsets, or surrounding text — only counts and labels — so it
// is safe to persist and to surface in a digest.
type FindingAggregate struct {
	// Kind is the finding category.
	Kind FindingKind `json:"kind"`
	// Label is the detector/rule id that fired (e.g. "ssn_us",
	// "github_token", "confidential"). It is a stable identifier, never
	// user data.
	Label string `json:"label"`
	// Count is how many distinct matches of this label were observed.
	Count int `json:"count"`
	// MaxConfidence is the highest per-match confidence in [0,1].
	MaxConfidence float64 `json:"max_confidence"`
	// Severity is the severity assigned to this finding class.
	Severity Severity `json:"severity"`
}

// ReviewEvent is one flagged upload in the queue. It is the persisted
// shape shared across the service and repository layers.
type ReviewEvent struct {
	// ID is the stable row id.
	ID uuid.UUID
	// TenantID scopes the event; RLS enforces isolation in Postgres and
	// explicit filtering does so in the memory repo.
	TenantID uuid.UUID
	// Signal is the producing signal, e.g. "ai_app_upload".
	Signal string
	// DestinationApp is the AI-app id (e.g. "chatgpt") or the
	// "suspected_ai_app" sentinel for a heuristic match.
	DestinationApp string
	// Severity is the overall severity of the event.
	Severity Severity
	// Confidence is the detector confidence in [0,1].
	Confidence float64
	// State is the current lifecycle state.
	State ReviewState
	// Findings is the redacted evidence: a list of finding aggregates.
	Findings []FindingAggregate
	// DeviceID is the originating device for the flagged upload, or nil
	// when the producer did not supply one. It is triage context for the
	// reviewer (which endpoint, is one device noisy), stored as the bare
	// identifier — never PII.
	DeviceID *uuid.UUID
	// OccurredAt is when the upload happened at the edge, or nil when the
	// producer did not supply it. Distinct from CreatedAt (the control
	// plane's enqueue time): the telemetry pipeline can lag, so this is
	// the time the user actually acted.
	OccurredAt *time.Time
	// CreatedAt is when the event was enqueued.
	CreatedAt time.Time
	// DecidedAt is when the event reached a terminal state, or nil while
	// pending.
	DecidedAt *time.Time
	// DecidedBy is the reviewer's actor id, or nil while pending.
	DecidedBy *string
}

// ListFilter narrows a [Repository.List] query.
type ListFilter struct {
	// State, if non-nil, restricts results to that state.
	State *ReviewState
	// Limit caps the number of rows; a non-positive value means "use the
	// repository default".
	Limit int
}

// Summary is the aggregate backlog snapshot a [Repository] computes for
// the non-blocking digest. The service decorates it with the window it
// was asked for; the repository fills the counts.
type Summary struct {
	// Total events created at or after the digest's `since` cutoff.
	Total int
	// Pending is how many of those are still awaiting a decision.
	Pending int
	// ByState counts events by lifecycle state.
	ByState map[ReviewState]int
	// BySeverity counts events by severity.
	BySeverity map[Severity]int
	// PendingByApp counts the still-pending backlog by destination app —
	// the actionable "what is waiting on a human, and where is it going"
	// view.
	PendingByApp map[string]int
}

// Repository is the persistence contract the queue depends on. It is
// declared here (not in internal/repository) so the dependency points
// inward: the concrete repos implement this interface.
//
// Every method is tenant-scoped: implementations MUST constrain all
// reads and writes to tenantID (Postgres via the `sng.tenant_id` RLS
// GUC, memory via explicit filtering) and MUST NOT trust an id argument
// to belong to the tenant without checking.
type Repository interface {
	// Enqueue inserts ev (its ID/CreatedAt/State already set by the
	// service) and returns the stored row.
	Enqueue(ctx context.Context, tenantID uuid.UUID, ev ReviewEvent) (ReviewEvent, error)

	// Get returns the event by id within the tenant, or ErrNotFound.
	Get(ctx context.Context, tenantID, id uuid.UUID) (ReviewEvent, error)

	// List returns events for the tenant, newest first, subject to f.
	List(ctx context.Context, tenantID uuid.UUID, f ListFilter) ([]ReviewEvent, error)

	// Transition atomically moves a pending event to the terminal state
	// `to`, stamping decidedAt/decidedBy. It MUST return ErrNotFound if
	// the event does not exist for the tenant and ErrConflict if the
	// event is already terminal (so a decision can never be overwritten).
	Transition(ctx context.Context, tenantID, id uuid.UUID, to ReviewState, decidedBy string, decidedAt time.Time) (ReviewEvent, error)

	// Summary aggregates the tenant's events created at/after `since`.
	Summary(ctx context.Context, tenantID uuid.UUID, since time.Time) (Summary, error)

	// BlockedApps returns the distinct destination apps for which the
	// tenant has at least one event in [StateBlocked] — the apps an
	// operator has confirmed should be blocked. The result is sorted for
	// a deterministic bundle and is an empty (non-nil) slice when none
	// are blocked. Implementations MUST scope to tenantID like every
	// other method.
	BlockedApps(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// AuditSink records an immutable audit trail of queue activity. It is a
// separate seam so the durable queue and the audit log can be backed by
// different stores, and so the service can run with a no-op sink in
// tests. Implementations MUST treat records as append-only.
type AuditSink interface {
	// RecordReview appends one audit record. An error is propagated to
	// the caller of the triggering operation so audit failures are never
	// silently dropped.
	RecordReview(ctx context.Context, rec AuditRecord) error
}

// AuditAction is the queue operation an [AuditRecord] describes.
type AuditAction string

const (
	// AuditEnqueue is recorded when an event enters the queue.
	AuditEnqueue AuditAction = "enqueue"
	// AuditApprove/AuditBlock/AuditDismiss are recorded on the
	// corresponding terminal decision.
	AuditApprove AuditAction = "approve"
	AuditBlock   AuditAction = "block"
	AuditDismiss AuditAction = "dismiss"
)

// AuditRecord is one immutable audit-trail entry.
type AuditRecord struct {
	// TenantID scopes the record.
	TenantID uuid.UUID
	// EventID is the review event the action applied to.
	EventID uuid.UUID
	// Action is what happened.
	Action AuditAction
	// Actor is who did it ("system" for enqueue).
	Actor string
	// ResultState is the event state after the action.
	ResultState ReviewState
	// At is when the action occurred.
	At time.Time
}

// NoopAuditSink is an [AuditSink] that discards every record. It is the
// default when no sink is injected, so the queue is fully functional
// (minus the external audit trail) out of the box.
type NoopAuditSink struct{}

// RecordReview implements [AuditSink] by doing nothing.
func (NoopAuditSink) RecordReview(context.Context, AuditRecord) error { return nil }
