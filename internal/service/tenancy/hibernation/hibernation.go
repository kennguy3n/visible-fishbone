// Package hibernation is the leader-only dormant-tenant SCALE-TO-ZERO
// controller plus its wake-on-activity path. It is the second half of
// the Phase 1 dormancy work: where internal/service/tenancy's
// SweepPlanner only reduces how OFTEN a dormant trial is reconciled,
// this package actively parks a dormant tenant's ONGOING resource draw
// and rehydrates it transparently on the first sign of life.
//
// # What hibernation does
//
// When the leader-only [Controller] observes a tenant reach
// [tenancy.TierDormant] (no activity in >14d by default), it hibernates
// the tenant:
//
//   - Telemetry ingest is driven to near-zero. A [SampleResolver]
//     wired into the telemetry sampler returns a near-zero keep
//     probability for the tenant's traffic, so a dormant tenant that
//     somehow still emits events writes almost no ClickHouse rows.
//     Security-relevant events (the inspect_full traffic class — TLS
//     decrypt, AV, IPS, DLP) are NEVER sampled away: the sampler's
//     mandatory 1:1 floor for that class overrides the hibernation
//     rate, so the compliance/audit record is preserved intact.
//   - ClickHouse retention is driven to the aggressive floor by a
//     [RetentionResolver], so the tenant's hot partitions age into the
//     S3 cold tier sooner. The cold tier stays queryable for
//     audit/compliance reads; nothing is deleted.
//   - NATS subscriptions are condensed via a [SubscriptionController]
//     so the tenant stops holding warm subscription state.
//
// # Wake-on-activity
//
// The first login / agent check-in / real request flows through the
// activity [Recorder], which notifies the [Coordinator]. The
// coordinator wakes the tenant — clears the hibernation marker (so full
// telemetry resumes immediately), resumes its NATS subscriptions, and
// records the wake latency — transparently, targeting a few seconds.
//
// # Honesty contract / fail-safe
//
// The feature is gated default-OFF; with the gate off nothing in this
// package runs and every tenant is active. Absence of a hibernation
// record means active. Every gate that reads hibernation state fails
// safe toward MORE work: an unreadable or absent state is treated as
// active, a hibernate action that errors leaves the tenant active (it
// is retried next cycle, never force-parked on a half-applied state),
// and the dormancy decision keeps the SweepPlanner's hard staleness
// upper bound. The controller never weakens tenant isolation (RLS) and
// never drops a security-relevant event.
//
// # Dependency inversion
//
// The package declares the [Store], [ColdArchiver],
// [SubscriptionController] and [ActivityLister] interfaces it needs and
// depends on nothing in the persistence or telemetry layers; the
// Postgres/in-memory stores live in internal/repository and depend on
// this package, and the sampler/retention adapters satisfy the
// telemetry-layer interfaces structurally, so the controller stays
// unit-testable with no database, ClickHouse, or NATS.
package hibernation

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// State is a tenant's hibernation state. The default (no persisted row)
// is [StateActive].
type State string

const (
	// StateActive is the default: full telemetry fidelity, normal NATS
	// subscriptions, tier-appropriate ClickHouse retention. A tenant
	// with no persisted row is active.
	StateActive State = "active"
	// StateHibernated is scale-to-zero: non-security telemetry sampled
	// to near-zero, NATS subscriptions condensed, ClickHouse retention
	// at the aggressive floor. Security events are never dropped.
	StateHibernated State = "hibernated"
)

// Valid reports whether s is one of the two known states.
func (s State) Valid() bool {
	switch s {
	case StateActive, StateHibernated:
		return true
	default:
		return false
	}
}

// Hibernated reports whether s is the parked state.
func (s State) Hibernated() bool { return s == StateHibernated }

// Record is one tenant's persisted hibernation state plus the audit
// trail of its most recent transition in each direction.
type Record struct {
	TenantID uuid.UUID
	State    State
	// Reason is a human-readable note on the most recent transition
	// (e.g. the dormancy tier that triggered hibernation, or the wake
	// source). Empty on a freshly created row.
	Reason string
	// HibernatedAt / WokeAt are the timestamps of the most recent
	// hibernate / wake transition. Nil until the transition occurs.
	HibernatedAt *time.Time
	WokeAt       *time.Time
	UpdatedAt    time.Time
}

// Store is the durable hibernation-state persistence the controller and
// coordinator need. All methods are cross-tenant (system-scoped): the
// leader-only controller scans every tenant and the per-replica
// registry sync reads the whole set, so implementations run under the
// system role (RLS still FORCE-enabled; the system policy gates the
// cross-tenant access). Implementations live in internal/repository.
type Store interface {
	// List returns every persisted hibernation record. Tenants with no
	// row are absent (they are active by default), so the caller treats
	// "not in the result" as active.
	List(ctx context.Context) ([]Record, error)
	// SetHibernated upserts the tenant to StateHibernated with the given
	// reason, stamping hibernated_at at `at`. Idempotent.
	SetHibernated(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (Record, error)
	// SetActive upserts the tenant to StateActive with the given reason,
	// stamping woke_at at `at`. Idempotent; safe to call for a tenant
	// that was never hibernated.
	SetActive(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (Record, error)
}

// ColdArchiver applies the aggressive ClickHouse-TTL → S3 cold-archive
// step for a hibernating tenant's hot partitions. The forward-looking
// retention tightening is handled by [RetentionResolver]; this hook is
// the optional one-shot trigger for migrating already-resident hot
// partitions (or a no-op when that is left to natural TTL ageing).
//
// Implementations MUST be idempotent. The controller's hibernate path
// applies cold-archive → NATS condense → persist and fails safe: if a
// later step errors the tenant stays active and the whole sequence —
// including ArchiveTenant — is retried on the next reconcile cycle, so
// a re-archive of already-cold partitions must be a no-op rather than an
// error or a double-migration.
type ColdArchiver interface {
	ArchiveTenant(ctx context.Context, tenantID uuid.UUID) error
}

// SubscriptionController condenses (on hibernate) and resumes (on wake)
// a tenant's NATS subscriptions so a parked tenant stops holding warm
// subscription state.
type SubscriptionController interface {
	Condense(ctx context.Context, tenantID uuid.UUID) error
	Resume(ctx context.Context, tenantID uuid.UUID) error
}

// ActivityLister supplies the cheap (id, last_active_at) projection the
// controller classifies each cycle. It is satisfied by the tenant
// repository's ListTenantActivity.
type ActivityLister interface {
	ListTenantActivity(ctx context.Context) ([]TenantActivity, error)
}

// TenantActivity is the controller's view of one tenant's activity
// signal. It mirrors repository.TenantActivity but is redeclared here so
// the package keeps its inward-pointing dependency rule (the repository
// adapter converts).
type TenantActivity struct {
	ID           uuid.UUID
	LastActiveAt *time.Time
}

// noopWriter discards log output; used as the default logger sink so a
// nil logger passed to a constructor never panics on write.
type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

// NoopColdArchiver is the default [ColdArchiver]: it does nothing, so a
// deployment with no cold-archive trigger wired relies purely on the
// RetentionResolver tightening + natural TTL ageing.
type NoopColdArchiver struct{}

// ArchiveTenant implements [ColdArchiver].
func (NoopColdArchiver) ArchiveTenant(context.Context, uuid.UUID) error { return nil }

// NoopSubscriptionController is the default [SubscriptionController]: it
// does nothing, so a deployment with no NATS subscription manager wired
// still hibernates telemetry + retention without error.
type NoopSubscriptionController struct{}

// Condense implements [SubscriptionController].
func (NoopSubscriptionController) Condense(context.Context, uuid.UUID) error { return nil }

// Resume implements [SubscriptionController].
func (NoopSubscriptionController) Resume(context.Context, uuid.UUID) error { return nil }
