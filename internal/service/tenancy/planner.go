// Package tenancy turns the raw tenants.last_active_at signal into an
// activity-tiered sweep plan. It is the control-plane half of the
// Phase 1 dormancy work: periodic per-tenant sweeps (IdP directory
// sync, posture refresh, ...) previously fanned out across all ~5000
// tenants every cycle, treating a months-idle trial identically to a
// busy enterprise. SweepPlanner lets a sweep visit only the tenants
// worth visiting this cycle — active tenants every cycle, idle ones at
// a reduced cadence, dormant ones rarely — collapsing the dominant
// avoidable control-plane cost while keeping a hard upper bound on how
// stale any tenant's reconcile can get.
package tenancy

import (
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Tier buckets a tenant by how recently the data plane last reported
// activity for it.
type Tier int

const (
	// TierActive: seen within IdleAfter. Visited every sweep cycle.
	TierActive Tier = iota
	// TierIdle: seen within DormantAfter but not IdleAfter. Visited on
	// a reduced cadence.
	TierIdle
	// TierDormant: not seen within DormantAfter, or never seen at all
	// (LastActiveAt == nil). Visited rarely.
	TierDormant
)

// String renders the tier for logs/metrics labels.
func (t Tier) String() string {
	switch t {
	case TierActive:
		return "active"
	case TierIdle:
		return "idle"
	case TierDormant:
		return "dormant"
	default:
		return "unknown"
	}
}

// Sensible defaults for ~5000-SME-tenant PoPs where most tenants are
// dormant trials. A dormant tenant is still reconciled at least once
// per (sweep interval × DefaultDormantEvery): at the IdP sync default
// of 5m that is ~8.3h, an acceptable staleness bound for a tenant that
// has shown no activity in over two weeks.
const (
	DefaultIdleAfter    = 24 * time.Hour
	DefaultDormantAfter = 14 * 24 * time.Hour
	DefaultIdleEvery    = 10
	DefaultDormantEvery = 100
)

// Classifier maps a tenant's last-active timestamp to a Tier given the
// current time.
type Classifier struct {
	// IdleAfter is the age past which a tenant is no longer active.
	IdleAfter time.Duration
	// DormantAfter is the age past which a tenant is dormant. Must be
	// greater than IdleAfter.
	DormantAfter time.Duration
}

// Classify buckets a tenant. A nil lastActive (never seen) is dormant.
//
// Fail-safe: an unconfigured or contradictory classifier (IdleAfter
// <= 0, or DormantAfter <= IdleAfter) treats every tenant as active.
// The cost of a misconfiguration is then doing *more* work, never
// silently starving a security-relevant sweep by mis-bucketing live
// tenants as dormant.
func (c Classifier) Classify(now time.Time, lastActive *time.Time) Tier {
	if c.IdleAfter <= 0 || c.DormantAfter <= c.IdleAfter {
		return TierActive
	}
	if lastActive == nil {
		return TierDormant
	}
	age := now.Sub(*lastActive)
	switch {
	case age < c.IdleAfter:
		return TierActive
	case age < c.DormantAfter:
		return TierIdle
	default:
		return TierDormant
	}
}

// SweepPlanner decides, per sweep cycle, which tenants a periodic
// per-tenant sweep should actually process. It is a pure value: the
// same inputs always yield the same plan, so it is trivially testable
// and safe to share across goroutines.
type SweepPlanner struct {
	Classifier
	// IdleEvery processes idle-tier tenants every Nth cycle. Values
	// <= 1 mean "every cycle".
	IdleEvery int64
	// DormantEvery processes dormant-tier tenants every Nth cycle.
	// Values <= 1 mean "every cycle".
	DormantEvery int64
}

// DefaultPlanner returns a SweepPlanner pre-filled with the package
// defaults.
func DefaultPlanner() SweepPlanner {
	return SweepPlanner{
		Classifier:   Classifier{IdleAfter: DefaultIdleAfter, DormantAfter: DefaultDormantAfter},
		IdleEvery:    DefaultIdleEvery,
		DormantEvery: DefaultDormantEvery,
	}
}

// ShouldVisit reports whether a tenant in `tier` is due on `cycle`
// (0-based). Cycle 0 visits every tier, so a freshly-started sweep
// always does one full reconcile before settling into the tiered
// cadence. Active tenants are always visited.
func (p SweepPlanner) ShouldVisit(tier Tier, cycle int64) bool {
	switch tier {
	case TierIdle:
		return dueThisCycle(cycle, p.IdleEvery)
	case TierDormant:
		return dueThisCycle(cycle, p.DormantEvery)
	default:
		// TierActive (and any unknown tier, defensively) is always due.
		return true
	}
}

// dueThisCycle implements the "every Nth cycle" gate. A non-positive or
// unit period means every cycle. Cycle 0 is always due (full startup
// sweep). A negative cycle is treated as due (defensive — callers pass
// a monotonic counter, but never silently skip).
func dueThisCycle(cycle, every int64) bool {
	if every <= 1 || cycle <= 0 {
		return true
	}
	return cycle%every == 0
}

// Plan returns the ids of the tenants a sweep should process on the
// given cycle, preserving the input order. The caller feeds it the
// cheap (id, last_active_at) projection it already loads once per cycle
// (repository.TenantRepository.ListTenantActivity) — Plan does no I/O.
func (p SweepPlanner) Plan(now time.Time, cycle int64, acts []repository.TenantActivity) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(acts))
	for _, a := range acts {
		if p.ShouldVisit(p.Classify(now, a.LastActiveAt), cycle) {
			out = append(out, a.ID)
		}
	}
	return out
}

// PlanSummary is a per-cycle breakdown for observability: how many
// tenants fell in each tier and how many were actually visited. It
// lets the sweep log a one-line "skipped 4 500 dormant tenants this
// cycle" without recomputing.
type PlanSummary struct {
	Cycle   int64
	Active  int
	Idle    int
	Dormant int
	Visited int
	Total   int
	Skipped int
}

// Summarize classifies and tallies without materialising the id slice,
// for cheap logging/metrics. Visited/Skipped honour the same cadence
// rules as Plan.
func (p SweepPlanner) Summarize(now time.Time, cycle int64, acts []repository.TenantActivity) PlanSummary {
	s := PlanSummary{Cycle: cycle, Total: len(acts)}
	for _, a := range acts {
		tier := p.Classify(now, a.LastActiveAt)
		switch tier {
		case TierActive:
			s.Active++
		case TierIdle:
			s.Idle++
		case TierDormant:
			s.Dormant++
		}
		if p.ShouldVisit(tier, cycle) {
			s.Visited++
		}
	}
	s.Skipped = s.Total - s.Visited
	return s
}
