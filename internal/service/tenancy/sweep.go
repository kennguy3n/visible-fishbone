package tenancy

import (
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SweepObserver receives, once per completed sweep cycle, the per-tier
// count of tenants a job visited and skipped. It is the seam through
// which TieredSweep exports the sweep_tenants_visited / _skipped metrics
// without the tenancy package importing internal/metrics — keeping
// tenancy a pure, dependency-light domain helper and avoiding an import
// cycle. A nil observer disables emission. Implementations must be safe
// for concurrent use (a Prometheus *CounterVec already is).
type SweepObserver interface {
	ObserveSweep(job string, tier Tier, visited, skipped int)
}

// TieredSweep is shared middleware that lets any periodic per-tenant job
// adopt activity-tiered cadence at a single integration point. It pairs
// a monotonic 0-based cycle counter with a SweepPlanner and (optionally)
// a SweepObserver, so a job only has to (1) Begin a cycle, (2) ask
// whether each tenant is due, and (3) Finish to publish per-tier
// observability — instead of hand-rolling its own atomic cycle counter
// and planner plumbing, as the IdP-sync and CASB reconcile loops each
// did before this helper existed.
//
// Fail-safe posture is inherited wholesale from SweepPlanner/Classifier:
// a zero or contradictory planner classifies every tenant as active
// (more work, never less), and cycle 0 is always a full sweep, so
// adopting the helper can never silently starve a security-relevant
// reconcile or delay a tenant's first pass.
//
// A *TieredSweep is safe for concurrent use; the cycle counter is
// atomic. Begin allocates a per-pass *SweepCycle, so overlapping passes
// (tests, or a tick that races a leadership re-acquisition) keep
// independent tallies.
type TieredSweep struct {
	job     string
	planner SweepPlanner
	obs     SweepObserver
	// cycle is the monotonic 0-based sweep counter the planner's cadence
	// gate consumes. The first pass is cycle 0 (a guaranteed full sweep).
	cycle atomic.Uint64
}

// NewTieredSweep builds a TieredSweep for a named job. job is the value
// of the {job} metric label, so keep it stable and low-cardinality
// (e.g. "idp_directory_sync"). obs may be nil to disable metric
// emission; the cycle counter and planner gating still work.
func NewTieredSweep(job string, planner SweepPlanner, obs SweepObserver) *TieredSweep {
	return &TieredSweep{job: job, planner: planner, obs: obs}
}

// Job returns the metric-label job name.
func (t *TieredSweep) Job() string { return t.job }

// Planner returns the underlying SweepPlanner for callers that need the
// raw classifier (e.g. to report the configured cadence). The planner is
// a value, so the returned copy cannot mutate the sweep's gating.
func (t *TieredSweep) Planner() SweepPlanner { return t.planner }

// SweepCycle is one pass of a TieredSweep. It carries the 0-based cycle
// number, the wall-clock snapshot used for tier classification, and the
// per-tier visited/skipped tallies accumulated as the job asks Due/Visit.
// A SweepCycle is NOT safe for concurrent use within a single pass — one
// pass runs on one goroutine (the leader's sweep loop).
type SweepCycle struct {
	sweep *TieredSweep
	// Cycle is the 0-based pass number this SweepCycle gates against.
	Cycle int64
	now   time.Time
	// visited/skipped are indexed by tierIndex (active, idle, dormant).
	visited [3]int
	skipped [3]int
}

// Begin starts a new sweep pass: it advances the monotonic 0-based cycle
// counter (the first pass is cycle 0, a guaranteed full sweep) and
// snapshots `now` for tier classification. Pass the job's own clock so
// tests stay deterministic. Call Finish on the returned cycle once the
// pass completes to publish the tallies.
func (t *TieredSweep) Begin(now time.Time) *SweepCycle {
	// 0-based monotonic cycle: Add returns the post-increment value, so
	// the first pass yields 1-1 == 0.
	cycle := int64(t.cycle.Add(1) - 1)
	return &SweepCycle{sweep: t, Cycle: cycle, now: now}
}

// tierIndex maps a Tier to its tally slot, clamping any unknown tier to
// active — consistent with the planner's fail-safe "treat as active"
// posture, so a future tier can never silently vanish from the metric.
func tierIndex(tier Tier) int {
	switch tier {
	case TierIdle:
		return 1
	case TierDormant:
		return 2
	default:
		return 0
	}
}

// sweepTierOrder lists the tiers in tally-slot order so Finish can emit
// them without re-deriving the mapping (and without allocating per call).
var sweepTierOrder = [3]Tier{TierActive, TierIdle, TierDormant}

// Visit reports whether a tenant whose data plane last reported activity
// at `lastActive` is due this cycle, recording the decision in the
// per-tier tally. It is the streaming primitive for jobs that page
// tenants (e.g. the CASB reconcile sweep) rather than pre-loading the
// activity projection. A nil lastActive means "never seen" (dormant).
func (c *SweepCycle) Visit(lastActive *time.Time) bool {
	return c.visitTier(c.sweep.planner.Classify(c.now, lastActive))
}

func (c *SweepCycle) visitTier(tier Tier) bool {
	idx := tierIndex(tier)
	if c.sweep.planner.ShouldVisit(tier, c.Cycle) {
		c.visited[idx]++
		return true
	}
	c.skipped[idx]++
	return false
}

// Due is the bulk primitive for jobs that load the cheap
// (id, last_active_at) projection once per cycle (e.g. IdP directory
// sync): it returns the ids due this cycle, preserving input order, and
// tallies every tenant by tier as a side effect.
func (c *SweepCycle) Due(acts []repository.TenantActivity) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(acts))
	for _, a := range acts {
		if c.Visit(a.LastActiveAt) {
			out = append(out, a.ID)
		}
	}
	return out
}

// Summary returns the accumulated per-cycle breakdown for cheap logging.
// It mirrors SweepPlanner.Summarize so callers can log a consistent
// shape whether they sweep in bulk or streaming.
func (c *SweepCycle) Summary() PlanSummary {
	s := PlanSummary{
		Cycle:   c.Cycle,
		Active:  c.visited[0] + c.skipped[0],
		Idle:    c.visited[1] + c.skipped[1],
		Dormant: c.visited[2] + c.skipped[2],
		Visited: c.visited[0] + c.visited[1] + c.visited[2],
	}
	s.Total = s.Active + s.Idle + s.Dormant
	s.Skipped = s.Total - s.Visited
	return s
}

// Finish publishes the accumulated per-tier tallies to the observer (if
// any). Call it exactly once at the end of a pass; after Finish the
// SweepCycle must not be reused for another Begin/Visit/Due pass and a
// fresh one should be obtained from Begin. Reading the tallies after
// Finish is safe, though — Summary is read-only over the same unchanged
// fields, so the common "Finish then Summary for a debug log" pattern is
// well-defined. Tiers with no tenants this cycle are not emitted, so an
// idle metric series never appears for a job that has no tenants in that
// tier.
func (c *SweepCycle) Finish() {
	if c.sweep.obs == nil {
		return
	}
	for idx, tier := range sweepTierOrder {
		if c.visited[idx] == 0 && c.skipped[idx] == 0 {
			continue
		}
		c.sweep.obs.ObserveSweep(c.sweep.job, tier, c.visited[idx], c.skipped[idx])
	}
}
