package policy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// canaryFixture wires a minimal policy.Service + memory rollout
// repo + CanaryService, returning the seeded tenant ID and graph
// so each test can branch into its own scenario without
// duplicating the boring setup.
type canaryFixture struct {
	tenantID uuid.UUID
	graph    repository.PolicyGraph
	policy   *Service
	canary   *CanaryService
	rollouts repository.PolicyRolloutRepository
	policyR  repository.PolicyRepository
}

func newCanaryFixture(t *testing.T) *canaryFixture {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := NewKeyService(keyRepo, auditRepo)
	svc := New(policyRepo, auditRepo, keys)

	raw, _ := json.Marshal(map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
		},
	})
	graph, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw)
	if err != nil {
		t.Fatalf("put graph: %v", err)
	}

	rollouts := memory.NewPolicyRolloutRepository(store)
	canary, err := NewCanaryService(svc, rollouts)
	if err != nil {
		t.Fatalf("new canary: %v", err)
	}
	return &canaryFixture{
		tenantID: tnt.ID,
		graph:    graph,
		policy:   svc,
		canary:   canary,
		rollouts: rollouts,
		policyR:  policyRepo,
	}
}

func TestCanary_StartDryRun_PersistsAndCompiles(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)

	rollout, dr, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{
		ProposedGraph: f.graph.Graph,
		Notes:         "first rollout",
	})
	if err != nil {
		t.Fatalf("start dry run: %v", err)
	}
	if rollout.Stage != repository.PolicyRolloutStageDryRun {
		t.Fatalf("stage = %s, want dry_run", rollout.Stage)
	}
	if rollout.CanaryPercent != 0 {
		t.Fatalf("canary_percent = %d, want 0", rollout.CanaryPercent)
	}
	// StartDryRun now owns draft persistence, so rollout.GraphID
	// points at a freshly minted draft row — not f.graph (the
	// previously-live seed).
	if rollout.GraphID == uuid.Nil || rollout.GraphID == f.graph.ID {
		t.Fatalf("graph_id = %s, want a freshly minted draft id", rollout.GraphID)
	}
	persisted, err := f.policyR.GetGraph(context.Background(), f.tenantID, rollout.GraphID)
	if err != nil {
		t.Fatalf("get auto-minted draft: %v", err)
	}
	if !persisted.IsDraft {
		t.Fatalf("auto-minted graph.IsDraft = false, want true")
	}
	if dr.SimulationID == uuid.Nil {
		t.Fatalf("dry-run simulation id missing")
	}
	if dr.Subject == "" || len(dr.Bundles) == 0 {
		t.Fatalf("dry-run result not populated: subj=%q bundles=%d", dr.Subject, len(dr.Bundles))
	}
}

func TestCanary_StartDryRun_RejectsActiveRollout(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)

	if _, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph}); err != nil {
		t.Fatalf("first start: %v", err)
	}
	_, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph})
	if !errors.Is(err, ErrCanaryRolloutActive) {
		t.Fatalf("second start err = %v, want ErrCanaryRolloutActive", err)
	}
}

func TestCanary_StartDryRun_AllowsAfterRollback(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)

	first, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph})
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := f.canary.Rollback(context.Background(), f.tenantID, first.ID, nil, "abort"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph}); err != nil {
		t.Fatalf("second start after rollback: %v", err)
	}
}

func TestCanary_Advance_StateMachine(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)

	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// dry_run -> canary requires non-zero percent
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageCanary,
	}); !errors.Is(err, ErrCanaryPercent) {
		t.Fatalf("zero-percent canary: err = %v, want ErrCanaryPercent", err)
	}

	r2, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage:     repository.PolicyRolloutStageCanary,
		CanaryPercent: 25,
		Notes:         "promoting to 25%",
	})
	if err != nil {
		t.Fatalf("dry_run -> canary: %v", err)
	}
	if r2.Stage != repository.PolicyRolloutStageCanary || r2.CanaryPercent != 25 {
		t.Fatalf("stage/percent wrong: %s/%d", r2.Stage, r2.CanaryPercent)
	}

	r3, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageFull,
	})
	if err != nil {
		t.Fatalf("canary -> full: %v", err)
	}
	if r3.Stage != repository.PolicyRolloutStageFull {
		t.Fatalf("full stage wrong: %s", r3.Stage)
	}

	r4, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageCompleted,
	})
	if err != nil {
		t.Fatalf("full -> completed: %v", err)
	}
	if r4.Stage != repository.PolicyRolloutStageCompleted {
		t.Fatalf("completed stage wrong: %s", r4.Stage)
	}

	// Terminal: further Advance is rejected.
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageRolledBack,
	}); err == nil {
		t.Fatalf("expected reject for completed -> rolled_back")
	}
}

func TestCanary_Advance_IllegalTransitions(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// dry_run -> completed (must go through full first).
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageCompleted,
	}); err == nil {
		t.Fatalf("expected reject for dry_run -> completed")
	}
}

func TestCanary_GetActive_ReturnsNonTerminalOnly(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)

	r1, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{ProposedGraph: f.graph.Graph})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	got, err := f.canary.GetActive(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if got.ID != r1.ID {
		t.Fatalf("get active id = %s, want %s", got.ID, r1.ID)
	}
	if _, err := f.canary.Rollback(context.Background(), f.tenantID, r1.ID, nil, "abort"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := f.canary.GetActive(context.Background(), f.tenantID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("after rollback err = %v, want ErrNotFound", err)
	}
}

func TestIsCanaryDevice_Deterministic(t *testing.T) {
	t.Parallel()
	rolloutID := uuid.New()
	deviceID := uuid.New()
	a := IsCanaryDevice(rolloutID, deviceID, 50)
	b := IsCanaryDevice(rolloutID, deviceID, 50)
	if a != b {
		t.Fatalf("non-deterministic: %v vs %v", a, b)
	}
}

func TestIsCanaryDevice_BoundaryPercents(t *testing.T) {
	t.Parallel()
	rolloutID := uuid.New()
	for i := 0; i < 100; i++ {
		deviceID := uuid.New()
		if IsCanaryDevice(rolloutID, deviceID, 0) {
			t.Fatalf("percent 0 should never select")
		}
		if !IsCanaryDevice(rolloutID, deviceID, 100) {
			t.Fatalf("percent 100 should always select")
		}
		// Out-of-range values clamp.
		if IsCanaryDevice(rolloutID, deviceID, -10) {
			t.Fatalf("negative percent should clamp to 0")
		}
		if !IsCanaryDevice(rolloutID, deviceID, 250) {
			t.Fatalf("percent > 100 should clamp to 100")
		}
	}
}

func TestIsCanaryDevice_ApproximatesTargetRate(t *testing.T) {
	t.Parallel()
	// With a uniform hash, the fraction of devices selected
	// should approach canary_percent / 100 for large N.
	rolloutID := uuid.New()
	const (
		N      = 5000
		target = 30
		slack  = 5 // ±5 percentage points
	)
	in := 0
	for i := 0; i < N; i++ {
		if IsCanaryDevice(rolloutID, uuid.New(), target) {
			in++
		}
	}
	actual := in * 100 / N
	if actual < target-slack || actual > target+slack {
		t.Fatalf("selection rate %d%% outside %d±%d%%", actual, target, slack)
	}
}

// detUUID deterministically derives a well-spread UUID from a
// seed via splitmix64. Tests get pseudo-random-looking IDs that
// are byte-identical on every run, so statistical assertions over
// them are reproducible and can never flake.
func detUUID(seed uint64) uuid.UUID {
	x := seed
	next := func() uint64 {
		x += 0x9E3779B97F4A7C15
		z := x
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	var u uuid.UUID
	binary.LittleEndian.PutUint64(u[0:8], next())
	binary.LittleEndian.PutUint64(u[8:16], next())
	return u
}

func TestIsCanaryDevice_RolloutSaltsAreIndependent(t *testing.T) {
	t.Parallel()
	// Two distinct rollouts at the same percent must sample
	// independently: a device's membership in rollout A tells you
	// nothing about its membership in rollout B, so the overlap of
	// two 50% cohorts is Binomial(N, 0.25) — mean N/4, σ≈13.7 at
	// N=1000. A weakly-salted hash (the old fnv1a(salt||id)%100)
	// leaves the two cohorts correlated for unlucky rollout pairs,
	// throwing heavy tails; this asserts every pair stays inside a
	// tight band AND the mean across many pairs is ~25%.
	//
	// Device and rollout IDs are seed-derived (detUUID), so the
	// result is fully deterministic and can never flake.
	const (
		N     = 1000
		pairs = 200
		// 6σ band around the Binomial(1000,0.25) mean of 250
		// (σ≈13.69 -> 6σ≈82). True independence stays well inside.
		lo = 168
		hi = 332
	)
	deviceIDs := make([]uuid.UUID, N)
	for i := range deviceIDs {
		deviceIDs[i] = detUUID(uint64(i))
	}
	totalOverlap := 0
	for p := 0; p < pairs; p++ {
		rollA := detUUID(0x1_0000_0000 + uint64(2*p))
		rollB := detUUID(0x1_0000_0000 + uint64(2*p+1))
		overlap := 0
		for _, d := range deviceIDs {
			if IsCanaryDevice(rollA, d, 50) && IsCanaryDevice(rollB, d, 50) {
				overlap++
			}
		}
		totalOverlap += overlap
		if overlap < lo || overlap > hi {
			t.Errorf("pair %d overlap %d outside 6σ independence band [%d,%d] (rollouts not independent?)", p, overlap, lo, hi)
		}
	}
	mean := float64(totalOverlap) / float64(pairs)
	if mean < 0.24*N || mean > 0.26*N {
		t.Fatalf("mean overlap %.1f over %d pairs not ~25%% of %d", mean, pairs, N)
	}
}

func TestIsCanaryDevice_DeterministicAndMonotonic(t *testing.T) {
	t.Parallel()
	// Fixed IDs pin the contract without any statistics, so this
	// case can never flake: the 0/100 edges are absolute, repeated
	// calls are stable, and once a device joins the cohort at some
	// percent it stays in for every higher percent (its bucket is
	// fixed, so membership is monotonic in canaryPercent).
	roll := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	dev := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	if IsCanaryDevice(roll, dev, 0) {
		t.Error("0% must exclude every device")
	}
	if !IsCanaryDevice(roll, dev, 100) {
		t.Error("100% must include every device")
	}
	want := IsCanaryDevice(roll, dev, 50)
	for i := 0; i < 5; i++ {
		if IsCanaryDevice(roll, dev, 50) != want {
			t.Fatal("verdict is not deterministic across calls")
		}
	}
	joinedAt := 0
	for p := 1; p <= 100; p++ {
		in := IsCanaryDevice(roll, dev, p)
		switch {
		case in && joinedAt == 0:
			joinedAt = p
		case !in && joinedAt != 0:
			t.Fatalf("device left cohort at percent %d after joining at %d (non-monotonic)", p, joinedAt)
		}
	}
	if joinedAt == 0 {
		t.Fatal("device never joined cohort across 1..100")
	}
}

func TestCanary_Advance_NotFound(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	_, err := f.canary.Advance(context.Background(), f.tenantID, uuid.New(), AdvanceInput{
		NextStage: repository.PolicyRolloutStageFull,
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestCanary_StartDryRun_RequiresInputs(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	if _, _, err := f.canary.StartDryRun(context.Background(), uuid.Nil, StartDryRunInput{ProposedGraph: f.graph.Graph}); err == nil {
		t.Fatalf("zero tenant_id should fail")
	}
	if _, _, err := f.canary.StartDryRun(context.Background(), f.tenantID, StartDryRunInput{}); err == nil {
		t.Fatalf("missing proposed graph should fail")
	}
}

func TestNewCanaryService_RejectsNilDeps(t *testing.T) {
	t.Parallel()
	if _, err := NewCanaryService(nil, nil); err == nil {
		t.Fatalf("expected error for nil deps")
	}
	store := memory.NewStore()
	rollouts := memory.NewPolicyRolloutRepository(store)
	if _, err := NewCanaryService(nil, rollouts); err == nil {
		t.Fatalf("expected error for nil policy svc")
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := NewKeyService(keyRepo, auditRepo)
	svc := New(policyRepo, auditRepo, keys)
	if _, err := NewCanaryService(svc, nil); err == nil {
		t.Fatalf("expected error for nil rollouts repo")
	}
}

func TestCanary_DeterministicTimestamps_ViaStoreClock(t *testing.T) {
	t.Parallel()
	// CreatedAt / UpdatedAt are stamped by the repository (not
	// the service), so the test pins the store clock. The
	// service-level WithCanaryClock pins the audit-log clock and
	// any internal time math the service layer adds in future.
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	store := memory.NewStore()
	store.SetClock(func() time.Time { return fixed })
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := NewKeyService(keyRepo, auditRepo)
	svc := New(policyRepo, auditRepo, keys)
	raw, _ := json.Marshal(map[string]any{"default_action": "deny"})
	graph, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw)
	if err != nil {
		t.Fatalf("put graph: %v", err)
	}
	rollouts := memory.NewPolicyRolloutRepository(store)
	canary, err := NewCanaryService(svc, rollouts, WithCanaryClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("new canary: %v", err)
	}
	got, _, err := canary.StartDryRun(context.Background(), tnt.ID, StartDryRunInput{ProposedGraph: graph.Graph})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !got.CreatedAt.Equal(fixed) {
		t.Fatalf("created_at = %v, want %v", got.CreatedAt, fixed)
	}
}

// TestCanary_Advance_PromotesDraftOnFirstEnforcingStage checks
// the draft -> live transition: the proposed graph starts out
// as a draft (so /policy/compile keeps serving the previously
// live graph during dry-run), and only flips to live on the
// dry_run -> canary transition.
func TestCanary_Advance_PromotesDraftOnFirstEnforcingStage(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	// Hand StartDryRun the raw proposed graph JSON. StartDryRun
	// owns the draft persistence (see ANALYSIS_0004 fix), so
	// the rollout.GraphID returned below points at the auto-
	// minted draft row we then expect Advance to promote.
	rawProp, _ := json.Marshal(map[string]any{
		"default_action": "allow",
		"rules": []map[string]any{
			{"id": "ngfw-allow", "domain": "ngfw", "verb": "allow"},
		},
	})

	// Pre-start: live current is the seeded f.graph.
	if cur, _ := f.policyR.GetCurrentGraph(context.Background(), f.tenantID); cur.ID != f.graph.ID {
		t.Fatalf("pre-start current = %s, want %s", cur.ID, f.graph.ID)
	}

	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID,
		StartDryRunInput{ProposedGraph: rawProp, PreviousGraphID: f.graph.ID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	draftID := rollout.GraphID

	// The auto-minted draft must actually be persisted as a draft.
	draft, err := f.policyR.GetGraph(context.Background(), f.tenantID, draftID)
	if err != nil {
		t.Fatalf("get auto-minted draft: %v", err)
	}
	if !draft.IsDraft {
		t.Fatalf("draft.IsDraft = false, want true")
	}

	// During dry-run, live MUST stay the previous graph.
	if cur, _ := f.policyR.GetCurrentGraph(context.Background(), f.tenantID); cur.ID != f.graph.ID {
		t.Fatalf("during dry-run current = %s, want previous %s", cur.ID, f.graph.ID)
	}

	// dry_run -> canary @ 50% triggers promotion.
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageCanary, CanaryPercent: 50,
	}); err != nil {
		t.Fatalf("advance to canary: %v", err)
	}
	cur, err := f.policyR.GetCurrentGraph(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("post-advance current: %v", err)
	}
	if cur.ID != draftID {
		t.Fatalf("post-advance current = %s, want promoted draft %s", cur.ID, draftID)
	}
}

// TestCanary_Rollback_LeavesDraftUnpromoted verifies the
// rollback path does NOT flip is_draft. The draft row stays
// queryable for audit but does not affect the live policy.
func TestCanary_Rollback_LeavesDraftUnpromoted(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	rawProp, _ := json.Marshal(map[string]any{"default_action": "allow"})
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID,
		StartDryRunInput{ProposedGraph: rawProp, PreviousGraphID: f.graph.ID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	draftID := rollout.GraphID
	if _, err := f.canary.Rollback(context.Background(), f.tenantID, rollout.ID, nil, "abort"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, err := f.policyR.GetGraph(context.Background(), f.tenantID, draftID)
	if err != nil {
		t.Fatalf("get draft after rollback: %v", err)
	}
	if !got.IsDraft {
		t.Fatalf("draft promoted by rollback — want IsDraft=true")
	}
	// And the live current is still the previous graph.
	cur, _ := f.policyR.GetCurrentGraph(context.Background(), f.tenantID)
	if cur.ID != f.graph.ID {
		t.Fatalf("post-rollback current = %s, want previous %s", cur.ID, f.graph.ID)
	}
}

// TestCanary_RollbackFromCanary_DemotesGraph pins the round-3
// BUG_0001 fix: rolling back a rollout that has already been
// promoted past dry_run must flip is_draft back to true on the
// proposed graph so the previous live graph again wins
// GetCurrentGraph. Without the fix the just-rolled-back
// proposal would silently keep serving as the live policy
// (the proposal would still have the higher version and would
// still have is_draft = false because the dry_run -> canary
// edge promoted it).
func TestCanary_RollbackFromCanary_DemotesGraph(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	rawProp, _ := json.Marshal(map[string]any{"default_action": "allow"})
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID,
		StartDryRunInput{ProposedGraph: rawProp, PreviousGraphID: f.graph.ID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	draftID := rollout.GraphID
	// dry_run -> canary promotes the draft.
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID,
		AdvanceInput{NextStage: repository.PolicyRolloutStageCanary, CanaryPercent: 25}); err != nil {
		t.Fatalf("advance to canary: %v", err)
	}
	promoted, err := f.policyR.GetGraph(context.Background(), f.tenantID, draftID)
	if err != nil {
		t.Fatalf("get after promote: %v", err)
	}
	if promoted.IsDraft {
		t.Fatalf("promoted graph still IsDraft — promotion path regressed")
	}
	cur, err := f.policyR.GetCurrentGraph(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("get current after promote: %v", err)
	}
	if cur.ID != draftID {
		t.Fatalf("post-promote current = %s, want proposed %s", cur.ID, draftID)
	}
	// Now rollback. The proposal must demote back to draft
	// so the previous graph again wins GetCurrentGraph.
	if _, err := f.canary.Rollback(context.Background(), f.tenantID, rollout.ID, nil, "abort"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	demoted, err := f.policyR.GetGraph(context.Background(), f.tenantID, draftID)
	if err != nil {
		t.Fatalf("get after rollback: %v", err)
	}
	if !demoted.IsDraft {
		t.Fatalf("rolled-back proposal still has IsDraft = false — BUG_0001 regressed")
	}
	cur, err = f.policyR.GetCurrentGraph(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("get current after rollback: %v", err)
	}
	if cur.ID != f.graph.ID {
		t.Fatalf("post-rollback current = %s, want previous %s — BUG_0001 regressed",
			cur.ID, f.graph.ID)
	}
}

// TestCanary_RollbackFromFull_DemotesGraph is the same pin
// as TestCanary_RollbackFromCanary_DemotesGraph but for the
// dry_run -> full -> rolled_back path. The dry_run -> full
// edge also promotes the proposal; the rollback must demote
// it the same way the canary -> rolled_back path does.
func TestCanary_RollbackFromFull_DemotesGraph(t *testing.T) {
	t.Parallel()
	f := newCanaryFixture(t)
	rawProp, _ := json.Marshal(map[string]any{"default_action": "deny"})
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenantID,
		StartDryRunInput{ProposedGraph: rawProp, PreviousGraphID: f.graph.ID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	draftID := rollout.GraphID
	if _, err := f.canary.Advance(context.Background(), f.tenantID, rollout.ID,
		AdvanceInput{NextStage: repository.PolicyRolloutStageFull}); err != nil {
		t.Fatalf("advance to full: %v", err)
	}
	if _, err := f.canary.Rollback(context.Background(), f.tenantID, rollout.ID, nil, "abort"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	demoted, err := f.policyR.GetGraph(context.Background(), f.tenantID, draftID)
	if err != nil {
		t.Fatalf("get after rollback: %v", err)
	}
	if !demoted.IsDraft {
		t.Fatalf("rolled-back proposal still has IsDraft = false (from full)")
	}
	cur, err := f.policyR.GetCurrentGraph(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("get current after rollback: %v", err)
	}
	if cur.ID != f.graph.ID {
		t.Fatalf("post-rollback current = %s, want previous %s", cur.ID, f.graph.ID)
	}
}

// TestErrCanaryPercent_MessageMatchesValidator pins the round-4
// Devin Review fix: the error message previously announced the
// valid range as [0, 100] but the validator rejected 0, so a
// client passing canary_percent=0 was told 0 was valid (per the
// message) and retried with the same value, getting stuck. The
// long-term fix changes the message to match what the validator
// actually accepts: [1, 100].
//
// Pinning the literal message keeps the contract honest — future
// edits to the validator must edit the message in lockstep.
func TestErrCanaryPercent_MessageMatchesValidator(t *testing.T) {
	t.Parallel()
	want := "policy: canary percent must be in [1, 100]"
	if got := ErrCanaryPercent.Error(); got != want {
		t.Fatalf("ErrCanaryPercent.Error() = %q, want %q\n"+
			"keep the message in lockstep with the (0, 100] validator at canary.go:290",
			got, want)
	}
}
