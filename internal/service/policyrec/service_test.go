package policyrec

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// memSource is an in-memory policy.TelemetrySource returning a fixed
// envelope slice filtered by the requested classes — the same contract
// the production ClickHouse Reader honours.
type memSource struct{ envs []schema.Envelope }

func (s *memSource) ListFlowEvents(ctx context.Context, tid uuid.UUID, since, until time.Time, limit int) ([]schema.Envelope, error) {
	return s.ListEvents(ctx, tid, []schema.EventClass{schema.EventClassFlow}, since, until, limit)
}

func (s *memSource) ListEvents(_ context.Context, _ uuid.UUID, classes []schema.EventClass, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	wanted := map[schema.EventClass]struct{}{}
	for _, c := range classes {
		wanted[c] = struct{}{}
	}
	out := make([]schema.Envelope, 0, len(s.envs))
	for _, e := range s.envs {
		if _, ok := wanted[e.EventClass]; ok || len(wanted) == 0 {
			out = append(out, e)
		}
	}
	return out, nil
}

// fakeGraphs is a fake PolicyGraphProvider that records the draft graph
// staged by Apply and can pretend the tenant has no live policy yet.
type fakeGraphs struct {
	current *repository.PolicyGraph
	putRaw  json.RawMessage
	putErr  error
}

func (f *fakeGraphs) GetCurrentGraph(_ context.Context, _ uuid.UUID) (repository.PolicyGraph, error) {
	if f.current == nil {
		return repository.PolicyGraph{}, repository.ErrNotFound
	}
	return *f.current, nil
}

func (f *fakeGraphs) PutDraftGraph(_ context.Context, _ uuid.UUID, _ *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	if f.putErr != nil {
		return repository.PolicyGraph{}, f.putErr
	}
	f.putRaw = raw
	return repository.PolicyGraph{ID: uuid.New(), Graph: raw, IsDraft: true}, nil
}

func newTestService(t *testing.T, envs []schema.Envelope, graphs *fakeGraphs) (*Service, repository.PolicyRecommendationRepository) {
	t.Helper()
	repo := memory.NewPolicyRecommendationRepository(memory.NewStore())
	return New(repo, &memSource{envs: envs}, graphs, nil, nil), repo
}

func TestService_Generate_FullCoverageNoCurrentPolicy(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	envs := []schema.Envelope{
		flowEnv(t, "10.0.0.5", "tcp", 443, schema.VerdictAllow),
		flowEnv(t, "10.0.0.9", "tcp", 443, schema.VerdictAllow),
		dnsEnv(t, "api.example.com", schema.VerdictAllow),
		httpEnv(t, "portal.example.com", "GET", schema.VerdictAllow),
		flowEnv(t, "203.0.113.7", "tcp", 23, schema.VerdictDeny), // blocked, not re-allowed
	}
	svc, _ := newTestService(t, envs, &fakeGraphs{})

	rec, err := svc.Generate(context.Background(), tenantID, nil, GenerateRequest{
		Since: time.Unix(0, 0), Until: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rec.Status != repository.PolicyRecommendationStatusPending {
		t.Fatalf("status = %q, want pending", rec.Status)
	}
	// 3 distinct permitted groups: tcp/443->10.0.0.0/24, dns, http.
	if rec.RuleCount != 3 {
		t.Fatalf("rule count = %d, want 3", rec.RuleCount)
	}

	var summary RecommendationSummary
	if err := json.Unmarshal(rec.Summary, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	// The candidate is synthesized from exactly this traffic, so it must
	// preserve all of it — coverage is 1.0 and nothing is newly denied.
	if summary.Coverage.Coverage != 1.0 {
		t.Fatalf("coverage = %v, want 1.0; newly denied = %+v", summary.Coverage.Coverage, summary.Coverage.NewlyDeniedSamples)
	}
	if summary.Coverage.NewlyDenied != 0 {
		t.Fatalf("newly denied = %d, want 0", summary.Coverage.NewlyDenied)
	}
	// Against an empty (default-deny) current policy, the candidate flips
	// the permitted traffic from deny -> allow, so impact.Changed counts
	// the 4 permitted envelopes.
	if summary.Impact.Changed != 4 {
		t.Fatalf("impact changed = %d, want 4", summary.Impact.Changed)
	}
}

func TestService_Generate_NewlyDeniedWhenTruncated(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	envs := []schema.Envelope{
		dnsEnv(t, "keep.example.com", schema.VerdictAllow),
		dnsEnv(t, "keep.example.com", schema.VerdictAllow),
		dnsEnv(t, "dropped.example.com", schema.VerdictAllow),
	}
	svc, _ := newTestService(t, envs, &fakeGraphs{})

	rec, err := svc.Generate(context.Background(), tenantID, nil, GenerateRequest{
		Since: time.Unix(0, 0), Until: time.Unix(1000, 0),
		Options: SynthesisOptions{MaxRules: 1},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var summary RecommendationSummary
	if err := json.Unmarshal(rec.Summary, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if !summary.Synthesis.Truncated {
		t.Fatal("expected synthesis to be truncated")
	}
	// The dropped single observation surfaces honestly as newly denied.
	if summary.Coverage.NewlyDenied != 1 {
		t.Fatalf("newly denied = %d, want 1", summary.Coverage.NewlyDenied)
	}
	if len(summary.Coverage.NewlyDeniedSamples) != 1 ||
		summary.Coverage.NewlyDeniedSamples[0].Descriptor != "dropped.example.com" {
		t.Fatalf("newly denied samples = %+v", summary.Coverage.NewlyDeniedSamples)
	}
}

func TestService_ApplyStagesDraftAndMarksApplied(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	actor := uuid.New()
	graphs := &fakeGraphs{}
	envs := []schema.Envelope{dnsEnv(t, "api.example.com", schema.VerdictAllow)}
	svc, _ := newTestService(t, envs, graphs)

	rec, err := svc.Generate(context.Background(), tenantID, &actor, GenerateRequest{
		Since: time.Unix(0, 0), Until: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	applied, draft, err := svc.Apply(context.Background(), tenantID, &actor, rec.ID)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.Status != repository.PolicyRecommendationStatusApplied {
		t.Fatalf("status = %q, want applied", applied.Status)
	}
	if applied.AppliedGraphID == nil || *applied.AppliedGraphID != draft.ID {
		t.Fatalf("applied graph id not recorded: %+v", applied.AppliedGraphID)
	}
	if !draft.IsDraft {
		t.Fatal("staged graph should be a draft")
	}
	if string(graphs.putRaw) != string(rec.CandidateGraph) {
		t.Fatalf("draft graph differs from candidate:\n%s\n%s", graphs.putRaw, rec.CandidateGraph)
	}

	// Applying again must conflict — the recommendation is no longer
	// pending.
	if _, _, err := svc.Apply(context.Background(), tenantID, &actor, rec.ID); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("re-apply error = %v, want ErrConflict", err)
	}
}

func TestService_Dismiss(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	envs := []schema.Envelope{dnsEnv(t, "api.example.com", schema.VerdictAllow)}
	svc, _ := newTestService(t, envs, &fakeGraphs{})

	rec, err := svc.Generate(context.Background(), tenantID, nil, GenerateRequest{
		Since: time.Unix(0, 0), Until: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	dismissed, err := svc.Dismiss(context.Background(), tenantID, nil, rec.ID)
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if dismissed.Status != repository.PolicyRecommendationStatusDismissed {
		t.Fatalf("status = %q, want dismissed", dismissed.Status)
	}
}

func TestService_Generate_RejectsBadWindow(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t, nil, &fakeGraphs{})
	_, err := svc.Generate(context.Background(), uuid.New(), nil, GenerateRequest{
		Since: time.Unix(1000, 0), Until: time.Unix(0, 0),
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}
}
