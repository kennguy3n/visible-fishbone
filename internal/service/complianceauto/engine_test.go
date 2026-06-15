package complianceauto

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fakeSource is a deterministic PlatformSource for engine tests. snapFn
// builds the per-tenant snapshot so a test can flip a single field and
// observe the resulting control flip end to end.
type fakeSource struct {
	ids    []uuid.UUID
	snapFn func(uuid.UUID) Snapshot
	err    error
}

func (f *fakeSource) Tenants(context.Context) ([]uuid.UUID, error) {
	return f.ids, f.err
}

func (f *fakeSource) Snapshot(_ context.Context, id uuid.UUID) (Snapshot, error) {
	if f.err != nil {
		return Snapshot{}, f.err
	}
	return f.snapFn(id), nil
}

var _ PlatformSource = (*fakeSource)(nil)

// healthySnapshot is an all-controls-pass snapshot at a fixed time.
func healthySnapshot(id uuid.UUID) Snapshot {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return Snapshot{
		TenantID:              id,
		ObservedAt:            at,
		HasPolicyGraph:        true,
		PolicyDefaultDeny:     true,
		PolicyGraphVersion:    7,
		RLSEnforced:           true,
		EncryptionAtRest:      true,
		TLSEnforced:           true,
		IDPConfigured:         1,
		IDPEnabled:            1,
		HasActiveSigningKey:   true,
		SigningKeyActivatedAt: at.Add(-10 * 24 * time.Hour),
		Region:                "eu-west-1",
		HasAuditActivity:      true,
		LastAuditAt:           at,
		RetentionDays:         90,
	}
}

func newTestEngine(t *testing.T, src PlatformSource) (*Engine, *memory.ComplianceAutoRepository) {
	t.Helper()
	repo := memory.NewComplianceAutoRepository()
	eng := NewEngine(src, repo, Config{
		Clock: func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) },
	})
	return eng, repo
}

func findControl(p TenantPosture, fw Framework, id string) (ControlResult, bool) {
	for _, fp := range p.Frameworks {
		if fp.Framework != fw {
			continue
		}
		for _, c := range fp.Controls {
			if c.Control.ID == id {
				return c, true
			}
		}
	}
	return ControlResult{}, false
}

func TestEngine_EvaluatePersistsAndPostureReads(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	src := &fakeSource{
		ids:    []uuid.UUID{id},
		snapFn: healthySnapshot,
	}
	eng, repo := newTestEngine(t, src)
	ctx := context.Background()

	posture, err := eng.Evaluate(ctx, id)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(posture.Frameworks) != len(Frameworks()) {
		t.Fatalf("frameworks = %d, want %d", len(posture.Frameworks), len(Frameworks()))
	}
	// A healthy snapshot passes every in-scope control.
	for _, fp := range posture.Frameworks {
		if fp.Fail != 0 {
			t.Errorf("framework %s: %d failing controls on healthy snapshot", fp.Framework, fp.Fail)
		}
		if fp.Total != len(ControlsForFramework(fp.Framework)) {
			t.Errorf("framework %s: total = %d, want %d", fp.Framework, fp.Total, len(ControlsForFramework(fp.Framework)))
		}
	}

	// The run was recorded.
	run, err := repo.LatestRun(ctx, id)
	if err != nil {
		t.Fatalf("latest run: %v", err)
	}
	if run.ControlsTotal != len(Catalog()) {
		t.Errorf("run controls total = %d, want %d", run.ControlsTotal, len(Catalog()))
	}

	// Evidence history was appended for every control.
	evidence, err := repo.ListEvidence(ctx, id, "", 0)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(evidence) != len(Catalog()) {
		t.Errorf("evidence rows = %d, want %d", len(evidence), len(Catalog()))
	}
	for _, e := range evidence {
		if len(e.Details) == 0 {
			t.Errorf("control %s: evidence details empty", e.ControlID)
		}
	}

	// Posture (read path) matches the freshly computed posture shape.
	read, err := eng.Posture(ctx, id, "")
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if len(read.Frameworks) != len(posture.Frameworks) {
		t.Fatalf("posture read frameworks = %d, want %d", len(read.Frameworks), len(posture.Frameworks))
	}
	// Read path joins catalog metadata (title) onto stored rows.
	if c, ok := findControl(read, FrameworkSOC2, "CC6.1"); !ok || c.Control.Title == "" {
		t.Errorf("posture read did not join catalog metadata for CC6.1: %+v", c)
	}
}

func TestEngine_PostureFrameworkFilter(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{id}, snapFn: healthySnapshot})
	ctx := context.Background()
	if _, err := eng.Evaluate(ctx, id); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	only, err := eng.Posture(ctx, id, FrameworkSOC2)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if len(only.Frameworks) != 1 || only.Frameworks[0].Framework != FrameworkSOC2 {
		t.Fatalf("filtered posture = %+v, want only SOC2", only.Frameworks)
	}
}

// TestEngine_FlipSettingFlipsControl is the core property: a real
// platform-state change must flip the persisted control verdict.
func TestEngine_FlipSettingFlipsControl(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	defaultDeny := true
	src := &fakeSource{
		ids: []uuid.UUID{id},
		snapFn: func(tid uuid.UUID) Snapshot {
			s := healthySnapshot(tid)
			s.PolicyDefaultDeny = defaultDeny
			return s
		},
	}
	eng, _ := newTestEngine(t, src)
	ctx := context.Background()

	if _, err := eng.Evaluate(ctx, id); err != nil {
		t.Fatalf("evaluate (deny): %v", err)
	}
	p, _ := eng.Posture(ctx, id, FrameworkSOC2)
	if c, ok := findControl(p, FrameworkSOC2, "CC6.1"); !ok || c.Status != StatusPass {
		t.Fatalf("CC6.1 with default-deny: status = %q, want pass", c.Status)
	}

	// Flip the platform setting and re-evaluate.
	defaultDeny = false
	if _, err := eng.Evaluate(ctx, id); err != nil {
		t.Fatalf("evaluate (allow): %v", err)
	}
	p, _ = eng.Posture(ctx, id, FrameworkSOC2)
	c, ok := findControl(p, FrameworkSOC2, "CC6.1")
	if !ok || c.Status != StatusFail {
		t.Fatalf("CC6.1 after flip to allow: status = %q, want fail", c.Status)
	}
}

func TestEngine_CollectAllSweepsEveryTenant(t *testing.T) {
	t.Parallel()
	a, b := uuid.New(), uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{a, b}, snapFn: healthySnapshot})
	ctx := context.Background()
	if err := eng.CollectAll(ctx); err != nil {
		t.Fatalf("collect all: %v", err)
	}
	for _, id := range []uuid.UUID{a, b} {
		p, err := eng.Posture(ctx, id, "")
		if err != nil {
			t.Fatalf("posture %s: %v", id, err)
		}
		if len(p.Frameworks) == 0 {
			t.Errorf("tenant %s has no posture after sweep", id)
		}
	}
}

// TestEngine_CollectAllSkipsTrailingPace proves the sweep does NOT wait
// the per-tenant pace after the final tenant: with a single tenant and a
// huge pace, CollectAll must still return promptly (it would block for an
// hour if it paced after the last tenant).
func TestEngine_CollectAllSkipsTrailingPace(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{id}, snapFn: healthySnapshot})
	eng.perTenant = time.Hour
	done := make(chan error, 1)
	go func() { done <- eng.CollectAll(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("collect all: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CollectAll blocked on a trailing pace after the final tenant")
	}
}

// TestEngine_CollectAllPacesBetweenTenants proves the between-tenant pace
// is still present and context-aware: with two tenants and a huge pace,
// the sweep blocks in the pause after the first tenant and unwinds with
// the context error when cancelled.
func TestEngine_CollectAllPacesBetweenTenants(t *testing.T) {
	t.Parallel()
	a, b := uuid.New(), uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{a, b}, snapFn: healthySnapshot})
	eng.perTenant = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.CollectAll(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled from the between-tenant pace, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CollectAll did not observe ctx cancellation during the between-tenant pace")
	}
}

func TestEngine_ExportPackRoundTrips(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{id}, snapFn: healthySnapshot})
	ctx := context.Background()
	if _, err := eng.Evaluate(ctx, id); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	pack, err := eng.ExportPack(ctx, id, FrameworkSOC2)
	if err != nil {
		t.Fatalf("export pack: %v", err)
	}
	if pack.Framework != FrameworkSOC2 {
		t.Fatalf("pack framework = %q", pack.Framework)
	}
	if pack.Summary.Total != len(ControlsForFramework(FrameworkSOC2)) {
		t.Fatalf("pack total = %d, want %d", pack.Summary.Total, len(ControlsForFramework(FrameworkSOC2)))
	}

	raw, err := pack.MarshalJSONIndent()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := ParsePackJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.TenantID != pack.TenantID || back.Framework != pack.Framework ||
		back.Summary != pack.Summary || len(back.Controls) != len(pack.Controls) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", back.Summary, pack.Summary)
	}
}

func TestEngine_EvaluateSnapshotErrorPropagates(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	eng, _ := newTestEngine(t, &fakeSource{ids: []uuid.UUID{id}, err: context.DeadlineExceeded})
	if _, err := eng.Evaluate(context.Background(), id); err == nil {
		t.Fatal("expected error when snapshot fails")
	}
}
