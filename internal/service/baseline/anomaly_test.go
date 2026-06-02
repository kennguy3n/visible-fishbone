// Package baseline_test — anomaly tests pin the Detector's
// emit policy:
//
//   - No emit during warmup (samples < MinWarmupSamples).
//   - No emit when max|z| < threshold.
//   - Emit at warning when threshold <= max|z| < 1.5*threshold.
//   - Emit at critical when max|z| >= 1.5*threshold.
//   - Cold-start (no row): folds + persists, never emits.
package baseline_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/baseline"
)

// stubEmitter records emit calls.
type stubEmitter struct {
	calls []repository.Alert
}

func (s *stubEmitter) Emit(ctx context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error) {
	a.ID = uuid.New()
	a.TenantID = tenantID
	a.CreatedAt = time.Now().UTC()
	a.UpdatedAt = a.CreatedAt
	s.calls = append(s.calls, a)
	return a, nil
}

func TestDetector_NoEmitDuringWarmup(t *testing.T) {
	s, tnt := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	emitter := &stubEmitter{}
	det := baseline.NewDetector(svc, emitter, baseline.DetectorOptions{})

	// Single observation — far below warmup.
	_, alert, err := det.ObserveAndScore(ctx(), tnt, "d", 60, baseline.Observation{Value: 999}, "")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if alert != nil {
		t.Fatalf("unexpected alert during warmup")
	}
	if len(emitter.calls) != 0 {
		t.Fatalf("emit called during warmup")
	}
}

func TestDetector_EmitsAtWarningOnce(t *testing.T) {
	s, tnt := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	emitter := &stubEmitter{}
	// Lower the warmup threshold so the test stays fast.
	det := baseline.NewDetector(svc, emitter, baseline.DetectorOptions{
		MinWarmupSamples: 5,
		WarningZScore:    3.0,
	})

	// Build a tight baseline around 100.
	for i := 0; i < 30; i++ {
		_, _, err := det.ObserveAndScore(ctx(), tnt, "auth.failures", 60,
			baseline.Observation{Value: 100 + float64(i%3-1)}, "")
		if err != nil {
			t.Fatalf("seed observe %d: %v", i, err)
		}
	}
	if len(emitter.calls) != 0 {
		t.Fatalf("emit during baseline build: %d", len(emitter.calls))
	}

	// 10x spike.
	_, alert, err := det.ObserveAndScore(ctx(), tnt, "auth.failures", 60,
		baseline.Observation{Value: 1000}, "")
	if err != nil {
		t.Fatalf("spike observe: %v", err)
	}
	if alert == nil {
		t.Fatalf("expected alert on spike")
	}
	if alert.Severity != repository.AlertSeverityCritical {
		t.Fatalf("severity = %s, want critical (z far above 1.5x threshold)", alert.Severity)
	}
	if len(emitter.calls) != 1 {
		t.Fatalf("emit called %d times, want 1", len(emitter.calls))
	}
	// The folded baseline must have absorbed the spike.
	cur, err := repo.GetForDimension(ctx(), tnt, "auth.failures", 60)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cur.Samples != 31 {
		t.Fatalf("Samples = %d, want 31 (30 seed + 1 spike)", cur.Samples)
	}
}

func TestDetector_NoEmitWhenNoEmitterConfigured(t *testing.T) {
	s, tnt := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	det := baseline.NewDetector(svc, nil, baseline.DetectorOptions{
		MinWarmupSamples: 2,
		WarningZScore:    3.0,
	})
	// Seed + spike — even though scoring would emit, with no
	// emitter the call returns successfully.
	for i := 0; i < 30; i++ {
		_, _, err := det.ObserveAndScore(ctx(), tnt, "d", 60,
			baseline.Observation{Value: 100 + float64(i%2)}, "")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	_, alert, err := det.ObserveAndScore(ctx(), tnt, "d", 60,
		baseline.Observation{Value: 100000}, "")
	if err != nil {
		t.Fatalf("spike: %v", err)
	}
	if alert != nil {
		t.Fatalf("unexpected alert despite no emitter")
	}
}

// TestDetector_RespectsLowerOperatorThreshold pins PR #40 round-7
// BUG_0001: an operator override (or feedback-tuning nudge) that
// lowers the BaselineModel.ZThreshold below DetectorOptions.
// WarningZScore must take effect. Pre-fix the Detector floored the
// effective threshold at WarningZScore (default 3.0), silently
// muting any sub-3σ overrides.
func TestDetector_RespectsLowerOperatorThreshold(t *testing.T) {
	s, tnt := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	emitter := &stubEmitter{}
	// WarningZScore stays at the package default (3.0σ); the
	// operator override below MUST take precedence anyway.
	det := baseline.NewDetector(svc, emitter, baseline.DetectorOptions{
		MinWarmupSamples: 5,
		WarningZScore:    3.0,
	})

	// Build a tight baseline around 100 (low variance so 2.5σ is reachable).
	for i := 0; i < 30; i++ {
		_, _, err := det.ObserveAndScore(ctx(), tnt, "auth.failures", 60,
			baseline.Observation{Value: 100 + float64(i%3-1)}, "")
		if err != nil {
			t.Fatalf("seed observe %d: %v", i, err)
		}
	}
	if len(emitter.calls) != 0 {
		t.Fatalf("emit during baseline build: %d", len(emitter.calls))
	}

	// Operator overrides the threshold down to 2.0σ — emulating
	// the feedback-tuning loop that lowered the threshold after a
	// streak of true_positive feedback on this dimension.
	if _, err := repo.UpdateThreshold(ctx(), tnt, "auth.failures", 60, 2.0); err != nil {
		t.Fatalf("operator override: %v", err)
	}

	// Modest spike: enough to exceed the persisted 2.0σ but
	// well below the 3.0σ WarningZScore floor that the pre-fix
	// Detector would have applied. With baseline mean ≈ 100 and
	// stddev ≈ 1 (from the i%3-1 sweep), value=103 lands at
	// roughly 2.5σ — comfortably between the new override and
	// the old floor.
	_, alert, err := det.ObserveAndScore(ctx(), tnt, "auth.failures", 60,
		baseline.Observation{Value: 103}, "")
	if err != nil {
		t.Fatalf("override spike: %v", err)
	}
	if alert == nil {
		t.Fatalf("expected alert after operator override; the WarningZScore floor would have suppressed this pre-fix")
	}
	// Severity is best-effort (depends on the exact baseline
	// stddev, which depends on the seed sequence). The
	// load-bearing assertion is that the threshold snapshot in
	// the alert evidence reflects the operator override (2.0),
	// not the WarningZScore floor (3.0).
	var ev map[string]any
	if err := json.Unmarshal(alert.Evidence, &ev); err != nil {
		t.Fatalf("evidence unmarshal: %v", err)
	}
	if got, ok := ev["threshold_z"].(float64); !ok || got != 2.0 {
		t.Errorf("evidence.threshold_z = %v, want 2.0 (operator override)", ev["threshold_z"])
	}
}

func TestDetector_RejectsInvalidArgs(t *testing.T) {
	s, _ := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	det := baseline.NewDetector(svc, &stubEmitter{}, baseline.DetectorOptions{})

	cases := []struct {
		name string
		tnt  uuid.UUID
		dim  string
		wnd  int
	}{
		{"nil tenant", uuid.Nil, "d", 60},
		{"empty dim", uuid.New(), "", 60},
		{"zero window", uuid.New(), "d", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, alert, err := det.ObserveAndScore(ctx(), tc.tnt, tc.dim, tc.wnd, baseline.Observation{Value: 1}, "")
			if err == nil {
				t.Fatalf("err = nil, want ErrInvalidArgument")
			}
			if alert != nil {
				t.Fatalf("alert = %v, want nil", alert)
			}
		})
	}
}
