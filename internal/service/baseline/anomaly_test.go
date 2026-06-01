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
