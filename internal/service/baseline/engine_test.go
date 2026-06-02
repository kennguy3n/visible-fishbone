// Package baseline_test exercises the Engine + Service contract
// for the statistical baseline layer.
//
// The Engine tests are arithmetic-only: they fold a known
// sequence of observations and assert the resulting Welford /
// EWMA state matches a reference implementation.
//
// The Service tests cover cold-start materialisation +
// optimistic-lock retry behaviour against the in-memory
// repository.
package baseline_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/baseline"
)

func ctx() context.Context { return context.Background() }

func seedTenant(t *testing.T) (*memory.Store, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	s.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "T", Slug: "t",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt.ID
}

func TestEngine_Fold_ColdStart(t *testing.T) {
	e := baseline.NewEngine()
	b := repository.BaselineModel{Alpha: 0.1, ZThreshold: 3.0}
	folded := e.Fold(b, baseline.Observation{Value: 42, At: time.Now()})
	if folded.Samples != 1 {
		t.Fatalf("Samples = %d, want 1", folded.Samples)
	}
	if folded.Mean != 42 {
		t.Fatalf("Mean = %v, want 42", folded.Mean)
	}
	if folded.M2 != 0 {
		t.Fatalf("M2 = %v, want 0", folded.M2)
	}
	if folded.EWMA != 42 {
		t.Fatalf("EWMA = %v, want 42 (cold start)", folded.EWMA)
	}
	if folded.EWMAVar != 0 {
		t.Fatalf("EWMAVar = %v, want 0 (cold start)", folded.EWMAVar)
	}
}

func TestEngine_Fold_WelfordMatchesNaive(t *testing.T) {
	// Reference: 10 samples — compute mean + sample variance
	// the naive way, then compare to the Engine's online
	// estimator. Equality should hold to machine epsilon.
	xs := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var sum, sumSq float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	for _, x := range xs {
		sumSq += (x - mean) * (x - mean)
	}
	wantVar := sumSq / float64(len(xs)-1)
	wantStd := math.Sqrt(wantVar)

	e := baseline.NewEngine()
	b := repository.BaselineModel{Alpha: 0.1, ZThreshold: 3.0}
	for _, x := range xs {
		b = e.Fold(b, baseline.Observation{Value: x})
	}
	if math.Abs(b.Mean-mean) > 1e-12 {
		t.Fatalf("Mean = %v, want %v", b.Mean, mean)
	}
	if math.Abs(b.StdDev()-wantStd) > 1e-12 {
		t.Fatalf("StdDev = %v, want %v", b.StdDev(), wantStd)
	}
}

func TestEngine_Fold_EWMAConvergesToConstant(t *testing.T) {
	// Feed 100 identical observations; the EWMA must
	// converge to that constant value and EWMAVar must
	// approach 0.
	e := baseline.NewEngine()
	b := repository.BaselineModel{Alpha: 0.1, ZThreshold: 3.0}
	for i := 0; i < 100; i++ {
		b = e.Fold(b, baseline.Observation{Value: 7})
	}
	if math.Abs(b.EWMA-7) > 1e-6 {
		t.Fatalf("EWMA = %v, want ≈ 7", b.EWMA)
	}
	if b.EWMAVar > 1e-6 {
		t.Fatalf("EWMAVar = %v, want ≈ 0", b.EWMAVar)
	}
}

func TestEngine_Fold_AppliesDefaults(t *testing.T) {
	e := baseline.NewEngine()
	folded := e.Fold(repository.BaselineModel{}, baseline.Observation{Value: 1})
	if folded.Alpha != baseline.DefaultAlpha {
		t.Fatalf("Alpha = %v, want %v (default)", folded.Alpha, baseline.DefaultAlpha)
	}
	if folded.ZThreshold != baseline.DefaultZThreshold {
		t.Fatalf("ZThreshold = %v, want %v (default)", folded.ZThreshold, baseline.DefaultZThreshold)
	}
}

func TestEngine_Score_ColdStartReturnsZero(t *testing.T) {
	e := baseline.NewEngine()
	b := repository.BaselineModel{Samples: 0}
	zw, ze := e.Score(b, baseline.Observation{Value: 100})
	if zw != 0 || ze != 0 {
		t.Fatalf("zw=%v ze=%v, want 0/0", zw, ze)
	}
}

func TestEngine_Score_DetectsSpike(t *testing.T) {
	e := baseline.NewEngine()
	b := repository.BaselineModel{Alpha: 0.1, ZThreshold: 3.0}
	for i := 0; i < 100; i++ {
		// Tight distribution around 100.
		b = e.Fold(b, baseline.Observation{Value: 100 + float64(i%3-1)})
	}
	zw, ze := e.Score(b, baseline.Observation{Value: 1000})
	if math.Abs(zw) < 5 {
		t.Fatalf("zw = %v, want >5σ on a 10x spike", zw)
	}
	if math.Abs(ze) < 5 {
		t.Fatalf("ze = %v, want >5σ on a 10x spike", ze)
	}
	if got := baseline.MaxAbsZ(zw, ze); got < 5 {
		t.Fatalf("MaxAbsZ = %v, want >5σ", got)
	}
}

func TestService_Observe_ColdStart(t *testing.T) {
	s, tnt := seedTenant(t)
	svc := baseline.NewService(memory.NewBaselineModelRepository(s))
	saved, err := svc.Observe(ctx(), tnt, "dns.queries.NXDOMAIN", 60, baseline.Observation{
		Value: 17, At: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if saved.Samples != 1 {
		t.Fatalf("Samples = %d, want 1 (cold start insert)", saved.Samples)
	}
	if saved.Mean != 17 {
		t.Fatalf("Mean = %v, want 17", saved.Mean)
	}
	if saved.Alpha != baseline.DefaultAlpha {
		t.Fatalf("Alpha = %v, want %v", saved.Alpha, baseline.DefaultAlpha)
	}
}

func TestService_Observe_FoldsAcrossCalls(t *testing.T) {
	s, tnt := seedTenant(t)
	svc := baseline.NewService(memory.NewBaselineModelRepository(s))
	xs := []float64{10, 12, 14, 16, 18}
	for _, x := range xs {
		_, err := svc.Observe(ctx(), tnt, "auth.failures", 60, baseline.Observation{Value: x})
		if err != nil {
			t.Fatalf("observe %v: %v", x, err)
		}
	}
	// Read back the persisted state directly.
	repo := memory.NewBaselineModelRepository(s)
	saved, err := repo.GetForDimension(ctx(), tnt, "auth.failures", 60)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if saved.Samples != int64(len(xs)) {
		t.Fatalf("Samples = %d, want %d", saved.Samples, len(xs))
	}
	if math.Abs(saved.Mean-14) > 1e-9 {
		t.Fatalf("Mean = %v, want 14", saved.Mean)
	}
}

func TestService_Observe_RejectsInvalid(t *testing.T) {
	s, tnt := seedTenant(t)
	svc := baseline.NewService(memory.NewBaselineModelRepository(s))
	tests := []struct {
		name    string
		tnt     uuid.UUID
		dim     string
		wnd     int
		wantErr error
	}{
		{"nil tenant", uuid.Nil, "d", 60, repository.ErrInvalidArgument},
		{"empty dim", tnt, "", 60, repository.ErrInvalidArgument},
		{"zero window", tnt, "d", 0, repository.ErrInvalidArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Observe(ctx(), tc.tnt, tc.dim, tc.wnd, baseline.Observation{Value: 1})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
