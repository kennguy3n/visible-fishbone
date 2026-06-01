// Package alert_test — feedback_test pins the tuning policy:
//
//   - Below MinSampleCount: no action.
//   - FP rate >= 0.5 → raise threshold by RaiseStep, capped at Max.
//   - FP <= 0.05 AND noise <= 0.05 → lower by LowerStep, floored at Min.
//   - Otherwise no change.
//   - Already at cap/floor → no_change with explanatory SkippedReason.
package alert_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
)

func seedBaselineAndAlerts(
	t *testing.T,
	s *memory.Store,
	tnt uuid.UUID,
	dimension string,
	z float64,
	fbDecisions []repository.AlertFeedbackDecision,
) {
	t.Helper()
	bRepo := memory.NewBaselineModelRepository(s)
	if _, err := bRepo.Upsert(ctx(), tnt, repository.BaselineModel{
		Dimension: dimension, WindowSeconds: 60,
		Alpha: 0.1, ZThreshold: z, Samples: 100, Mean: 10, M2: 9, EWMA: 10, EWMAVar: 1,
	}); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	aRepo := memory.NewAlertRepository(s)
	fbRepo := memory.NewAlertFeedbackRepository(s)
	for i, decision := range fbDecisions {
		now := time.Now().UTC()
		a, err := aRepo.Create(ctx(), tnt, repository.Alert{
			Kind: "baseline.zscore_exceeded", Severity: repository.AlertSeverityWarning,
			Dimension: dimension, ObservedValue: 100, BaselineMean: 10, BaselineStdDev: 1,
			ZScore: 5, WindowStart: now.Add(-time.Minute), WindowEnd: now,
			Summary: "spike", Evidence: []byte(`{}`),
			State: repository.AlertStateOpen,
		})
		if err != nil {
			t.Fatalf("seed alert %d: %v", i, err)
		}
		if _, err := fbRepo.Create(ctx(), tnt, repository.AlertFeedback{
			AlertID: a.ID, Decision: decision,
		}); err != nil {
			t.Fatalf("seed feedback %d: %v", i, err)
		}
	}
}

func TestFeedback_Submit_HappyPath(t *testing.T) {
	s, tnt := seedTenant(t)
	aRepo := memory.NewAlertRepository(s)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		aRepo, memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{},
	)
	a, err := aRepo.Create(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	by := uuid.New()
	got, err := fb.Submit(ctx(), tnt, a.ID, repository.AlertFeedbackFalsePositive, "noisy probe", &by)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got.AlertID != a.ID || got.Decision != repository.AlertFeedbackFalsePositive {
		t.Fatalf("got = %+v", got)
	}
}

func TestFeedback_Submit_RejectsInvalidDecision(t *testing.T) {
	s, tnt := seedTenant(t)
	aRepo := memory.NewAlertRepository(s)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		aRepo, memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{},
	)
	_, err := fb.Submit(ctx(), tnt, uuid.New(), "bogus", "", nil)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestFeedback_TuneDimension_BelowMinSampleCount(t *testing.T) {
	s, tnt := seedTenant(t)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		memory.NewAlertRepository(s),
		memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{MinSampleCount: 5},
	)
	fb.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	// Only seed 2 feedback rows.
	seedBaselineAndAlerts(t, s, tnt, "d", 3.0, []repository.AlertFeedbackDecision{
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
	})
	res, err := fb.TuneDimension(ctx(), tnt, "d", 60)
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if res.Action != "no_change" {
		t.Fatalf("action = %s, want no_change", res.Action)
	}
	if res.SkippedReason == "" {
		t.Fatalf("expected SkippedReason")
	}
}

func TestFeedback_TuneDimension_RaisesOnHighFP(t *testing.T) {
	s, tnt := seedTenant(t)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		memory.NewAlertRepository(s),
		memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{
			MinSampleCount: 4, RaiseStep: 0.5, MaxZThreshold: 6.0,
		},
	)
	fb.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	// 5 feedback, 4 false positives → 80% FP rate.
	seedBaselineAndAlerts(t, s, tnt, "d", 3.0, []repository.AlertFeedbackDecision{
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackTruePositive,
	})
	res, err := fb.TuneDimension(ctx(), tnt, "d", 60)
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if res.Action != "raised" {
		t.Fatalf("action = %s, want raised", res.Action)
	}
	if res.NewZThreshold != 3.5 {
		t.Fatalf("NewZThreshold = %v, want 3.5", res.NewZThreshold)
	}
}

func TestFeedback_TuneDimension_LowersOnLowFPAndLowNoise(t *testing.T) {
	s, tnt := seedTenant(t)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		memory.NewAlertRepository(s),
		memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{
			MinSampleCount: 4, LowerStep: 0.25, MinZThreshold: 2.0,
		},
	)
	fb.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	// 20 true positives → 0% FP, 0% noise.
	decisions := make([]repository.AlertFeedbackDecision, 20)
	for i := range decisions {
		decisions[i] = repository.AlertFeedbackTruePositive
	}
	seedBaselineAndAlerts(t, s, tnt, "d", 3.0, decisions)
	res, err := fb.TuneDimension(ctx(), tnt, "d", 60)
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if res.Action != "lowered" {
		t.Fatalf("action = %s, want lowered", res.Action)
	}
	if res.NewZThreshold != 2.75 {
		t.Fatalf("NewZThreshold = %v, want 2.75", res.NewZThreshold)
	}
}

func TestFeedback_TuneDimension_AlreadyAtCap(t *testing.T) {
	s, tnt := seedTenant(t)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		memory.NewAlertRepository(s),
		memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{
			MinSampleCount: 4, RaiseStep: 0.5, MaxZThreshold: 6.0,
		},
	)
	fb.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	seedBaselineAndAlerts(t, s, tnt, "d", 6.0, []repository.AlertFeedbackDecision{
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
		repository.AlertFeedbackFalsePositive,
	})
	res, err := fb.TuneDimension(ctx(), tnt, "d", 60)
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if res.Action != "no_change" {
		t.Fatalf("action = %s, want no_change", res.Action)
	}
	if res.SkippedReason != "already at MaxZThreshold" {
		t.Fatalf("SkippedReason = %q, want 'already at MaxZThreshold'", res.SkippedReason)
	}
}

func TestFeedback_TuneDimension_MissingBaseline(t *testing.T) {
	s, tnt := seedTenant(t)
	fb := alert.NewFeedback(
		memory.NewAlertFeedbackRepository(s),
		memory.NewAlertRepository(s),
		memory.NewBaselineModelRepository(s),
		alert.FeedbackTuningOptions{MinSampleCount: 1},
	)
	fb.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	res, err := fb.TuneDimension(ctx(), tnt, "missing.dim", 60)
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if res.Action != "no_change" {
		t.Fatalf("action = %s, want no_change", res.Action)
	}
}
