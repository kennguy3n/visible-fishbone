// Package alert — feedback_logger_test pins the logging contract
// of Feedback.tickOnce: every failure path (tenants enumeration,
// per-tenant baseline.List, per-dimension TuneDimension) MUST
// surface a slog WARN record so a production operator can
// diagnose why threshold tuning stopped firing.
//
// Previously the docstring promised logging but the struct had
// no logger field and the implementation discarded errors with
// `_, _ = TuneDimension(...)`; this test guards against that
// regression. See PR #40 round-12 ANALYSIS_0001.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// erroringBaseline always fails List. Other methods are stubs.
type erroringBaseline struct{}

func (erroringBaseline) GetForDimension(
	context.Context, uuid.UUID, string, int,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, repository.ErrNotFound
}
func (erroringBaseline) Upsert(
	context.Context, uuid.UUID, repository.BaselineModel,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}
func (erroringBaseline) UpdateThreshold(
	context.Context, uuid.UUID, string, int, float64,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}
func (erroringBaseline) List(
	context.Context, uuid.UUID, repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	return repository.PageResult[repository.BaselineModel]{}, errors.New("simulated list failure")
}

// tuneFailingBaseline succeeds at List (returning one model)
// but the TuneDimension call fails because the AlertFeedbackRepository
// .ListByDimension errors. This drives the third log-call path.
type tuneFailingBaseline struct{}

func (tuneFailingBaseline) GetForDimension(
	context.Context, uuid.UUID, string, int,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, repository.ErrNotFound
}
func (tuneFailingBaseline) Upsert(
	context.Context, uuid.UUID, repository.BaselineModel,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}
func (tuneFailingBaseline) UpdateThreshold(
	context.Context, uuid.UUID, string, int, float64,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}
func (tuneFailingBaseline) List(
	_ context.Context, tenantID uuid.UUID, _ repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	return repository.PageResult[repository.BaselineModel]{
		Items: []repository.BaselineModel{{
			TenantID:      tenantID,
			Dimension:     "fail.dim",
			WindowSeconds: 60,
		}},
	}, nil
}

type erroringFeedback struct{}

func (erroringFeedback) Create(context.Context, uuid.UUID, repository.AlertFeedback) (repository.AlertFeedback, error) {
	return repository.AlertFeedback{}, nil
}
func (erroringFeedback) GetForAlert(context.Context, uuid.UUID, uuid.UUID) (repository.AlertFeedback, error) {
	return repository.AlertFeedback{}, repository.ErrNotFound
}
func (erroringFeedback) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (erroringFeedback) ListByDimension(context.Context, uuid.UUID, string, int, time.Time) ([]repository.AlertFeedback, error) {
	return nil, errors.New("simulated feedback list failure")
}

// captureLogger wires a slog handler that writes JSON records to
// a buffer the test can scan. Using JSON over text keeps the
// assertion robust against slog formatting changes.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// assertWarn fails the test unless buf contains at least one
// JSON record at WARN level whose msg matches wantSubstring.
func assertWarn(t *testing.T, buf *bytes.Buffer, wantSubstring string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Level == "WARN" && strings.Contains(rec.Msg, wantSubstring) {
			return
		}
	}
	t.Fatalf("missing WARN log containing %q. captured:\n%s", wantSubstring, buf.String())
}

func TestFeedback_TickOnce_LogsTenantsEnumError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	fb := NewFeedback(erroringFeedback{}, nil, erroringBaseline{}, FeedbackTuningOptions{})
	fb.SetLogger(captureLogger(&buf))

	fb.tickOnce(context.Background(), func(context.Context) ([]uuid.UUID, error) {
		return nil, errors.New("simulated tenants enum failure")
	})

	assertWarn(t, &buf, "tenants enumeration failed")
}

func TestFeedback_TickOnce_LogsBaselineListError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	fb := NewFeedback(erroringFeedback{}, nil, erroringBaseline{}, FeedbackTuningOptions{})
	fb.SetLogger(captureLogger(&buf))

	fb.tickOnce(context.Background(), func(context.Context) ([]uuid.UUID, error) {
		return []uuid.UUID{uuid.New()}, nil
	})

	assertWarn(t, &buf, "baseline list failed")
}

func TestFeedback_TickOnce_LogsTuneDimensionError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	fb := NewFeedback(erroringFeedback{}, nil, tuneFailingBaseline{}, FeedbackTuningOptions{
		MinSampleCount: 1,
	})
	fb.SetLogger(captureLogger(&buf))

	fb.tickOnce(context.Background(), func(context.Context) ([]uuid.UUID, error) {
		return []uuid.UUID{uuid.New()}, nil
	})

	assertWarn(t, &buf, "TuneDimension failed")
}

func TestFeedback_SetLogger_NilResetsToDefault(t *testing.T) {
	t.Parallel()
	fb := NewFeedback(erroringFeedback{}, nil, erroringBaseline{}, FeedbackTuningOptions{})
	// Replace with a custom logger, then reset to nil — must
	// not panic, must use slog.Default().
	var buf bytes.Buffer
	fb.SetLogger(captureLogger(&buf))
	fb.SetLogger(nil)
	if fb.logger == nil {
		t.Fatal("SetLogger(nil) left logger nil; expected slog.Default()")
	}
}
