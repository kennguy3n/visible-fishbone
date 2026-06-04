package compliance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

func TestSOC2Collector_CollectsWiredControls(t *testing.T) {
	src := compliance.Sources{
		RBACPolicy:    func(context.Context) (any, error) { return map[string]string{"role": "admin"}, nil },
		AccessReviews: func(context.Context) (any, error) { return []string{"review-1"}, nil },
		HAConfig:      func(context.Context) (any, error) { return map[string]string{"model": "active-active"}, nil },
	}
	c := compliance.NewSOC2Collector(src, nil, compliance.WithCollectorClock(func() time.Time {
		return time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	}))
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	res, err := c.Collect(context.Background(), compliance.CollectionWeekly)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.FailedControl) != 0 {
		t.Fatalf("unexpected failures: %v", res.FailedControl)
	}
	// CC6.1 (2 wired exports) + CC8.1 (1 wired export) = 3 artifacts.
	if len(res.Bundle.Artifacts) != 3 {
		t.Fatalf("artifacts = %d, want 3", len(res.Bundle.Artifacts))
	}
	controls := res.Bundle.Controls()
	if len(controls) != 2 || controls[0] != compliance.ControlCC61 || controls[1] != compliance.ControlCC81 {
		t.Fatalf("controls = %v, want [CC6.1 CC8.1]", controls)
	}

	missing := res.MissingControls()
	// CC6.2, CC6.3, CC7.1 were never wired.
	wantMissing := map[string]bool{compliance.ControlCC62: true, compliance.ControlCC63: true, compliance.ControlCC71: true}
	if len(missing) != len(wantMissing) {
		t.Fatalf("missing = %v, want keys %v", missing, wantMissing)
	}
	for _, m := range missing {
		if !wantMissing[m] {
			t.Fatalf("unexpected missing control %q", m)
		}
	}
}

func TestSOC2Collector_RecordsControlFailureButKeepsOthers(t *testing.T) {
	boom := errors.New("rbac export failed")
	src := compliance.Sources{
		RBACPolicy: func(context.Context) (any, error) { return nil, boom },
		HAConfig:   func(context.Context) (any, error) { return map[string]string{"model": "active-active"}, nil },
	}
	c := compliance.NewSOC2Collector(src, nil)

	res, err := c.Collect(context.Background(), compliance.CollectionManual)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := res.FailedControl[compliance.ControlCC61]; !errors.Is(got, boom) {
		t.Fatalf("FailedControl[CC6.1] = %v, want %v", got, boom)
	}
	// CC8.1 still collected despite CC6.1 failing.
	controls := res.Bundle.Controls()
	if len(controls) != 1 || controls[0] != compliance.ControlCC81 {
		t.Fatalf("controls = %v, want [CC8.1]", controls)
	}
}

func TestSOC2Collector_ValidateRejectsNoProviders(t *testing.T) {
	// NewSOC2CollectorWithProviders with an empty slice has nothing to
	// collect — Validate must surface that as a config error.
	c := compliance.NewSOC2CollectorWithProviders(nil, nil)
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate error for empty collector")
	}
}

func TestSOC2Collector_ContextCancellation(t *testing.T) {
	src := compliance.Sources{
		RBACPolicy: func(context.Context) (any, error) { return map[string]string{"x": "y"}, nil },
	}
	c := compliance.NewSOC2Collector(src, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx, compliance.CollectionWeekly); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
