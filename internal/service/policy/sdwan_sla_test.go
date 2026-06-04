package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func newSLAService(t *testing.T) (*policy.SLATemplateService, uuid.UUID) {
	t.Helper()
	repo := policy.NewInMemorySLATemplateRepository()
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	svc := policy.NewSLATemplateService(repo, policy.WithSLAClock(func() time.Time { return fixed }))
	return svc, uuid.New()
}

func f64(v float64) *float64 { return &v }

func TestSLATemplateInputValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      policy.SLATemplateInput
		wantErr bool
	}{
		{"ok", policy.SLATemplateInput{Name: "n", TrafficClass: policy.SLAClassRealTime, MaxJitterMs: f64(15)}, false},
		{"empty name", policy.SLATemplateInput{Name: "", TrafficClass: policy.SLAClassRealTime}, true},
		{"bad class", policy.SLATemplateInput{Name: "n", TrafficClass: "platinum"}, true},
		{"negative latency", policy.SLATemplateInput{Name: "n", TrafficClass: policy.SLAClassBusinessCritical, MaxLatencyMs: f64(-1)}, true},
		{"loss over 100", policy.SLATemplateInput{Name: "n", TrafficClass: policy.SLAClassBestEffort, MaxLossPct: f64(101)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, repository.ErrInvalidArgument) {
					t.Fatalf("expected ErrInvalidArgument, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSLATemplateCRUD(t *testing.T) {
	svc, tenant := newSLAService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, tenant, policy.SLATemplateInput{
		Name:         "voice",
		TrafficClass: policy.SLAClassRealTime,
		MaxJitterMs:  f64(15),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == uuid.Nil || created.TenantID != tenant {
		t.Fatalf("unexpected identity: %+v", created)
	}
	if created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("timestamps not set: %+v", created)
	}

	got, err := svc.Get(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "voice" {
		t.Fatalf("unexpected name: %q", got.Name)
	}

	// Duplicate name -> conflict.
	if _, err := svc.Create(ctx, tenant, policy.SLATemplateInput{Name: "voice", TrafficClass: policy.SLAClassRealTime}); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	updated, err := svc.Update(ctx, tenant, created.ID, policy.SLATemplateInput{
		Name:         "voice",
		TrafficClass: policy.SLAClassBusinessCritical,
		MaxLatencyMs: f64(40),
		MaxLossPct:   f64(0.05),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.TrafficClass != policy.SLAClassBusinessCritical || updated.MaxJitterMs != nil {
		t.Fatalf("update did not replace fields: %+v", updated)
	}
	if updated.MaxLatencyMs == nil || *updated.MaxLatencyMs != 40 {
		t.Fatalf("expected latency 40, got %+v", updated.MaxLatencyMs)
	}

	if err := svc.Delete(ctx, tenant, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.Get(ctx, tenant, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestSLATemplateTenantIsolation(t *testing.T) {
	svc, tenant := newSLAService(t)
	ctx := context.Background()
	created, err := svc.Create(ctx, tenant, policy.SLATemplateInput{Name: "n", TrafficClass: policy.SLAClassBestEffort})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	other := uuid.New()
	if _, err := svc.Get(ctx, other, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected isolation not-found, got %v", err)
	}
}

func TestSLAEnsureDefaultsIdempotent(t *testing.T) {
	svc, tenant := newSLAService(t)
	ctx := context.Background()

	first, err := svc.EnsureDefaults(ctx, tenant)
	if err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	if len(first) != len(policy.DefaultSLATemplates()) {
		t.Fatalf("expected %d defaults, got %d", len(policy.DefaultSLATemplates()), len(first))
	}
	second, err := svc.EnsureDefaults(ctx, tenant)
	if err != nil {
		t.Fatalf("ensure defaults (2nd): %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("ensure defaults not idempotent: %d != %d", len(second), len(first))
	}

	// Spot-check the business-critical thresholds from the spec.
	var bc *policy.SLATemplate
	for i := range second {
		if second[i].Name == policy.SLAClassBusinessCritical {
			bc = &second[i]
		}
	}
	if bc == nil || bc.MaxLatencyMs == nil || *bc.MaxLatencyMs != 50 || bc.MaxLossPct == nil || *bc.MaxLossPct != 0.1 {
		t.Fatalf("business-critical defaults wrong: %+v", bc)
	}
}

func TestSLACompileDeterministicAndBestEffortNull(t *testing.T) {
	svc, tenant := newSLAService(t)
	ctx := context.Background()
	if _, err := svc.EnsureDefaults(ctx, tenant); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}

	slice, err := svc.Compile(ctx, tenant)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(slice) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(slice))
	}
	// Deterministic ordering: classes are sorted ascending.
	if slice[0].Class > slice[1].Class || slice[1].Class > slice[2].Class {
		t.Fatalf("compile output not ordered: %+v", slice)
	}
	for _, e := range slice {
		if e.ConsecutiveBreaches != policy.SLADefaultConsecutiveBreaches {
			t.Fatalf("expected default consecutive breaches, got %d", e.ConsecutiveBreaches)
		}
		if e.Class == policy.SLAClassBestEffort {
			if e.MaxLatencyMs != nil || e.MaxLossPct != nil || e.MaxJitterMs != nil || e.MinThroughputMbps != nil {
				t.Fatalf("best-effort should have null thresholds: %+v", e)
			}
		}
	}
}
