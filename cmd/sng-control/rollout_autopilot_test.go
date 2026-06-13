package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/metrics"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// enabledAutopilotConfig returns a config with the autopilot turned on
// and a promotion guardrail at least as strict as the rollout demote
// threshold buildRouter wires (MaxErrorRate 0.05 / MinSamples 50), so
// NewAutopilot accepts it.
func enabledAutopilotConfig() *config.Config {
	cfg := &config.Config{}
	cfg.RolloutAutopilot = config.RolloutAutopilot{
		Enabled:      true,
		Interval:     time.Hour,
		AutoEnrol:    true,
		DwellWindow:  24 * time.Hour,
		MinSamples:   200,
		MaxErrorRate: 0.01,
		MaxDenyRate:  0.05,
	}
	return cfg
}

// newRolloutServiceForTest builds a rollout.Service over the memory repo
// with the same demote threshold buildRouter uses in production.
func newRolloutServiceForTest(t *testing.T) *rollout.Service {
	t.Helper()
	repo := memory.NewCapabilityRolloutRepository()
	svc, err := rollout.New(repo, rollout.WithThreshold(rollout.Threshold{
		MaxErrorRate: 0.05,
		MinSamples:   50,
	}))
	if err != nil {
		t.Fatalf("rollout.New: %v", err)
	}
	return svc
}

func TestParseAutopilotCapabilities(t *testing.T) {
	t.Parallel()

	all, err := parseAutopilotCapabilities(nil)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if len(all) != len(rollout.AllCapabilities()) {
		t.Fatalf("empty list governed %d caps, want all %d", len(all), len(rollout.AllCapabilities()))
	}

	got, err := parseAutopilotCapabilities([]string{string(rollout.CapabilityIDPDirectorySync)})
	if err != nil {
		t.Fatalf("valid id: %v", err)
	}
	if len(got) != 1 || got[0] != rollout.CapabilityIDPDirectorySync {
		t.Fatalf("parsed %v, want [idp_directory_sync]", got)
	}

	if _, err := parseAutopilotCapabilities([]string{"not_a_capability"}); err == nil {
		t.Fatal("unknown capability accepted, want error")
	}
}

func TestBuildRolloutAutopilotDisabledGate(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{} // RolloutAutopilot.Enabled defaults false
	svc := newRolloutServiceForTest(t)
	ap, err := buildRolloutAutopilot(cfg, svc, nil, rollout.NewMonitorMetricsRecorder(nil), nil, nil)
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if ap != nil {
		t.Fatal("disabled autopilot must be nil so main skips scheduling it")
	}
}

func TestBuildRolloutAutopilotEnabled(t *testing.T) {
	t.Parallel()
	cfg := enabledAutopilotConfig()
	svc := newRolloutServiceForTest(t)
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	ap, err := buildRolloutAutopilot(cfg, svc, tenants, rollout.NewMonitorMetricsRecorder(nil), nil, nil)
	if err != nil {
		t.Fatalf("enabled build: %v", err)
	}
	if ap == nil {
		t.Fatal("enabled autopilot must be non-nil")
	}
}

func TestBuildRolloutAutopilotRejectsLooseGuardrail(t *testing.T) {
	t.Parallel()
	cfg := enabledAutopilotConfig()
	// Promotion ceiling LOOSER than the demote threshold (0.05): a reading
	// that auto-demotes would NOT block promotion. NewAutopilot must
	// refuse this so the "demote implies promotion-blocked" invariant
	// holds, and buildRouter fails boot rather than silently mis-gating.
	cfg.RolloutAutopilot.MaxErrorRate = 0.5
	svc := newRolloutServiceForTest(t)
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	if _, err := buildRolloutAutopilot(cfg, svc, tenants, rollout.NewMonitorMetricsRecorder(nil), nil, nil); err == nil {
		t.Fatal("autopilot with looser-than-demote guardrail accepted, want error")
	}
}

func TestBuildRolloutAutopilotRejectsUnknownCapability(t *testing.T) {
	t.Parallel()
	cfg := enabledAutopilotConfig()
	cfg.RolloutAutopilot.Capabilities = []string{"bogus"}
	svc := newRolloutServiceForTest(t)
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	if _, err := buildRolloutAutopilot(cfg, svc, tenants, rollout.NewMonitorMetricsRecorder(nil), nil, nil); err == nil {
		t.Fatal("autopilot with unknown capability accepted, want error")
	}
}

func TestAutopilotTenantListerFiltersActive(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewTenantRepository(store)
	ctx := context.Background()

	active, err := repo.Create(ctx, repository.Tenant{Slug: "active-1", Status: repository.TenantStatusActive})
	if err != nil {
		t.Fatalf("create active: %v", err)
	}
	if _, err := repo.Create(ctx, repository.Tenant{Slug: "suspended-1", Status: repository.TenantStatusSuspended}); err != nil {
		t.Fatalf("create suspended: %v", err)
	}

	lister := autopilotTenantLister{tenants: repo}
	ids, err := lister.ListActiveTenantIDs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 1 || ids[0] != active.ID {
		t.Fatalf("active ids = %v, want [%s] (suspended excluded)", ids, active.ID)
	}
}

func TestRolloutAuditSinkAppends(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	audit := memory.NewAuditLogRepository(store)
	sink := newRolloutAuditSink(audit, slog.Default())
	ctx := context.Background()
	created, err := memory.NewTenantRepository(store).Create(ctx, repository.Tenant{Slug: "audit-tenant"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenant := created.ID

	sink.OnTransition(ctx, rollout.Record{
		TenantID:   tenant,
		Capability: rollout.CapabilityIDPDirectorySync,
		State:      rollout.StateEnforce,
		UpdatedBy:  rollout.AutopilotActor,
		Reason:     "guardrails held across dwell window",
	}, rollout.StateMonitor)

	page, err := audit.List(ctx, tenant, repository.AuditFilter{}, repository.Page{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(page.Items))
	}
	got := page.Items[0]
	if got.Action != "rollout.transition.enforce" {
		t.Fatalf("action = %q, want rollout.transition.enforce", got.Action)
	}
	if got.ResourceType != "capability_rollout" {
		t.Fatalf("resource type = %q, want capability_rollout", got.ResourceType)
	}
	if got.TenantID != tenant {
		t.Fatalf("tenant = %s, want %s", got.TenantID, tenant)
	}
}

func TestNewAutopilotObserverNilMetrics(t *testing.T) {
	t.Parallel()
	if _, ok := newAutopilotObserver(nil).(rollout.NoopAutopilotObserver); !ok {
		t.Fatal("nil metrics must yield the no-op observer")
	}
}

func TestNewAutopilotObserverLiveMetrics(t *testing.T) {
	t.Parallel()
	mx := metrics.New(config.Metrics{Namespace: "sng_test", Enabled: true})
	obs := newAutopilotObserver(mx)
	if _, ok := obs.(rollout.NoopAutopilotObserver); ok {
		t.Fatal("live metrics must yield the metrics-backed observer")
	}
	// Exercise every path; a mislabelled vector would panic here.
	obs.Enrolled(rollout.CapabilityIDPDirectorySync)
	obs.Promoted(rollout.CapabilityIDPDirectorySync)
	obs.Demoted(rollout.CapabilityIDPDirectorySync)
	obs.PromotionBlocked(rollout.CapabilityIDPDirectorySync, "guardrail")
}
