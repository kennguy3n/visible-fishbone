package main

import (
	"strings"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/capacityplan"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy/hibernation"
)

// TestHibernatedSampleRateMatchesService guards against silent drift
// between the capacity model's DefaultHibernatedSampleRate and the
// control-plane sampler's. The capacityplan package deliberately
// re-declares the constant to stay free of any service-layer import;
// this test-only import keeps that decoupling while still failing CI if
// the two values diverge.
func TestHibernatedSampleRateMatchesService(t *testing.T) {
	if capacityplan.DefaultHibernatedSampleRate != hibernation.DefaultHibernatedSampleRate {
		t.Fatalf("capacityplan.DefaultHibernatedSampleRate (%v) drifted from hibernation.DefaultHibernatedSampleRate (%v); keep them in lock-step",
			capacityplan.DefaultHibernatedSampleRate, hibernation.DefaultHibernatedSampleRate)
	}
}

// TestCapacityPlanIdleMultiplierTracksRuntime guards against the
// capacity model's idle keep fraction silently drifting from the runtime
// sampler default. The model's default lives in internal/capacityplan
// (unexported) and the runtime default in internal/service/telemetry on
// purpose — the bench is an analytical projection, not a runtime import
// in its hot path — so this test, not a shared symbol, is what keeps the
// capacity projection honest about what the deployed sampler actually
// does. It reads the model's applied default through the public API (the
// idle multiplier withDefaults fills when TierSampling is on). If the
// runtime default changes, update the model default (and the calibrated
// expectations in the tier-sampling tests) to match.
func TestCapacityPlanIdleMultiplierTracksRuntime(t *testing.T) {
	ts := RunCapacityPlan(CapacityPlanConfig{TierSampling: true}).TierSampling
	if ts == nil {
		t.Fatal("TierSampling section nil with the policy enabled")
	}
	if ts.IdleSampleMultiplier != telemetry.DefaultIdleSampleMultiplier {
		t.Fatalf("capacity model idle multiplier = %v, runtime telemetry.DefaultIdleSampleMultiplier = %v; the bench projection has drifted from the deployed sampler",
			ts.IdleSampleMultiplier, telemetry.DefaultIdleSampleMultiplier)
	}
}

func TestCapacityPlanDefaultsAndCardinality(t *testing.T) {
	s := RunCapacityPlan(CapacityPlanConfig{})
	if s.TenantCount != 5000 {
		t.Fatalf("tenant count = %d, want 5000", s.TenantCount)
	}
	if len(s.TelemetryClasses) != 7 {
		t.Fatalf("classes = %d, want 7", len(s.TelemetryClasses))
	}
	// 5000 tenants × 7 classes = 35,000 distinct subjects.
	if s.NATS.DistinctSubjects != 35000 {
		t.Fatalf("distinct subjects = %d, want 35000", s.NATS.DistinctSubjects)
	}
	// Busiest partition must be at least the even average and never
	// exceed the whole set.
	if float64(s.NATS.SubjectsPerPartitionMax) < s.NATS.SubjectsPerPartitionAvg {
		t.Fatalf("max %d below avg %.1f", s.NATS.SubjectsPerPartitionMax, s.NATS.SubjectsPerPartitionAvg)
	}
	if s.NATS.SubjectsPerPartitionMax > s.NATS.DistinctSubjects {
		t.Fatalf("max per partition %d exceeds total %d", s.NATS.SubjectsPerPartitionMax, s.NATS.DistinctSubjects)
	}
	// An empty config must inherit the documented default knobs, including
	// PgBouncer enabled — withDefaults cannot rely on the bool zero value
	// to express "enabled", so this guards that the tri-state default is
	// actually applied (regression for the partial-config bug).
	if !s.Postgres.PGBouncerMode {
		t.Fatalf("empty config should default to PgBouncer enabled, got disabled")
	}
}

func TestCapacityPlanPartialConfigKeepsPgBouncerDefault(t *testing.T) {
	// A partial config that only sets TenantCount must still pick up the
	// PgBouncer default. With a bare bool this silently modelled the
	// fleet without pooling; the tri-state pointer fixes it.
	partial := RunCapacityPlan(CapacityPlanConfig{TenantCount: 1000})
	if !partial.Postgres.PGBouncerMode {
		t.Fatalf("partial config should keep PgBouncer enabled by default")
	}
	// Pooling must actually take effect: the backend needs fewer conns
	// than the summed app pools.
	if partial.Postgres.BackendConnsRequired >= partial.Postgres.TotalAppConns {
		t.Fatalf("pooled backend conns (%d) should be below total app conns (%d)",
			partial.Postgres.BackendConnsRequired, partial.Postgres.TotalAppConns)
	}
}

func TestCapacityPlanSinglePartitionNoSkew(t *testing.T) {
	s := RunCapacityPlan(CapacityPlanConfig{NATSPartitions: 1})
	if s.NATS.SubjectsPerPartitionMax != s.NATS.DistinctSubjects {
		t.Fatalf("single partition should hold all subjects: max=%d distinct=%d",
			s.NATS.SubjectsPerPartitionMax, s.NATS.DistinctSubjects)
	}
}

func TestCapacityPlanClickHouseRecommendsBatchBeforeShards(t *testing.T) {
	// Default 5k-tenant load is ~13 inserts/s/shard at batch 1024: the
	// fix is a bigger batch (within the cap), NOT more shards.
	s := RunCapacityPlan(CapacityPlanConfig{})
	ch := s.ClickHouse
	if ch.InsertsPerSecPerShard <= 1.0 {
		t.Fatalf("expected the default load to exceed 1 insert/s/shard, got %.2f", ch.InsertsPerSecPerShard)
	}
	if ch.RecommendedBatchSize <= ch.BatchSize {
		t.Fatalf("recommended batch %d should exceed current %d", ch.RecommendedBatchSize, ch.BatchSize)
	}
	if ch.RecommendedShards != ch.Shards {
		t.Fatalf("batch should absorb the load without resharding: shards %d -> %d", ch.Shards, ch.RecommendedShards)
	}
	if !strings.Contains(ch.Note, "CLICKHOUSE_BATCH_SIZE") {
		t.Fatalf("note should advise raising the batch size: %q", ch.Note)
	}
}

func TestCapacityPlanClickHouseShardsWhenBatchCapped(t *testing.T) {
	// A very large fleet pushes the needed batch past the cap, forcing
	// a shard recommendation.
	s := RunCapacityPlan(CapacityPlanConfig{TenantCount: 1_000_000})
	ch := s.ClickHouse
	if ch.RecommendedShards <= ch.Shards {
		t.Fatalf("huge fleet should require more shards: %d -> %d", ch.Shards, ch.RecommendedShards)
	}
	if ch.RecommendedBatchSize != 65536 {
		t.Fatalf("batch should be pinned to the cap when sharding: %d", ch.RecommendedBatchSize)
	}
	if !strings.Contains(ch.Note, "CLICKHOUSE_SHARDING") {
		t.Fatalf("note should advise sharding: %q", ch.Note)
	}
}

func TestCapacityPlanClickHouseHealthyAtLowLoad(t *testing.T) {
	// 100 tenants is well within a single shard's healthy envelope.
	s := RunCapacityPlan(CapacityPlanConfig{TenantCount: 100})
	ch := s.ClickHouse
	if ch.InsertsPerSecPerShard > 1.0 {
		t.Fatalf("100 tenants should be under 1 insert/s/shard, got %.2f", ch.InsertsPerSecPerShard)
	}
	if ch.RecommendedShards != ch.Shards || ch.RecommendedBatchSize != ch.BatchSize {
		t.Fatalf("healthy load should not change knobs: %+v", ch)
	}
}

func TestCapacityPlanPostgresPgBouncerReducesBackendConns(t *testing.T) {
	with := RunCapacityPlan(CapacityPlanConfig{PGBouncerMode: boolPtr(true)})
	without := RunCapacityPlan(CapacityPlanConfig{PGBouncerMode: boolPtr(false)})
	if with.Postgres.BackendConnsRequired >= without.Postgres.BackendConnsRequired {
		t.Fatalf("PgBouncer should reduce backend conns: with=%d without=%d",
			with.Postgres.BackendConnsRequired, without.Postgres.BackendConnsRequired)
	}
	// Without PgBouncer the backend must carry the full app-pool sum.
	if without.Postgres.BackendConnsRequired != without.Postgres.TotalAppConns {
		t.Fatalf("without pooling, backend conns (%d) should equal total app conns (%d)",
			without.Postgres.BackendConnsRequired, without.Postgres.TotalAppConns)
	}
}

func TestCapacityPlanPostgresFlagsUndersizedPool(t *testing.T) {
	// A high RPS with a tiny pool should surface a remediation note.
	s := RunCapacityPlan(CapacityPlanConfig{ControlPlaneRPS: 200_000, PGMaxOpenConns: 2, ControlPlaneReplicas: 1})
	if s.Postgres.RecommendedPoolSize <= s.Postgres.PoolSizePerReplica {
		t.Fatalf("recommended pool %d should exceed configured %d", s.Postgres.RecommendedPoolSize, s.Postgres.PoolSizePerReplica)
	}
	if !strings.Contains(s.Postgres.Note, "PG_MAX_OPEN_CONNS") {
		t.Fatalf("note should call out PG_MAX_OPEN_CONNS: %q", s.Postgres.Note)
	}
}

func TestCapacityPlanTierSamplingDefaultOff(t *testing.T) {
	// With the policy off the section is omitted and the ClickHouse
	// projection is the full publish rate — the baseline is untouched.
	s := RunCapacityPlan(CapacityPlanConfig{})
	if s.TierSampling != nil {
		t.Fatal("tier-sampling section should be nil when the policy is off")
	}
	if s.ClickHouse.TotalRowsPerSec != 26500.0 {
		t.Fatalf("baseline rows/s = %.1f, want 26500.0", s.ClickHouse.TotalRowsPerSec)
	}
}

func TestCapacityPlanTierSamplingCollapsesDormantCohort(t *testing.T) {
	s := RunCapacityPlan(CapacityPlanConfig{TierSampling: true})
	ts := s.TierSampling
	if ts == nil {
		t.Fatal("tier-sampling section should be present when enabled")
	}
	// Default NoOps split: 10% active, 15% idle, 75% dormant of 5000.
	if ts.ActiveTenants != 500 || ts.IdleTenants != 750 || ts.DormantTenants != 3750 {
		t.Fatalf("cohort split = %d/%d/%d, want 500/750/3750",
			ts.ActiveTenants, ts.IdleTenants, ts.DormantTenants)
	}
	// Sampled total must be well below baseline and the ClickHouse plan
	// must size against the sampled rate, not the full publish rate.
	if ts.SampledRowsPerSec >= ts.BaselineRowsPerSec {
		t.Fatalf("sampled %.1f should be below baseline %.1f", ts.SampledRowsPerSec, ts.BaselineRowsPerSec)
	}
	if s.ClickHouse.TotalRowsPerSec != ts.SampledRowsPerSec {
		t.Fatalf("ClickHouse total %.1f should equal sampled %.1f",
			s.ClickHouse.TotalRowsPerSec, ts.SampledRowsPerSec)
	}
	if ts.ReductionPct < 50 {
		t.Fatalf("expected a >50%% reduction at the NoOps split, got %.1f%%", ts.ReductionPct)
	}
	// Dormant tenants are 75% of the fleet but write only the
	// security-event floor (ips+ztna = 0.5/s each): 3750 × 0.5 = 1875.
	if ts.DormantRowsPerSec != 1875.0 {
		t.Fatalf("dormant rows/s = %.1f, want 1875.0 (security floor)", ts.DormantRowsPerSec)
	}
}

func TestCapacityPlanTierSamplingPreservesSecurityFloor(t *testing.T) {
	// Even with idle fully shed and the dormant majority, the fleet
	// never drops below the security-event publish rate of the non-active
	// cohorts — security events are never sampled away.
	s := RunCapacityPlan(CapacityPlanConfig{TierSampling: true, IdleSampleMultiplier: 0.0001})
	ts := s.TierSampling
	// active(500)=2650 full; idle≈0; dormant(3750)=1875 security floor.
	if ts.DormantRowsPerSec != 1875.0 {
		t.Fatalf("dormant security floor changed: %.1f, want 1875.0", ts.DormantRowsPerSec)
	}
	if ts.SampledRowsPerSec < ts.ActiveRowsPerSec+ts.DormantRowsPerSec {
		t.Fatalf("sampled total %.1f dropped below active+dormant floor %.1f",
			ts.SampledRowsPerSec, ts.ActiveRowsPerSec+ts.DormantRowsPerSec)
	}
}

func TestCapacityPlanTierSamplingRendersAndRoundTrips(t *testing.T) {
	r := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModeCapacityPlan,
		Theoretical:   DefaultTheoreticalTargets(),
		Competitor:    DefaultCompetitorBaselines(),
		CapacityPlan:  RunCapacityPlan(CapacityPlanConfig{TierSampling: true}),
	}
	r.Grade()
	md := r.ToMarkdown()
	if !strings.Contains(md, "WS-4 activity-tier telemetry sampling") {
		t.Errorf("markdown missing tier-sampling section")
	}
	js, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	got, err := ReportFromJSON(js)
	if err != nil {
		t.Fatalf("ReportFromJSON: %v", err)
	}
	if got.CapacityPlan.TierSampling == nil {
		t.Fatal("tier-sampling section dropped in JSON round-trip")
	}
}

func TestNextPow2(t *testing.T) {
	cases := map[int]int{0: 1, 1: 1, 2: 2, 3: 4, 16: 16, 17: 32, 300: 256}
	for in, want := range cases {
		if got := nextPow2(in); got != want {
			t.Errorf("nextPow2(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestCapacityPlanRendersInMarkdown(t *testing.T) {
	r := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModeCapacityPlan,
		Theoretical:   DefaultTheoreticalTargets(),
		Competitor:    DefaultCompetitorBaselines(),
		CapacityPlan:  RunCapacityPlan(CapacityPlanConfig{}),
	}
	r.Grade()
	md := r.ToMarkdown()
	for _, want := range []string{"Capacity plan @ 5000 tenants", "Postgres connection-pool pressure", "ClickHouse write throughput", "NATS subject cardinality", "AI inference footprint (WS-9 shared pool)", "Periodic per-tenant sweep cost"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

// TestCapacityPlanMarkdownSurfacesPerActiveTenantRows guards the
// hibernation branch of the ClickHouse section: when DormantFraction > 0
// the fleet-average rows/tenant averages in the near-zero parked
// telemetry, so the report must additionally surface the per-active-tenant
// figure (the rate the tenants that still write full fidelity drive). The
// baseline render (no hibernation) must stay on the single-figure line.
func TestCapacityPlanMarkdownSurfacesPerActiveTenantRows(t *testing.T) {
	render := func(cfg CapacityPlanConfig) string {
		r := &BusinessBenchmarkReport{
			SchemaVersion: SchemaVersion,
			Mode:          ModeCapacityPlan,
			Theoretical:   DefaultTheoreticalTargets(),
			Competitor:    DefaultCompetitorBaselines(),
			CapacityPlan:  RunCapacityPlan(cfg),
		}
		r.Grade()
		return r.ToMarkdown()
	}

	hib := render(CapacityPlanConfig{DormantFraction: 0.8})
	if !strings.Contains(hib, "active-tenant") {
		t.Errorf("hibernated render must surface the per-active-tenant rows/month figure; got:\n%s", hib)
	}

	base := render(CapacityPlanConfig{})
	if strings.Contains(base, "active-tenant") {
		t.Errorf("baseline render (no hibernation) must not show the per-active-tenant figure; got:\n%s", base)
	}
}

func TestCapacityPlanRoundTripsThroughJSON(t *testing.T) {
	r := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModeCapacityPlan,
		Theoretical:   DefaultTheoreticalTargets(),
		Competitor:    DefaultCompetitorBaselines(),
		CapacityPlan:  RunCapacityPlan(CapacityPlanConfig{}),
	}
	js, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	got, err := ReportFromJSON(js)
	if err != nil {
		t.Fatalf("ReportFromJSON: %v", err)
	}
	if got.CapacityPlan == nil {
		t.Fatal("capacity plan dropped in round-trip")
	}
	if got.CapacityPlan.NATS.DistinctSubjects != r.CapacityPlan.NATS.DistinctSubjects {
		t.Fatalf("distinct subjects mismatch after round-trip")
	}
	if got.CapacityPlan.PeriodicSweep.ReductionFactor != r.CapacityPlan.PeriodicSweep.ReductionFactor {
		t.Fatalf("sweep reduction factor mismatch after round-trip")
	}
}

func TestCapacityPlanPeriodicSweepDividend(t *testing.T) {
	s := RunCapacityPlan(CapacityPlanConfig{})
	sw := s.PeriodicSweep

	// Default dormant-heavy mix sums to the fleet.
	if sw.ActiveTenants+sw.IdleTenants+sw.DormantTenants != s.TenantCount {
		t.Fatalf("tier breakdown %d+%d+%d != %d",
			sw.ActiveTenants, sw.IdleTenants, sw.DormantTenants, s.TenantCount)
	}
	// Untiered cost is one full fan-out per job.
	if sw.UntieredVisitsPerCyclePerJob != s.TenantCount {
		t.Fatalf("untiered/job = %d, want %d", sw.UntieredVisitsPerCyclePerJob, s.TenantCount)
	}
	// Tiering must strictly reduce per-cycle work and never below the
	// active floor (active tenants are always visited).
	if sw.TieredVisitsPerCyclePerJob >= float64(sw.UntieredVisitsPerCyclePerJob) {
		t.Fatalf("tiered (%.1f) should be below untiered (%d)",
			sw.TieredVisitsPerCyclePerJob, sw.UntieredVisitsPerCyclePerJob)
	}
	if sw.TieredVisitsPerCyclePerJob < float64(sw.ActiveTenants) {
		t.Fatalf("tiered (%.1f) below active floor (%d) — active tenants must always be visited",
			sw.TieredVisitsPerCyclePerJob, sw.ActiveTenants)
	}
	// The headline tail dividends: idle ~10x (every 10th cycle) and
	// dormant ~100x (every 100th), matching the default planner cadence.
	if sw.IdleReductionFactor != 10 {
		t.Fatalf("idle reduction = %.1f, want 10", sw.IdleReductionFactor)
	}
	if sw.DormantReductionFactor != 100 {
		t.Fatalf("dormant reduction = %.1f, want 100", sw.DormantReductionFactor)
	}
	// Aggregate scales with the job count.
	if sw.JobCount < 1 {
		t.Fatalf("expected at least one tiered job, got %d", sw.JobCount)
	}
	if sw.UntieredVisitsPerCycleTotal != sw.UntieredVisitsPerCyclePerJob*sw.JobCount {
		t.Fatalf("aggregate untiered %d != per-job %d × jobs %d",
			sw.UntieredVisitsPerCycleTotal, sw.UntieredVisitsPerCyclePerJob, sw.JobCount)
	}
}

func TestCapacityPlanPeriodicSweepClampsNegativeFraction(t *testing.T) {
	// A stray negative weight in a partially-specified mix must be
	// clamped to 0 so it can never produce a negative tenant count.
	s := RunCapacityPlan(CapacityPlanConfig{
		TenantCount:          1000,
		SweepActiveFraction:  -0.1,
		SweepIdleFraction:    0.5,
		SweepDormantFraction: 0.5,
	})
	sw := s.PeriodicSweep
	if sw.ActiveTenants < 0 || sw.IdleTenants < 0 || sw.DormantTenants < 0 {
		t.Fatalf("negative tenant count after clamp: %d/%d/%d",
			sw.ActiveTenants, sw.IdleTenants, sw.DormantTenants)
	}
	if sw.ActiveTenants != 0 {
		t.Fatalf("clamped active fraction should yield 0 active tenants, got %d", sw.ActiveTenants)
	}
	if sw.ActiveTenants+sw.IdleTenants+sw.DormantTenants != s.TenantCount {
		t.Fatalf("tier breakdown %d+%d+%d != %d after clamp",
			sw.ActiveTenants, sw.IdleTenants, sw.DormantTenants, s.TenantCount)
	}
}

func TestCapacityPlanPeriodicSweepAllActiveNoDividend(t *testing.T) {
	// A fully-active fleet (fail-safe / no dormancy) must show no
	// reduction: every tenant is visited every cycle.
	s := RunCapacityPlan(CapacityPlanConfig{
		TenantCount:          1000,
		SweepActiveFraction:  1,
		SweepIdleFraction:    0,
		SweepDormantFraction: 0,
	})
	sw := s.PeriodicSweep
	if sw.TieredVisitsPerCyclePerJob != 1000 {
		t.Fatalf("all-active tiered/job = %.1f, want 1000", sw.TieredVisitsPerCyclePerJob)
	}
	if sw.ReductionFactor != 1 {
		t.Fatalf("all-active reduction = %.1f, want 1", sw.ReductionFactor)
	}
}
