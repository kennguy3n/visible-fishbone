package main

import (
	"strings"
	"testing"
)

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
	for _, want := range []string{"Capacity plan @ 5000 tenants", "Postgres connection-pool pressure", "ClickHouse write throughput", "NATS subject cardinality", "Periodic per-tenant sweep cost"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
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
