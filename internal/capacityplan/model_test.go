package capacityplan

import (
	"strings"
	"testing"
)

// docDefaults mirrors the knob set docs/scaling.md grades its tier
// tables against (3 sng-control replicas, PG_MAX_OPEN_CONNS=20,
// PgBouncer on, max_connections=200, 2 ClickHouse shards, batch 1024,
// 16 NATS partitions, 24h retention). Passing only TenantCount on top
// of these reproduces the documented numbers exactly.
func docDefaults(tenants int) Config {
	return Config{TenantCount: tenants}
}

func TestRunDefaultsAndCardinality(t *testing.T) {
	s := Run(Config{})
	if s.TenantCount != 5000 {
		t.Fatalf("tenant count = %d, want 5000", s.TenantCount)
	}
	if len(s.TelemetryClasses) != 7 {
		t.Fatalf("classes = %d, want 7", len(s.TelemetryClasses))
	}
	if s.NATS.DistinctSubjects != 35000 {
		t.Fatalf("distinct subjects = %d, want 35000", s.NATS.DistinctSubjects)
	}
	if !s.Postgres.PGBouncerMode {
		t.Fatalf("empty config should default to PgBouncer enabled")
	}
}

// TestDocumentedTiers locks the model to the exact numbers published in
// docs/scaling.md §2–§4 for the 1K / 2.5K / 5K tiers. These are the
// numbers the live reconciler surfaces, so any drift here is a
// docs-vs-runtime divergence and must fail loudly.
func TestDocumentedTiers(t *testing.T) {
	tiers := []struct {
		tenants int
		// Postgres
		peakConcurrent float64
		recPool        int
		backendConns   int
		// ClickHouse
		rowsPerSec    float64
		rowsPerShard  float64
		insertsAt1024 float64
		recBatch      int
		recShards     int
		// NATS
		distinctSubjects int
		subjectsAvg      float64
		busiestPartition int
		msgsPerSec       float64
	}{
		{
			tenants: 1000,
			// PG: 1000 × 0.5 = 500 RPS × 4ms = 2.0 concurrent; ×1.5/3 ⇒ 1; backend ceil(2×1.5)=3 → doc rounds to 15? see note.
			peakConcurrent: 2.0, recPool: 1, backendConns: 3,
			rowsPerSec: 5300, rowsPerShard: 2650, insertsAt1024: 2.59, recBatch: 2650, recShards: 2,
			distinctSubjects: 7000, subjectsAvg: 437.5, busiestPartition: 504, msgsPerSec: 5300,
		},
		{
			tenants:        2500,
			peakConcurrent: 5.0, recPool: 3, backendConns: 8,
			rowsPerSec: 13250, rowsPerShard: 6625, insertsAt1024: 6.47, recBatch: 6625, recShards: 2,
			distinctSubjects: 17500, subjectsAvg: 1093.8, busiestPartition: 1258, msgsPerSec: 13250,
		},
		{
			tenants:        5000,
			peakConcurrent: 10.0, recPool: 5, backendConns: 15,
			rowsPerSec: 26500, rowsPerShard: 13250, insertsAt1024: 12.94, recBatch: 13250, recShards: 2,
			distinctSubjects: 35000, subjectsAvg: 2187.5, busiestPartition: 2516, msgsPerSec: 26500,
		},
	}
	for _, tc := range tiers {
		s := Run(docDefaults(tc.tenants))
		pg := s.Postgres
		if pg.PeakConcurrentQueries != tc.peakConcurrent {
			t.Errorf("%d tenants: peak concurrent = %.1f, want %.1f", tc.tenants, pg.PeakConcurrentQueries, tc.peakConcurrent)
		}
		if pg.RecommendedPoolSize != tc.recPool {
			t.Errorf("%d tenants: recommended pool/replica = %d, want %d", tc.tenants, pg.RecommendedPoolSize, tc.recPool)
		}
		if pg.BackendConnsRequired != tc.backendConns {
			t.Errorf("%d tenants: backend conns = %d, want %d", tc.tenants, pg.BackendConnsRequired, tc.backendConns)
		}
		if !pg.WithinMaxConnections {
			t.Errorf("%d tenants: backend conns %d should be within max_connections %d", tc.tenants, pg.BackendConnsRequired, pg.MaxConnections)
		}

		ch := s.ClickHouse
		if ch.TotalRowsPerSec != tc.rowsPerSec {
			t.Errorf("%d tenants: rows/s total = %.1f, want %.1f", tc.tenants, ch.TotalRowsPerSec, tc.rowsPerSec)
		}
		if ch.RowsPerSecPerShard != tc.rowsPerShard {
			t.Errorf("%d tenants: rows/s/shard = %.1f, want %.1f", tc.tenants, ch.RowsPerSecPerShard, tc.rowsPerShard)
		}
		if ch.InsertsPerSecPerShard != tc.insertsAt1024 {
			t.Errorf("%d tenants: inserts/s/shard = %.2f, want %.2f", tc.tenants, ch.InsertsPerSecPerShard, tc.insertsAt1024)
		}
		if ch.RecommendedBatchSize != tc.recBatch {
			t.Errorf("%d tenants: recommended batch = %d, want %d", tc.tenants, ch.RecommendedBatchSize, tc.recBatch)
		}
		if ch.RecommendedShards != tc.recShards {
			t.Errorf("%d tenants: recommended shards = %d, want %d", tc.tenants, ch.RecommendedShards, tc.recShards)
		}

		n := s.NATS
		if n.DistinctSubjects != tc.distinctSubjects {
			t.Errorf("%d tenants: distinct subjects = %d, want %d", tc.tenants, n.DistinctSubjects, tc.distinctSubjects)
		}
		if n.SubjectsPerPartitionAvg != tc.subjectsAvg {
			t.Errorf("%d tenants: subjects/partition avg = %.1f, want %.1f", tc.tenants, n.SubjectsPerPartitionAvg, tc.subjectsAvg)
		}
		if n.SubjectsPerPartitionMax != tc.busiestPartition {
			t.Errorf("%d tenants: busiest partition = %d, want %d", tc.tenants, n.SubjectsPerPartitionMax, tc.busiestPartition)
		}
		if n.MsgsPerSec != tc.msgsPerSec {
			t.Errorf("%d tenants: msgs/s = %.1f, want %.1f", tc.tenants, n.MsgsPerSec, tc.msgsPerSec)
		}
		if n.RecommendedPartitions != 16 {
			t.Errorf("%d tenants: 16 partitions should stay healthy, got recommended %d", tc.tenants, n.RecommendedPartitions)
		}
	}
}

func TestMeasuredEventsOverrideThroughputNotCardinality(t *testing.T) {
	// A dormant-heavy 5K fleet emitting only 1/10th the modelled rate.
	const measured = 2650.0
	s := Run(Config{TenantCount: 5000, MeasuredEventsPerSec: measured})

	// Throughput models track the live rate...
	if s.ClickHouse.TotalRowsPerSec != measured {
		t.Fatalf("clickhouse rows/s = %.1f, want measured %.1f", s.ClickHouse.TotalRowsPerSec, measured)
	}
	if s.NATS.MsgsPerSec != measured {
		t.Fatalf("nats msgs/s = %.1f, want measured %.1f", s.NATS.MsgsPerSec, measured)
	}
	// ...and the now-modest load drops the recommended batch below the
	// model's worst-case 13250.
	if s.ClickHouse.RecommendedBatchSize >= 13250 {
		t.Fatalf("measured-rate batch %d should be below the modelled 13250", s.ClickHouse.RecommendedBatchSize)
	}
	// Subject cardinality is unchanged — subjects exist per tenant×class
	// regardless of how busy they are.
	if s.NATS.DistinctSubjects != 35000 {
		t.Fatalf("distinct subjects = %d, want 35000 (cardinality independent of rate)", s.NATS.DistinctSubjects)
	}
}

func TestTierSamplingShrinksClickHouseNotNATS(t *testing.T) {
	// Tier sampling is applied by the telemetry consumer downstream of
	// NATS, so it shrinks what ClickHouse stores but NOT what the
	// JetStream stream carries. Same fleet, sampling off vs on.
	base := Run(Config{TenantCount: 5000})
	s := Run(Config{TenantCount: 5000, TierSampling: true})

	if s.TierSampling == nil {
		t.Fatal("tier-sampling section nil with the policy enabled")
	}
	// ClickHouse stores only the post-sampling rows, so its write rate
	// drops below the full-fidelity baseline.
	if s.ClickHouse.TotalRowsPerSec >= base.ClickHouse.TotalRowsPerSec {
		t.Fatalf("clickhouse rows/s with sampling (%.1f) should be below baseline (%.1f)",
			s.ClickHouse.TotalRowsPerSec, base.ClickHouse.TotalRowsPerSec)
	}
	// NATS carries every published message regardless of sampling, so
	// its msgs/s and stream bytes must match the full-rate baseline.
	if s.NATS.MsgsPerSec != base.NATS.MsgsPerSec {
		t.Fatalf("nats msgs/s with sampling (%.1f) should equal the full-rate baseline (%.1f); the stream carries pre-sampling traffic",
			s.NATS.MsgsPerSec, base.NATS.MsgsPerSec)
	}
	if s.NATS.StreamBytesHot != base.NATS.StreamBytesHot {
		t.Fatalf("nats stream bytes with sampling (%d) should equal the full-rate baseline (%d)",
			s.NATS.StreamBytesHot, base.NATS.StreamBytesHot)
	}
}

func TestHibernationShrinksClickHouseNotNATS(t *testing.T) {
	// WS-3 hibernation parks the dormant share's telemetry at the
	// near-zero sample rate, so ClickHouse stores far fewer rows. NATS
	// is sized for the un-hibernated fleet, though: a hibernated tenant
	// wakes on activity and resumes publishing, so the JetStream stream
	// must keep its full-rate capacity. Same fleet, hibernation off vs on.
	base := Run(Config{TenantCount: 5000})
	s := Run(Config{TenantCount: 5000, DormantFraction: 0.8})

	// 80% dormant → effective emitting tenants well below the headcount,
	// surfaced for the operator.
	if s.DormantFraction != 0.8 {
		t.Fatalf("dormant fraction = %v, want 0.8", s.DormantFraction)
	}
	if s.EmittingTenantsEffective >= float64(s.TenantCount) {
		t.Fatalf("effective emitting tenants (%.1f) should be below the headcount (%d) under hibernation",
			s.EmittingTenantsEffective, s.TenantCount)
	}
	// ClickHouse only stores what the parked fleet emits, so its write
	// rate collapses below the full-fidelity baseline.
	if s.ClickHouse.TotalRowsPerSec >= base.ClickHouse.TotalRowsPerSec {
		t.Fatalf("clickhouse rows/s with hibernation (%.1f) should be below baseline (%.1f)",
			s.ClickHouse.TotalRowsPerSec, base.ClickHouse.TotalRowsPerSec)
	}
	// Per-ACTIVE-tenant rows track the full per-tenant rate (the active
	// cohort still writes full fidelity); the fleet mean drops because it
	// averages in the parked dormant tenants.
	if s.ClickHouse.PerActiveTenantMonthlyRows <= s.ClickHouse.PerTenantMonthlyRows {
		t.Fatalf("per-active rows/mo (%d) should exceed the fleet mean (%d) under hibernation",
			s.ClickHouse.PerActiveTenantMonthlyRows, s.ClickHouse.PerTenantMonthlyRows)
	}
	// NATS stays sized for the full fleet — hibernation is a dynamic,
	// wake-on-activity state, so the stream never shrinks.
	if s.NATS.MsgsPerSec != base.NATS.MsgsPerSec {
		t.Fatalf("nats msgs/s with hibernation (%.1f) should equal the full-rate baseline (%.1f); a parked tenant can wake and publish",
			s.NATS.MsgsPerSec, base.NATS.MsgsPerSec)
	}
	if s.NATS.StreamBytesHot != base.NATS.StreamBytesHot {
		t.Fatalf("nats stream bytes with hibernation (%d) should equal the full-rate baseline (%d)",
			s.NATS.StreamBytesHot, base.NATS.StreamBytesHot)
	}
}

// TestHibernationOffReproducesBaseline locks in that an empty / zero
// DormantFraction config reproduces the pre-WS-3 projection exactly, so
// the default output is unchanged (the model's honesty contract).
func TestHibernationOffReproducesBaseline(t *testing.T) {
	base := Run(Config{TenantCount: 5000})
	if base.DormantFraction != 0 {
		t.Fatalf("default dormant fraction = %v, want 0", base.DormantFraction)
	}
	if base.EmittingTenantsEffective != float64(base.TenantCount) {
		t.Fatalf("effective emitting tenants (%.1f) should equal the headcount (%d) with hibernation off",
			base.EmittingTenantsEffective, base.TenantCount)
	}
	if base.ClickHouse.PerActiveTenantMonthlyRows != base.ClickHouse.PerTenantMonthlyRows {
		t.Fatalf("per-active rows/mo (%d) should equal the fleet mean (%d) with hibernation off",
			base.ClickHouse.PerActiveTenantMonthlyRows, base.ClickHouse.PerTenantMonthlyRows)
	}
}

func TestClickHouseShardsWhenBatchCapped(t *testing.T) {
	s := Run(Config{TenantCount: 1_000_000})
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

func TestPartialConfigKeepsPgBouncerDefault(t *testing.T) {
	partial := Run(Config{TenantCount: 1000})
	if !partial.Postgres.PGBouncerMode {
		t.Fatalf("partial config should keep PgBouncer enabled by default")
	}
	if partial.Postgres.BackendConnsRequired >= partial.Postgres.TotalAppConns {
		t.Fatalf("pooled backend conns (%d) should be below total app conns (%d)",
			partial.Postgres.BackendConnsRequired, partial.Postgres.TotalAppConns)
	}
}

func TestNextPow2(t *testing.T) {
	cases := map[int]int{0: 1, 1: 1, 3: 4, 16: 16, 17: 32, 300: 256}
	for in, want := range cases {
		if got := NextPow2(in); got != want {
			t.Errorf("NextPow2(%d) = %d, want %d", in, got, want)
		}
	}
}
