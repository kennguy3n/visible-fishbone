package nats_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
)

func TestTenantPartitioner_SingleCellDisablesFanOut(t *testing.T) {
	t.Parallel()
	for _, n := range []int{-3, 0, 1} {
		tp := sngnats.NewTenantPartitioner(n)
		if tp.Count() != 1 {
			t.Errorf("NewTenantPartitioner(%d).Count() = %d, want 1", n, tp.Count())
		}
		if tp.Enabled() {
			t.Errorf("NewTenantPartitioner(%d).Enabled() = true, want false", n)
		}
		if got := tp.Partition("any-tenant"); got != 0 {
			t.Errorf("single-cell Partition = %d, want 0", got)
		}
		// Unpartitioned subject shape (historical layout).
		if got, want := tp.SubjectForTenant("abc", "flow"), "sng.abc.telemetry.flow"; got != want {
			t.Errorf("SubjectForTenant = %q, want %q", got, want)
		}
	}
}

func TestTenantPartitioner_Deterministic(t *testing.T) {
	t.Parallel()
	tp := sngnats.NewTenantPartitioner(8)
	if !tp.Enabled() {
		t.Fatal("Enabled() = false, want true for 8 cells")
	}
	tenant := uuid.NewString()
	first := tp.Partition(tenant)
	for i := 0; i < 100; i++ {
		if got := tp.Partition(tenant); got != first {
			t.Fatalf("Partition not deterministic: got %d then %d", first, got)
		}
	}
	if first < 0 || first >= 8 {
		t.Fatalf("Partition out of range: %d", first)
	}
}

func TestTenantPartitioner_PartitionedSubjectMatchesFilter(t *testing.T) {
	t.Parallel()
	tp := sngnats.NewTenantPartitioner(8)
	tenant := uuid.NewString()
	p := tp.Partition(tenant)

	subject := tp.SubjectForTenant(tenant, "flow")
	wantSubject := fmt.Sprintf("sng.%d.%s.telemetry.flow", p, tenant)
	if subject != wantSubject {
		t.Errorf("SubjectForTenant = %q, want %q", subject, wantSubject)
	}
	// The per-cell consumer filter must structurally cover the
	// published subject: sng.<p>.*.telemetry.>
	wantFilter := fmt.Sprintf("sng.%d.*.telemetry.>", p)
	if got := sngnats.TelemetryPartitionSubject(p); got != wantFilter {
		t.Errorf("TelemetryPartitionSubject(%d) = %q, want %q", p, got, wantFilter)
	}
	if got, want := sngnats.TelemetryPartitionStreamSuffix(p), fmt.Sprintf("TELEMETRY_%d", p); got != want {
		t.Errorf("TelemetryPartitionStreamSuffix(%d) = %q, want %q", p, got, want)
	}
}

// TestTenantPartitioner_DistributionSpread guards against a
// degenerate hash that piles every tenant into one cell: across many
// random tenants every one of the 8 cells must receive at least one.
func TestTenantPartitioner_DistributionSpread(t *testing.T) {
	t.Parallel()
	const cells = 8
	tp := sngnats.NewTenantPartitioner(cells)
	seen := make(map[int]int)
	for i := 0; i < 5000; i++ {
		p := tp.Partition(uuid.NewString())
		if p < 0 || p >= cells {
			t.Fatalf("partition %d out of range [0,%d)", p, cells)
		}
		seen[p]++
	}
	if len(seen) != cells {
		t.Fatalf("expected all %d cells populated, got %d: %v", cells, len(seen), seen)
	}
}

func TestPartitionerFromConfig(t *testing.T) {
	t.Parallel()
	if got := sngnats.PartitionerFromConfig(nil).Count(); got != 1 {
		t.Errorf("nil config Count = %d, want 1", got)
	}
	if got := sngnats.PartitionerFromConfig(&config.NATS{Partitions: 16}).Count(); got != 16 {
		t.Errorf("Count = %d, want 16", got)
	}
}

func TestDefaultStreams_PartitionedFanOut(t *testing.T) {
	t.Parallel()
	cfg := defaultNATSConfig()
	cfg.Partitions = 4
	specs := sngnats.DefaultStreams(cfg)

	// 4 telemetry partition streams + policy + events + dlq.
	telemetry := map[string]string{}
	for _, s := range specs {
		if len(s.Subjects) == 1 && len(s.Name) >= len("TEST_TELEMETRY_") && s.Name[:len("TEST_TELEMETRY_")] == "TEST_TELEMETRY_" {
			telemetry[s.Name] = s.Subjects[0]
		}
	}
	if len(telemetry) != 4 {
		t.Fatalf("expected 4 partitioned telemetry streams, got %d: %v", len(telemetry), telemetry)
	}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("TEST_TELEMETRY_%d", i)
		want := fmt.Sprintf("sng.%d.*.telemetry.>", i)
		if got, ok := telemetry[name]; !ok || got != want {
			t.Errorf("stream %s subject = %q (present=%v), want %q", name, got, ok, want)
		}
	}
	// The unpartitioned single stream must NOT be present in fan-out mode.
	for _, s := range specs {
		if s.Name == "TEST_TELEMETRY" {
			t.Errorf("unpartitioned TEST_TELEMETRY present alongside partitioned streams")
		}
	}
}
