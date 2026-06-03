package clickhouse

import (
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/stats"
)

func TestShardIndex_DeterministicAndInRange(t *testing.T) {
	t.Parallel()
	const shards = 4
	tenant := uuid.New()
	first := shardIndex(tenant, shards)
	for i := 0; i < 50; i++ {
		if got := shardIndex(tenant, shards); got != first {
			t.Fatalf("shardIndex not deterministic: %d then %d", first, got)
		}
	}
	if first < 0 || first >= shards {
		t.Fatalf("shardIndex out of range: %d", first)
	}
}

func TestShardIndex_SingleShard(t *testing.T) {
	t.Parallel()
	for _, n := range []int{-1, 0, 1} {
		if got := shardIndex(uuid.New(), n); got != 0 {
			t.Errorf("shardIndex(_, %d) = %d, want 0", n, got)
		}
	}
}

func TestShardIndex_DistributionSpread(t *testing.T) {
	t.Parallel()
	const shards = 4
	seen := make(map[int]int)
	for i := 0; i < 4000; i++ {
		p := shardIndex(uuid.New(), shards)
		if p < 0 || p >= shards {
			t.Fatalf("shard %d out of range", p)
		}
		seen[p]++
	}
	if len(seen) != shards {
		t.Fatalf("expected all %d shards populated, got %d: %v", shards, len(seen), seen)
	}
}

func TestMergeTrafficClassCounts_SumsAndOrders(t *testing.T) {
	t.Parallel()
	perShard := [][]stats.TrafficClassCount{
		{
			{Class: "inspect_full", Events: 10, Bytes: 100},
			{Class: "block", Events: 5, Bytes: 0},
		},
		{
			{Class: "inspect_full", Events: 7, Bytes: 50},
			{Class: "trusted_direct", Events: 20, Bytes: 2000},
		},
	}
	got := mergeTrafficClassCounts(perShard)

	want := map[string]stats.TrafficClassCount{
		"inspect_full":   {Class: "inspect_full", Events: 17, Bytes: 150},
		"block":          {Class: "block", Events: 5, Bytes: 0},
		"trusted_direct": {Class: "trusted_direct", Events: 20, Bytes: 2000},
	}
	if len(got) != len(want) {
		t.Fatalf("merged len = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, row := range got {
		w, ok := want[row.Class]
		if !ok {
			t.Errorf("unexpected class %q", row.Class)
			continue
		}
		if row.Events != w.Events || row.Bytes != w.Bytes {
			t.Errorf("class %q = {events:%d bytes:%d}, want {events:%d bytes:%d}",
				row.Class, row.Events, row.Bytes, w.Events, w.Bytes)
		}
	}
	// Ordered by events desc: trusted_direct(20) > inspect_full(17) > block(5).
	if got[0].Class != "trusted_direct" || got[1].Class != "inspect_full" || got[2].Class != "block" {
		t.Errorf("ordering wrong: %v", got)
	}
}

func TestMergeTrafficClassCounts_Empty(t *testing.T) {
	t.Parallel()
	if got := mergeTrafficClassCounts(nil); got != nil {
		t.Errorf("merge(nil) = %v, want nil", got)
	}
	if got := mergeTrafficClassCounts([][]stats.TrafficClassCount{{}, {}}); got != nil {
		t.Errorf("merge of empty shards = %v, want nil", got)
	}
}

func TestNewShardedWriter_RequiresEndpoint(t *testing.T) {
	t.Parallel()
	_, err := NewShardedWriter(t.Context(), Config{}, nil)
	if err == nil {
		t.Fatal("expected error when no endpoints configured")
	}
}
