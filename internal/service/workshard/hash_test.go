package workshard

import (
	"math/rand"
	"testing"

	"github.com/google/uuid"
)

func TestShardIndexInRangeAndDeterministic(t *testing.T) {
	t.Parallel()
	const n = 256
	for i := 0; i < 10000; i++ {
		id := uuid.New()
		s1 := shardIndex(id, n)
		s2 := shardIndex(id, n)
		if s1 != s2 {
			t.Fatalf("shardIndex not deterministic for %s: %d vs %d", id, s1, s2)
		}
		if s1 < 0 || s1 >= n {
			t.Fatalf("shard %d out of range [0,%d)", s1, n)
		}
	}
}

func TestShardIndexCollapsesToZero(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1} {
		for i := 0; i < 100; i++ {
			if got := shardIndex(uuid.New(), n); got != 0 {
				t.Fatalf("shardCount=%d should map all tenants to 0, got %d", n, got)
			}
		}
	}
}

func TestHRWSingleWorkerOwnsAll(t *testing.T) {
	t.Parallel()
	me := uuid.New()
	got := ownedShards(64, []uuid.UUID{me}, me)
	if len(got) != 64 {
		t.Fatalf("single worker must own all 64 shards, got %d", len(got))
	}
}

func TestHRWWinnerOrderIndependent(t *testing.T) {
	t.Parallel()
	workers := make([]uuid.UUID, 7)
	for i := range workers {
		workers[i] = uuid.New()
	}
	rng := rand.New(rand.NewSource(1))
	for shard := 0; shard < 512; shard++ {
		want := hrwWinner(shard, workers)
		// Shuffle a copy and recompute; the winner must not depend on
		// the order workers appear in.
		shuffled := append([]uuid.UUID(nil), workers...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := hrwWinner(shard, shuffled); got != want {
			t.Fatalf("shard %d: winner depends on order (%s vs %s)", shard, want, got)
		}
	}
}

func TestHRWBalance(t *testing.T) {
	t.Parallel()
	const (
		shardCount = 1024
		nWorkers   = 8
	)
	workers := make([]uuid.UUID, nWorkers)
	for i := range workers {
		workers[i] = uuid.New()
	}
	counts := map[uuid.UUID]int{}
	for shard := 0; shard < shardCount; shard++ {
		counts[hrwWinner(shard, workers)]++
	}
	// Every worker should get a non-trivial slice; assert each is within
	// a generous band around the fair share (shardCount/nWorkers = 128).
	fair := shardCount / nWorkers
	for w, c := range counts {
		if c < fair/2 || c > fair*2 {
			t.Errorf("worker %s owns %d shards, outside [%d,%d] band", w, c, fair/2, fair*2)
		}
	}
	if len(counts) != nWorkers {
		t.Fatalf("expected all %d workers to own shards, got %d", nWorkers, len(counts))
	}
}

// TestHRWMinimalMovementOnAdd verifies the rendezvous property that adding
// a worker only steals shards onto the newcomer — it never reshuffles a
// shard between two pre-existing workers.
func TestHRWMinimalMovementOnAdd(t *testing.T) {
	t.Parallel()
	const shardCount = 1024
	base := make([]uuid.UUID, 5)
	for i := range base {
		base[i] = uuid.New()
	}
	before := make([]uuid.UUID, shardCount)
	for s := 0; s < shardCount; s++ {
		before[s] = hrwWinner(s, base)
	}

	added := uuid.New()
	grown := append(append([]uuid.UUID(nil), base...), added)
	moved := 0
	for s := 0; s < shardCount; s++ {
		after := hrwWinner(s, grown)
		if after != before[s] {
			moved++
			if after != added {
				t.Fatalf("shard %d moved between existing workers (%s -> %s); rendezvous must only steal onto the newcomer",
					s, before[s], after)
			}
		}
	}
	if moved == 0 {
		t.Fatalf("adding a worker should move some shards, moved 0")
	}
}

// TestHRWMinimalMovementOnRemove verifies that removing a worker only
// moves that worker's shards — shards owned by survivors are untouched.
func TestHRWMinimalMovementOnRemove(t *testing.T) {
	t.Parallel()
	const shardCount = 1024
	workers := make([]uuid.UUID, 6)
	for i := range workers {
		workers[i] = uuid.New()
	}
	before := make([]uuid.UUID, shardCount)
	for s := 0; s < shardCount; s++ {
		before[s] = hrwWinner(s, workers)
	}

	removed := workers[3]
	remaining := append(append([]uuid.UUID(nil), workers[:3]...), workers[4:]...)
	for s := 0; s < shardCount; s++ {
		after := hrwWinner(s, remaining)
		if before[s] != removed && after != before[s] {
			t.Fatalf("shard %d owned by surviving worker %s moved to %s on unrelated removal",
				s, before[s], after)
		}
		if after == removed {
			t.Fatalf("shard %d still assigned to removed worker", s)
		}
	}
}
