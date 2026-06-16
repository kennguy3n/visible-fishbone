package workshard

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// testClock is a settable clock shared between a Distributor and the
// memory repository so expiry is fully deterministic (no sleeps).
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Unix(1_700_000_000, 0).UTC()} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newWorker builds a Distributor wired to a shared repo and clock with a
// fixed identity, suitable for driving runCycle directly.
func newWorker(repo *memory.WorkShardRepository, clk *testClock, id uuid.UUID, shardCount int) *Distributor {
	return New(repo,
		WithWorkerID(id),
		WithShardCount(shardCount),
		WithClock(clk.now),
		WithLeaseTTL(20*time.Second),
		WithSafetyMargin(7*time.Second),
		WithConcurrency(8),
	)
}

// settle drives each worker's cycle in a fixed order for n rounds so the
// fleet converges to its rendezvous assignment (a freshly joined worker
// can only reclaim a shard once the prior owner releases it on its own
// next cycle, so a couple of rounds are needed after membership change).
func settle(t *testing.T, n int, workers ...*Distributor) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		for _, w := range workers {
			if err := w.runCycle(ctx); err != nil {
				t.Fatalf("runCycle: %v", err)
			}
		}
	}
}

func ownedSet(d *Distributor) map[int]struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[int]struct{}, len(d.owned))
	for s := range d.owned {
		out[s] = struct{}{}
	}
	return out
}

func TestSingleReplicaOwnsAllShards(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const shards = 32
	d := newWorker(repo, clk, uuid.New(), shards)

	settle(t, 1, d)

	if got := len(ownedSet(d)); got != shards {
		t.Fatalf("single replica must own all %d shards, owns %d", shards, got)
	}
	// Every tenant must be owned by the sole replica.
	for i := 0; i < 1000; i++ {
		if !d.Owns(uuid.New()) {
			t.Fatalf("single replica must own every tenant")
		}
	}
}

func TestOwnsBeforeFirstCycleFailsClosed(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	d := newWorker(repo, clk, uuid.New(), 16)

	if d.Owns(uuid.New()) {
		t.Fatalf("Owns must be false before the first successful cycle")
	}
	if got := d.FilterOwned([]uuid.UUID{uuid.New(), uuid.New()}); got != nil {
		t.Fatalf("FilterOwned must be empty before first cycle, got %v", got)
	}
}

func TestOwnershipFailsClosedAfterValidityLapse(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	d := newWorker(repo, clk, uuid.New(), 16)
	settle(t, 1, d)

	tenant := uuid.New()
	if !d.Owns(tenant) {
		t.Fatalf("sole replica should own the tenant right after a cycle")
	}
	// Advance past the local validity window (ttl-margin = 13s) without
	// running a new cycle: the worker must stop claiming ownership even
	// though the database lease (20s) has not yet expired.
	clk.advance(14 * time.Second)
	if d.Owns(tenant) {
		t.Fatalf("Owns must fail closed once the local validity window lapses")
	}
	if got := d.FilterOwned([]uuid.UUID{tenant}); got != nil {
		t.Fatalf("FilterOwned must be empty after validity lapse, got %v", got)
	}
}

func TestTwoWorkersPartitionShards(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const shards = 64
	a := newWorker(repo, clk, uuid.New(), shards)
	b := newWorker(repo, clk, uuid.New(), shards)

	settle(t, 4, a, b)

	sa, sb := ownedSet(a), ownedSet(b)
	// Disjoint.
	for s := range sa {
		if _, dup := sb[s]; dup {
			t.Fatalf("shard %d owned by both workers", s)
		}
	}
	// Complete: union covers every shard exactly once.
	if len(sa)+len(sb) != shards {
		t.Fatalf("shards not fully partitioned: |A|=%d |B|=%d want sum %d", len(sa), len(sb), shards)
	}
	// Both workers should get a share (HRW balance with 2 workers).
	if len(sa) == 0 || len(sb) == 0 {
		t.Fatalf("expected both workers to own shards, got |A|=%d |B|=%d", len(sa), len(sb))
	}

	// Exactly-once at the tenant level.
	for i := 0; i < 2000; i++ {
		tn := uuid.New()
		oa, ob := a.Owns(tn), b.Owns(tn)
		if oa == ob {
			t.Fatalf("tenant %s owned by both=%v or neither: A=%v B=%v", tn, oa && ob, oa, ob)
		}
	}
}

func TestWorkerDeathReassignsShards(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const shards = 48
	a := newWorker(repo, clk, uuid.New(), shards)
	b := newWorker(repo, clk, uuid.New(), shards)

	settle(t, 4, a, b)
	if len(ownedSet(b)) == 0 {
		t.Fatalf("precondition: B should own some shards")
	}

	// B dies: it stops heartbeating and cycling. Advance past the lease
	// TTL so B's registry row and leases expire.
	clk.advance(25 * time.Second)

	// A runs a cycle: B is no longer live, so A is the HRW winner for
	// every shard and reclaims B's now-expired leases in a single cycle.
	settle(t, 1, a)
	if got := len(ownedSet(a)); got != shards {
		t.Fatalf("after B's death A must own all %d shards, owns %d", shards, got)
	}
}

func TestGracefulHandoffOnJoin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const shards = 64
	a := newWorker(repo, clk, uuid.New(), shards)

	settle(t, 1, a)
	if len(ownedSet(a)) != shards {
		t.Fatalf("A should start owning all shards")
	}

	// B joins; after convergence A must have released the shards B now
	// owns (no shard is held by two workers in the lease ledger).
	b := newWorker(repo, clk, uuid.New(), shards)
	settle(t, 4, a, b)

	leases, err := repo.ListLeases(ctx)
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	owner := map[int]uuid.UUID{}
	for _, l := range leases {
		if prev, dup := owner[l.Shard]; dup {
			t.Fatalf("shard %d double-leased to %s and %s", l.Shard, prev, l.WorkerID)
		}
		owner[l.Shard] = l.WorkerID
	}
	// A's in-memory view must match the lease ledger (no stale claims).
	for s := range ownedSet(a) {
		if owner[s] != a.workerID {
			t.Fatalf("A claims shard %d locally but ledger owner is %s", s, owner[s])
		}
	}
}

func TestForEachOwnedExactlyOnceAcrossWorkers(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const (
		shards  = 64
		tenants = 1500
	)
	a := newWorker(repo, clk, uuid.New(), shards)
	b := newWorker(repo, clk, uuid.New(), shards)
	settle(t, 4, a, b)

	all := make([]uuid.UUID, tenants)
	for i := range all {
		all[i] = uuid.New()
	}

	var mu sync.Mutex
	count := map[uuid.UUID]int{}
	record := func(_ context.Context, id uuid.UUID) error {
		mu.Lock()
		count[id]++
		mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for _, w := range []*Distributor{a, b} {
		wg.Add(1)
		go func(d *Distributor) {
			defer wg.Done()
			if err := d.ForEachOwned(context.Background(), all, record); err != nil {
				t.Errorf("ForEachOwned: %v", err)
			}
		}(w)
	}
	wg.Wait()

	for _, id := range all {
		if count[id] != 1 {
			t.Fatalf("tenant %s processed %d times, want exactly 1", id, count[id])
		}
	}
}

func TestForEachOwnedBoundedConcurrency(t *testing.T) {
	t.Parallel()
	clk := newTestClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	const (
		shards = 64
		limit  = 4
	)
	d := New(repo,
		WithWorkerID(uuid.New()),
		WithShardCount(shards),
		WithClock(clk.now),
		WithConcurrency(limit),
	)
	settle(t, 1, d)

	tenants := make([]uuid.UUID, 200)
	for i := range tenants {
		tenants[i] = uuid.New()
	}

	var active, maxActive int64
	fn := func(_ context.Context, _ uuid.UUID) error {
		cur := atomic.AddInt64(&active, 1)
		for {
			old := atomic.LoadInt64(&maxActive)
			if cur <= old || atomic.CompareAndSwapInt64(&maxActive, old, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt64(&active, -1)
		return nil
	}
	if err := d.ForEachOwned(context.Background(), tenants, fn); err != nil {
		t.Fatalf("ForEachOwned: %v", err)
	}
	if maxActive > limit {
		t.Fatalf("observed concurrency %d exceeded limit %d", maxActive, limit)
	}
	if maxActive < 2 {
		t.Fatalf("expected real parallelism, max observed %d", maxActive)
	}
}
