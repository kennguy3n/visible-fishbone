//go:build integration

// workshard_integration_test verifies the work-shard storage contract and
// the end-to-end distribution guarantee against a real Postgres (the
// memory implementation pins the same semantics in fast unit tests):
//
//   - AcquireShards is atomic — under two workers racing for the same
//     shards, each shard ends up owned by exactly one worker.
//   - A lease is reclaimable only after it expires (missed heartbeat),
//     and takeover bumps the fence token.
//   - Two Distributors sharing the database partition the tenant space
//     so a per-tenant job runs exactly once per tenant per cycle — the
//     property that lets the old leader-gated jobs run active/active.
package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/workshard"
)

func TestWorkShardAcquireIsExclusiveUnderRace(t *testing.T) {
	store, cleanup := startPostgres(t)
	defer cleanup()
	ctx := context.Background()
	repo := store.NewWorkShardRepository()

	a, b := uuid.New(), uuid.New()
	ttl := 30 * time.Second
	if err := repo.Heartbeat(ctx, a, "a", ttl); err != nil {
		t.Fatalf("heartbeat a: %v", err)
	}
	if err := repo.Heartbeat(ctx, b, "b", ttl); err != nil {
		t.Fatalf("heartbeat b: %v", err)
	}

	shards := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var wg sync.WaitGroup
	var mu sync.Mutex
	owner := map[int]uuid.UUID{}
	acquire := func(id uuid.UUID) {
		defer wg.Done()
		held, err := repo.AcquireShards(ctx, id, shards, ttl)
		if err != nil {
			t.Errorf("acquire %s: %v", id, err)
			return
		}
		mu.Lock()
		for _, l := range held {
			if prev, dup := owner[l.Shard]; dup {
				t.Errorf("shard %d acquired by both %s and %s", l.Shard, prev, id)
			}
			owner[l.Shard] = id
		}
		mu.Unlock()
	}
	wg.Add(2)
	go acquire(a)
	go acquire(b)
	wg.Wait()

	// Authoritative check against the ledger: each shard exactly once.
	leases, err := repo.ListLeases(ctx)
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	seen := map[int]int{}
	for _, l := range leases {
		seen[l.Shard]++
	}
	for _, s := range shards {
		if seen[s] != 1 {
			t.Fatalf("shard %d has %d live leases, want exactly 1", s, seen[s])
		}
	}
}

func TestWorkShardExpiryAndTakeover(t *testing.T) {
	store, cleanup := startPostgres(t)
	defer cleanup()
	ctx := context.Background()
	repo := store.NewWorkShardRepository()

	a, b := uuid.New(), uuid.New()
	shortTTL := 1 * time.Second

	if err := repo.Heartbeat(ctx, a, "a", shortTTL); err != nil {
		t.Fatalf("heartbeat a: %v", err)
	}
	held, err := repo.AcquireShards(ctx, a, []int{42}, shortTTL)
	if err != nil || len(held) != 1 || held[0].FenceToken != 1 {
		t.Fatalf("A acquire: held=%+v err=%v", held, err)
	}

	// While A's lease is live, B cannot take it.
	if got, _ := repo.AcquireShards(ctx, b, []int{42}, shortTTL); len(got) != 0 {
		t.Fatalf("B must not take a live lease, got %+v", got)
	}

	// Let the lease expire (real wall clock), then B takes over with a
	// bumped fence token.
	time.Sleep(1200 * time.Millisecond)
	got, err := repo.AcquireShards(ctx, b, []int{42}, shortTTL)
	if err != nil || len(got) != 1 || got[0].WorkerID != b {
		t.Fatalf("B takeover: got=%+v err=%v", got, err)
	}
	if got[0].FenceToken != 2 {
		t.Fatalf("takeover must bump fence to 2, got %d", got[0].FenceToken)
	}

	// A, now expired, drops out of the live set.
	time.Sleep(1200 * time.Millisecond)
	live, err := repo.ListLiveWorkers(ctx)
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	for _, w := range live {
		if w.WorkerID == a {
			t.Fatalf("expired worker A still listed live")
		}
	}
}

// TestWorkShardExactlyOnceAcrossWorkers is the end-to-end proof: two
// Distributors backed by the same Postgres converge to a disjoint,
// complete partition of the tenant space, so a per-tenant job invoked
// via ForEachOwned on every replica runs exactly once per tenant.
func TestWorkShardExactlyOnceAcrossWorkers(t *testing.T) {
	store, cleanup := startPostgres(t)
	defer cleanup()
	repo := store.NewWorkShardRepository()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const shards = 64
	mk := func() *workshard.Distributor {
		return workshard.New(repo,
			workshard.WithWorkerID(uuid.New()),
			workshard.WithShardCount(shards),
			workshard.WithLeaseTTL(3*time.Second),
			workshard.WithCycleInterval(150*time.Millisecond),
			workshard.WithSafetyMargin(1*time.Second),
			workshard.WithConcurrency(8),
		)
	}
	a, b := mk(), mk()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("start a: %v", err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start b: %v", err)
	}
	defer func() { cancel(); a.Wait(); b.Wait() }()

	tenants := make([]uuid.UUID, 1000)
	for i := range tenants {
		tenants[i] = uuid.New()
	}

	// Wait for the fleet to converge to a complete, disjoint partition.
	deadline := time.Now().Add(8 * time.Second)
	for {
		oa := a.FilterOwned(tenants)
		ob := b.FilterOwned(tenants)
		if partitioned(oa, ob, tenants) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("workers did not converge to a partition: |A|=%d |B|=%d of %d", len(oa), len(ob), len(tenants))
		}
		time.Sleep(100 * time.Millisecond)
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
	for _, d := range []*workshard.Distributor{a, b} {
		wg.Add(1)
		go func(w *workshard.Distributor) {
			defer wg.Done()
			if err := w.ForEachOwned(ctx, tenants, record); err != nil {
				t.Errorf("ForEachOwned: %v", err)
			}
		}(d)
	}
	wg.Wait()

	for _, id := range tenants {
		if count[id] != 1 {
			t.Fatalf("tenant %s processed %d times, want exactly 1", id, count[id])
		}
	}
}

// partitioned reports whether oa and ob form a disjoint cover of all.
func partitioned(oa, ob, all []uuid.UUID) bool {
	if len(oa)+len(ob) != len(all) {
		return false
	}
	seen := make(map[uuid.UUID]int, len(all))
	for _, id := range oa {
		seen[id]++
	}
	for _, id := range ob {
		seen[id]++
	}
	if len(seen) != len(all) {
		return false
	}
	for _, c := range seen {
		if c != 1 {
			return false
		}
	}
	return true
}
