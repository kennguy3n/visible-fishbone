// Package memory_test — workshard_test pins the storage contract the
// work distributor depends on: atomic single-winner shard acquisition,
// fence-token monotonicity across ownership changes, lease/heartbeat
// expiry against an injectable clock, and the graceful-release and
// expired-worker-sweep paths. The postgres implementation must mirror
// these semantics (they are re-verified against a real database in
// workshard_integration_test.go).
package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// clock is a trivial settable clock for deterministic expiry tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0).UTC()} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestAcquireShardsSingleWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewWorkShardRepository()
	a, b := uuid.New(), uuid.New()
	ttl := 20 * time.Second

	// A takes shards 1,2,3.
	got, err := repo.AcquireShards(ctx, a, []int{1, 2, 3}, ttl)
	if err != nil {
		t.Fatalf("A acquire: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("A should hold 3 shards, got %d", len(got))
	}
	for _, l := range got {
		if l.FenceToken != 1 {
			t.Errorf("shard %d: first acquisition should have fence 1, got %d", l.Shard, l.FenceToken)
		}
	}

	// B races for 2,3,4 while A's leases are still valid: B may only
	// take 4; 2 and 3 stay with A.
	got, err = repo.AcquireShards(ctx, b, []int{2, 3, 4}, ttl)
	if err != nil {
		t.Fatalf("B acquire: %v", err)
	}
	if len(got) != 1 || got[0].Shard != 4 {
		t.Fatalf("B should hold only shard 4, got %+v", got)
	}

	// Every live lease must have exactly one owner.
	leases, err := repo.ListLeases(ctx)
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	owner := map[int]uuid.UUID{}
	for _, l := range leases {
		if prev, dup := owner[l.Shard]; dup {
			t.Fatalf("shard %d owned by two workers: %s and %s", l.Shard, prev, l.WorkerID)
		}
		owner[l.Shard] = l.WorkerID
	}
	if owner[2] != a || owner[3] != a || owner[4] != b {
		t.Fatalf("unexpected ownership: %v", owner)
	}
}

func TestAcquireShardsRenewKeepsFenceTakeoverBumps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := newClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	a, b := uuid.New(), uuid.New()
	ttl := 20 * time.Second

	if _, err := repo.AcquireShards(ctx, a, []int{7}, ttl); err != nil {
		t.Fatalf("A acquire: %v", err)
	}
	// A renews within the window: fence token must stay 1.
	clk.advance(5 * time.Second)
	got, err := repo.AcquireShards(ctx, a, []int{7}, ttl)
	if err != nil {
		t.Fatalf("A renew: %v", err)
	}
	if got[0].FenceToken != 1 {
		t.Fatalf("renewal must keep fence 1, got %d", got[0].FenceToken)
	}

	// Let the lease expire, then B takes over: fence token must bump.
	clk.advance(ttl + time.Second)
	got, err = repo.AcquireShards(ctx, b, []int{7}, ttl)
	if err != nil {
		t.Fatalf("B takeover: %v", err)
	}
	if len(got) != 1 || got[0].WorkerID != b {
		t.Fatalf("B should take shard 7, got %+v", got)
	}
	if got[0].FenceToken != 2 {
		t.Fatalf("takeover must bump fence to 2, got %d", got[0].FenceToken)
	}
}

func TestAcquireExpiredLeaseReclaimable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := newClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	a, b := uuid.New(), uuid.New()
	ttl := 10 * time.Second

	if _, err := repo.AcquireShards(ctx, a, []int{1}, ttl); err != nil {
		t.Fatalf("A acquire: %v", err)
	}
	// Before expiry, B cannot take it.
	clk.advance(5 * time.Second)
	got, _ := repo.AcquireShards(ctx, b, []int{1}, ttl)
	if len(got) != 0 {
		t.Fatalf("B must not take a live lease, got %+v", got)
	}
	// After expiry, B reclaims it.
	clk.advance(6 * time.Second)
	got, _ = repo.AcquireShards(ctx, b, []int{1}, ttl)
	if len(got) != 1 || got[0].WorkerID != b {
		t.Fatalf("B should reclaim expired shard 1, got %+v", got)
	}
}

func TestReleaseShardsExcept(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewWorkShardRepository()
	a := uuid.New()
	ttl := 20 * time.Second

	if _, err := repo.AcquireShards(ctx, a, []int{1, 2, 3, 4}, ttl); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := repo.ReleaseShardsExcept(ctx, a, []int{2, 4}); err != nil {
		t.Fatalf("release: %v", err)
	}
	held, err := repo.ListHeldShards(ctx, a)
	if err != nil {
		t.Fatalf("list held: %v", err)
	}
	if len(held) != 2 || held[0].Shard != 2 || held[1].Shard != 4 {
		t.Fatalf("expected to keep shards 2,4, got %+v", held)
	}

	// Empty keep releases everything.
	if err := repo.ReleaseShardsExcept(ctx, a, nil); err != nil {
		t.Fatalf("release all: %v", err)
	}
	held, _ = repo.ListHeldShards(ctx, a)
	if len(held) != 0 {
		t.Fatalf("expected no held shards, got %+v", held)
	}
}

func TestHeartbeatAndWorkerExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := newClock()
	repo := memory.NewWorkShardRepository().WithClock(clk.now)
	a, b := uuid.New(), uuid.New()
	ttl := 15 * time.Second

	if err := repo.Heartbeat(ctx, a, "host-a", ttl); err != nil {
		t.Fatalf("heartbeat a: %v", err)
	}
	if err := repo.Heartbeat(ctx, b, "host-b", ttl); err != nil {
		t.Fatalf("heartbeat b: %v", err)
	}
	live, err := repo.ListLiveWorkers(ctx)
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("expected 2 live workers, got %d", len(live))
	}

	// A keeps heartbeating; B goes silent. After the TTL only A is live.
	clk.advance(10 * time.Second)
	if err := repo.Heartbeat(ctx, a, "host-a", ttl); err != nil {
		t.Fatalf("heartbeat a: %v", err)
	}
	clk.advance(10 * time.Second) // 20s since B's last heartbeat (> ttl)
	live, _ = repo.ListLiveWorkers(ctx)
	if len(live) != 1 || live[0].WorkerID != a {
		t.Fatalf("expected only A live, got %+v", live)
	}

	// started_at is preserved across heartbeats.
	if !live[0].StartedAt.Equal(clk.now().Add(-20 * time.Second)) {
		t.Errorf("A started_at should be the first heartbeat time, got %v", live[0].StartedAt)
	}

	// Sweep removes B once it is grace-expired; A survives.
	deleted, err := repo.DeleteExpiredWorkers(ctx, 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected to sweep 1 expired worker, got %d", deleted)
	}
}

func TestListLiveWorkersStableOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewWorkShardRepository()
	ttl := 20 * time.Second
	for i := 0; i < 8; i++ {
		if err := repo.Heartbeat(ctx, uuid.New(), "h", ttl); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}
	first, _ := repo.ListLiveWorkers(ctx)
	second, _ := repo.ListLiveWorkers(ctx)
	if len(first) != len(second) {
		t.Fatalf("inconsistent lengths")
	}
	for i := range first {
		if first[i].WorkerID != second[i].WorkerID {
			t.Fatalf("order not stable at %d", i)
		}
	}
	// Verify ascending byte order.
	for i := 1; i < len(first); i++ {
		if string(first[i-1].WorkerID[:]) > string(first[i].WorkerID[:]) {
			t.Fatalf("not sorted at %d", i)
		}
	}
}
