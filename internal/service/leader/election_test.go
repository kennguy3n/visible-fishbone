package leader

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeCluster models a shared advisory-lock namespace across many
// electors: at most one session may hold a given lockID at a time.
type fakeCluster struct {
	mu      sync.Mutex
	held    map[int64]*fakeSession
	openErr error
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{held: make(map[int64]*fakeSession)}
}

func (c *fakeCluster) Open(_ context.Context) (Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openErr != nil {
		return nil, c.openErr
	}
	return &fakeSession{cluster: c}, nil
}

type fakeSession struct {
	cluster *fakeCluster
	lockID  int64
	holding bool
	dead    bool
}

func (s *fakeSession) TryLock(_ context.Context, lockID int64) (bool, error) {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	if _, taken := s.cluster.held[lockID]; taken {
		return false, nil
	}
	s.cluster.held[lockID] = s
	s.holding = true
	s.lockID = lockID
	return true, nil
}

func (s *fakeSession) Unlock(_ context.Context, lockID int64) error {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	if s.cluster.held[lockID] == s {
		delete(s.cluster.held, lockID)
		s.holding = false
	}
	return nil
}

func (s *fakeSession) Ping(_ context.Context) error {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	if s.dead {
		return errors.New("connection dead")
	}
	return nil
}

func (s *fakeSession) Close(_ context.Context) {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	if s.holding && s.cluster.held[s.lockID] == s {
		delete(s.cluster.held, s.lockID)
	}
	s.holding = false
}

// kill simulates the leader's database connection dropping: the lock
// is reclaimed by the "server" and subsequent Ping fails.
func (s *fakeSession) kill() {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	s.dead = true
	if s.holding && s.cluster.held[s.lockID] == s {
		delete(s.cluster.held, s.lockID)
		s.holding = false
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for: %s", msg)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func TestElector_SingleInstanceBecomesLeader(t *testing.T) {
	cluster := newFakeCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	waitFor(t, e.IsLeader, "single instance to acquire leadership")
}

func TestElector_OnlyOneLeaderAcrossInstances(t *testing.T) {
	cluster := newFakeCluster()
	a := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("a"))
	b := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("b"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	go b.Run(ctx)

	waitFor(t, func() bool { return a.IsLeader() || b.IsLeader() }, "some instance to become leader")
	// Give the follower several intervals to (incorrectly) also grab it.
	time.Sleep(60 * time.Millisecond)
	if a.IsLeader() && b.IsLeader() {
		t.Fatal("both instances claim leadership simultaneously")
	}
}

func TestElector_FailoverOnLeaderConnectionLoss(t *testing.T) {
	cluster := newFakeCluster()
	a := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("a"))
	b := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("b"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	waitFor(t, a.IsLeader, "a to become leader")

	// b joins; it must stay a follower while a holds the lock.
	go b.Run(ctx)
	time.Sleep(40 * time.Millisecond)
	if b.IsLeader() {
		t.Fatal("b became leader while a still held the lock")
	}

	// Kill a's session — its lock is reclaimed; b must take over and
	// a must step down once it notices its session is dead.
	a.mu.Lock()
	sess := a.session.(*fakeSession)
	a.mu.Unlock()
	sess.kill()

	waitFor(t, b.IsLeader, "b to take over after a's connection loss")
	waitFor(t, func() bool { return !a.IsLeader() }, "a to step down after losing its session")
}

func TestElector_RelinquishOnShutdown(t *testing.T) {
	cluster := newFakeCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "leadership before shutdown")

	cancel()
	waitFor(t, func() bool { return !e.IsLeader() }, "leadership released on shutdown")

	// The lock must be free for a fresh elector to acquire.
	cluster.mu.Lock()
	_, stillHeld := cluster.held[e.LockID()]
	cluster.mu.Unlock()
	if stillHeld {
		t.Fatal("advisory lock not released after shutdown")
	}
}

func TestElector_RunIfLeaderRunsOnlyWhenLeader(t *testing.T) {
	cluster := newFakeCluster()
	// Pre-occupy the lock so our elector starts as a follower.
	occupier := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("occupier"))
	occCtx, occCancel := context.WithCancel(context.Background())
	go occupier.Run(occCtx)
	waitFor(t, occupier.IsLeader, "occupier to grab the lock")

	e := New(cluster, WithCheckInterval(9*time.Millisecond), WithIdentity("e"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	var mu sync.Mutex
	running := false
	starts := 0
	go e.RunIfLeader(ctx, "job", func(jobCtx context.Context) {
		mu.Lock()
		running = true
		starts++
		mu.Unlock()
		<-jobCtx.Done()
		mu.Lock()
		running = false
		mu.Unlock()
	})

	// While occupier holds leadership, the job must not run.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	wasRunning := running
	mu.Unlock()
	if wasRunning {
		t.Fatal("job ran while elector was a follower")
	}

	// Release the lock; e should become leader and start the job.
	occCancel()
	waitFor(t, e.IsLeader, "e to become leader after occupier left")
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return running
	}, "job to start once e is leader")

	// Cancelling the root ctx must stop the job.
	cancel()
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return !running
	}, "job to stop on shutdown")
}

func TestLockIDForName_StableNonNegative(t *testing.T) {
	t.Parallel()
	a := LockIDForName("app-registry-sync")
	if a < 0 {
		t.Fatalf("LockIDForName negative: %d", a)
	}
	if a != LockIDForName("app-registry-sync") {
		t.Fatal("LockIDForName not stable")
	}
	if a == LockIDForName("cert-monitor") {
		t.Fatal("distinct names collided")
	}
}
