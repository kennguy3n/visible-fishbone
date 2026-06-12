package leader

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The tests in this package are deterministic: leadership transitions
// are driven by calling the elector's step function (tick) directly,
// and the periodic poll inside Run / RunIfLeader is driven through an
// injected ticker channel (withTicker). Nothing depends on wall-clock
// timing, so there are no sleeps and no flaky waitFor deadlines — the
// failover suite passes identically under heavy CPU contention and
// `-race -count=N`.

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

func (c *fakeCluster) holder(lockID int64) (*fakeSession, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.held[lockID]
	return s, ok
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
// is reclaimed by the "server" and subsequent Ping fails. This is the
// ungraceful-crash path (no Unlock), exactly what fencing defends
// against during the window before the stale leader notices.
func (s *fakeSession) kill() {
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	s.dead = true
	if s.holding && s.cluster.held[s.lockID] == s {
		delete(s.cluster.held, s.lockID)
		s.holding = false
	}
}

// staticTicker returns a tickerFunc that always hands back ch, so a
// test can drive Run / RunIfLeader's poll one beat at a time by
// sending on ch. The interval argument is ignored.
//
// Single-consumer constraint: every newTicker call on the elector
// returns this same ch, so all consumers compete for each value sent.
// Drive at most one loop (one Run OR one RunIfLeader) per elector with
// a given staticTicker; combining several on one elector would split
// beats between them and deadlock. Use a separate channel per loop if
// you need to drive more than one.
func staticTicker(ch <-chan time.Time) tickerFunc {
	return func(time.Duration) (<-chan time.Time, func()) { return ch, func() {} }
}

// killLeaderSession kills the dead-connection of e's currently held
// session, unwrapping the epochSession decorator used by the fencing
// tests. e must currently be the leader.
func killLeaderSession(t *testing.T, e *LeaderElector) {
	t.Helper()
	e.mu.Lock()
	sess := e.session
	e.mu.Unlock()
	switch s := sess.(type) {
	case *fakeSession:
		s.kill()
	case *epochSession:
		s.Session.(*fakeSession).kill()
	default:
		t.Fatalf("killLeaderSession: unexpected session type %T (is e the leader?)", sess)
	}
}

// recordingJob is a RunIfLeader callback that reports each start and
// stop on buffered channels. Buffered so the job never blocks; the
// test drains starts to confirm a run and inspects len(starts) for
// the negative "did not run" assertion.
type recordingJob struct {
	starts chan struct{}
	stops  chan struct{}
}

func newRecordingJob() *recordingJob {
	return &recordingJob{
		starts: make(chan struct{}, 8),
		stops:  make(chan struct{}, 8),
	}
}

func (j *recordingJob) fn(jobCtx context.Context) {
	j.starts <- struct{}{}
	<-jobCtx.Done()
	j.stops <- struct{}{}
}

func TestElector_SingleInstanceBecomesLeader(t *testing.T) {
	cluster := newFakeCluster()
	e := New(cluster)
	ctx := context.Background()

	// One election step is enough for a single replica to win.
	e.tick(ctx)

	if !e.IsLeader() {
		t.Fatal("single instance did not acquire leadership on first tick")
	}
	if _, held := cluster.holder(e.LockID()); !held {
		t.Fatal("advisory lock not held after acquisition")
	}
}

func TestElector_OnlyOneLeaderAcrossInstances_SplitBrainAvoidance(t *testing.T) {
	cluster := newFakeCluster()
	const n = 5
	ctx := context.Background()
	electors := make([]*LeaderElector, n)
	for i := range electors {
		electors[i] = New(cluster, WithIdentity(string(rune('a'+i))))
	}

	// All replicas race to acquire the same lock concurrently. The
	// shared advisory-lock namespace must admit exactly one winner.
	var wg sync.WaitGroup
	wg.Add(n)
	for _, e := range electors {
		go func(e *LeaderElector) {
			defer wg.Done()
			e.tick(ctx)
		}(e)
	}
	wg.Wait()

	if got := countLeaders(electors); got != 1 {
		t.Fatalf("split brain: %d leaders after contended election, want exactly 1", got)
	}

	// Re-running the election repeatedly must never produce a second
	// leader while the first still holds the lock.
	for round := 0; round < 5; round++ {
		for _, e := range electors {
			e.tick(ctx)
		}
		if got := countLeaders(electors); got != 1 {
			t.Fatalf("split brain on round %d: %d leaders, want exactly 1", round, got)
		}
	}
}

func countLeaders(electors []*LeaderElector) int {
	n := 0
	for _, e := range electors {
		if e.IsLeader() {
			n++
		}
	}
	return n
}

func TestElector_CleanLeaderHandoff(t *testing.T) {
	cluster := newFakeCluster()
	ctx := context.Background()
	a := New(cluster, WithIdentity("a"))
	b := New(cluster, WithIdentity("b"))

	a.tick(ctx) // a acquires.
	b.tick(ctx) // b contends, loses, stays a follower.
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("after initial election: a=%v b=%v, want a leader / b follower", a.IsLeader(), b.IsLeader())
	}

	// Graceful handoff: a steps down (e.g. rolling deploy drains the
	// pod). The lock must be released so b can take over cleanly.
	a.relinquish(ctx)
	if a.IsLeader() {
		t.Fatal("a still leader after relinquish")
	}
	if _, held := cluster.holder(a.LockID()); held {
		t.Fatal("advisory lock not released after graceful step-down")
	}

	b.tick(ctx) // b now acquires the freed lock.
	if !b.IsLeader() {
		t.Fatal("b did not take over after a's clean handoff")
	}
}

func TestElector_FailoverOnLeaderConnectionLoss(t *testing.T) {
	cluster := newFakeCluster()
	ctx := context.Background()
	a := New(cluster, WithIdentity("a"))
	b := New(cluster, WithIdentity("b"))

	a.tick(ctx) // a acquires.
	b.tick(ctx) // b is a follower while a holds the lock.
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("setup: a=%v b=%v, want a leader / b follower", a.IsLeader(), b.IsLeader())
	}

	// a's database session dies (connection drop / partition the
	// server detects): the advisory lock is reclaimed immediately,
	// but a has NOT yet noticed and still believes it is the leader.
	killLeaderSession(t, a)

	// b's next election step acquires the now-free lock. This is the
	// bounded two-leader window the fencing layer exists to make
	// safe: a is still IsLeader()==true here.
	b.tick(ctx)
	if !b.IsLeader() {
		t.Fatal("b did not take over after a's connection loss")
	}
	if !a.IsLeader() {
		t.Fatal("expected a to still believe it is leader before it next ticks (stale-leader window)")
	}

	// a's next step pings its dead session, fails, and steps down —
	// closing the window so exactly one leader remains.
	a.tick(ctx)
	if a.IsLeader() {
		t.Fatal("a did not step down after detecting its dead session")
	}
	if got := countLeaders([]*LeaderElector{a, b}); got != 1 {
		t.Fatalf("%d leaders after failover settled, want exactly 1", got)
	}
}

func TestElector_RelinquishOnShutdown(t *testing.T) {
	cluster := newFakeCluster()
	tickC := make(chan time.Time)
	created := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	e := New(cluster, withTicker(func(time.Duration) (<-chan time.Time, func()) {
		// Signalling here proves Run's immediate election tick has
		// already returned (Run builds the ticker only after it).
		created <- struct{}{}
		return tickC, func() { stopped <- struct{}{} }
	}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.Run(ctx)
		close(done)
	}()

	<-created // immediate election completed; outcome is now stable.
	if !e.IsLeader() {
		t.Fatal("single instance not leader after Run's immediate election")
	}

	cancel() // shutdown.
	<-done   // Run has returned (and relinquished).
	<-stopped
	if e.IsLeader() {
		t.Fatal("leadership not released on shutdown")
	}
	if _, held := cluster.holder(e.LockID()); held {
		t.Fatal("advisory lock not released after shutdown")
	}
}

// TestElector_GatedLoopStopsOnOldLeaderResumesOnNew is the core HA
// guarantee for the leader-gated background loops (Shadow-IT NoOps,
// IdP directory sync, rebalance): the loop runs ONLY on the elected
// leader, stops on the replica that loses leadership, and starts on
// the replica that takes over.
func TestElector_GatedLoopStopsOnOldLeaderResumesOnNew(t *testing.T) {
	cluster := newFakeCluster()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pollA := make(chan time.Time)
	pollB := make(chan time.Time)
	a := New(cluster, WithIdentity("a"), withTicker(staticTicker(pollA)))
	b := New(cluster, WithIdentity("b"), withTicker(staticTicker(pollB)))

	jobA := newRecordingJob()
	jobB := newRecordingJob()
	go a.RunIfLeader(ctx, "gated-loop", jobA.fn)
	go b.RunIfLeader(ctx, "gated-loop", jobB.fn)

	// a becomes leader; b is a follower.
	a.tick(ctx)
	b.tick(ctx)
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("setup: a=%v b=%v", a.IsLeader(), b.IsLeader())
	}

	// Drive a's supervision poll: a is leader so its loop starts.
	pollA <- time.Now()
	<-jobA.starts

	// Drive b's poll twice while it is a follower. The second send
	// only returns once b has fully processed the first beat and
	// looped back to receive, so by then b's loop has provably had a
	// chance to (incorrectly) start. It must not have.
	pollB <- time.Now()
	pollB <- time.Now()
	if len(jobB.starts) != 0 {
		t.Fatal("gated loop ran on the follower replica b")
	}

	// Failover: a's session dies; b acquires; a notices and steps down.
	killLeaderSession(t, a)
	b.tick(ctx)
	a.tick(ctx)
	if a.IsLeader() || !b.IsLeader() {
		t.Fatalf("after failover: a=%v b=%v, want b leader", a.IsLeader(), b.IsLeader())
	}

	// The loop must STOP on the old leader a...
	pollA <- time.Now()
	<-jobA.stops
	// ...and START on the new leader b.
	pollB <- time.Now()
	<-jobB.starts
}

// TestRunIfLeader_RestartsOnLeadershipFlap covers a single replica
// that loses then regains leadership between supervision polls: the
// job's context must be cancelled and the job re-invoked with a fresh
// term so it never keeps running against a stale leadership term.
func TestRunIfLeader_RestartsOnLeadershipFlap(t *testing.T) {
	cluster := newFakeCluster()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	poll := make(chan time.Time)
	e := New(cluster, withTicker(staticTicker(poll)))
	job := newRecordingJob()
	go e.RunIfLeader(ctx, "gated-loop", job.fn)

	// Acquire, then start the job.
	e.tick(ctx)
	poll <- time.Now()
	<-job.starts

	// Flap: lose the session and re-acquire before the next poll.
	killLeaderSession(t, e)
	e.tick(ctx) // detects dead session, steps down.
	if e.IsLeader() {
		t.Fatal("expected step-down after killed session")
	}
	e.tick(ctx) // re-acquires with a new generation/epoch.
	if !e.IsLeader() {
		t.Fatal("expected re-acquisition after flap")
	}

	// The supervisor must tear the old run down (generation changed)
	// and start a fresh one.
	poll <- time.Now()
	<-job.stops
	poll <- time.Now()
	<-job.starts
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
