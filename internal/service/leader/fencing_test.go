package leader

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// epochCluster is a fakeCluster whose sessions also implement
// EpochReader, handing out a strictly increasing epoch each time a
// session is opened. It models the production pgSession's
// transaction-id-backed epoch without a database.
type epochCluster struct {
	*fakeCluster
	counter atomic.Uint64
}

func newEpochCluster() *epochCluster {
	return &epochCluster{fakeCluster: newFakeCluster()}
}

func (c *epochCluster) Open(ctx context.Context) (Session, error) {
	s, err := c.fakeCluster.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &epochSession{Session: s, c: c}, nil
}

type epochSession struct {
	Session
	c *epochCluster
}

func (s *epochSession) Epoch(_ context.Context) (uint64, error) {
	return s.c.counter.Add(1), nil
}

func TestFencingToken_ValidAndNewerThan(t *testing.T) {
	a := FencingToken{LockID: 1, Epoch: 5}
	b := FencingToken{LockID: 1, Epoch: 6}
	if !a.Valid() {
		t.Error("non-zero epoch token should be Valid")
	}
	if (FencingToken{}).Valid() {
		t.Error("zero token must not be Valid")
	}
	if !b.NewerThan(a) {
		t.Error("epoch 6 should be newer than 5")
	}
	if a.NewerThan(b) {
		t.Error("epoch 5 must not be newer than 6")
	}
	if (FencingToken{LockID: 2, Epoch: 9}).NewerThan(a) {
		t.Error("tokens for different lock IDs are not comparable")
	}
}

func TestFencingToken_FollowerGetsZeroToken(t *testing.T) {
	cluster := newFakeCluster()
	// Pre-occupy the lock so our elector stays a follower.
	occ := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("occ"))
	occCtx, occCancel := context.WithCancel(context.Background())
	defer occCancel()
	go occ.Run(occCtx)
	waitFor(t, occ.IsLeader, "occupier to take the lock")

	e := New(cluster, WithCheckInterval(5*time.Millisecond), WithIdentity("follower"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(40 * time.Millisecond)

	tok, ok := e.FencingToken()
	if ok || tok.Valid() {
		t.Fatalf("follower returned a valid token: %+v ok=%v", tok, ok)
	}
}

func TestFencingToken_LeaderEpochFromEpochReader(t *testing.T) {
	cluster := newEpochCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")

	tok, ok := e.FencingToken()
	if !ok || !tok.Valid() {
		t.Fatalf("leader token invalid: %+v ok=%v", tok, ok)
	}
	if tok.LockID != e.LockID() {
		t.Errorf("token lock ID = %d, want %d", tok.LockID, e.LockID())
	}
	// The epoch came from the EpochReader, not the generation
	// counter: the first session opened yields epoch 1.
	if tok.Epoch != 1 {
		t.Errorf("token epoch = %d, want 1 (from EpochReader)", tok.Epoch)
	}
	if !e.HoldsToken(tok) {
		t.Error("HoldsToken should be true for the live term's token")
	}
}

func TestFencingToken_GenerationFallbackWithoutEpochReader(t *testing.T) {
	// The plain fakeSession does not implement EpochReader, so the
	// elector falls back to its in-process generation counter.
	cluster := newFakeCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")

	tok, ok := e.FencingToken()
	if !ok || tok.Epoch == 0 {
		t.Fatalf("expected a valid fallback token, got %+v ok=%v", tok, ok)
	}
}

func TestHoldsToken_StaleAfterFlap(t *testing.T) {
	cluster := newEpochCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")

	stale, _ := e.FencingToken()

	// Kill the lock-holding session: the lock is reclaimed and the
	// elector must step down, then re-acquire with a fresh epoch.
	e.mu.Lock()
	sess := e.session.(*epochSession).Session.(*fakeSession)
	e.mu.Unlock()
	sess.kill()

	waitFor(t, func() bool { return !e.IsLeader() }, "elector to step down after losing its session")
	waitFor(t, e.IsLeader, "elector to re-acquire leadership")

	fresh, ok := e.FencingToken()
	if !ok {
		t.Fatal("expected a fresh token after re-acquire")
	}
	if !fresh.NewerThan(stale) {
		t.Errorf("fresh token %+v should be newer than stale %+v", fresh, stale)
	}
	if e.HoldsToken(stale) {
		t.Error("stale token must no longer be held after a flap")
	}
	if !e.HoldsToken(fresh) {
		t.Error("fresh token should be held")
	}
}

func TestTransitionsMetric_IncrementsOnAcquisition(t *testing.T) {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "sng", Subsystem: "leader", Name: "transitions_total",
		Help: "test",
	})
	cluster := newEpochCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond), WithTransitionsCounter(c))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")
	waitFor(t, func() bool { return testutil.ToFloat64(c) >= 1 }, "transitions counter to reach 1")

	if got := testutil.ToFloat64(c); got != 1 {
		t.Errorf("transitions_total = %v, want 1", got)
	}
}

func TestWithTransitionsMetric_RegistersCanonicalName(t *testing.T) {
	reg := prometheus.NewRegistry()
	cluster := newEpochCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond), WithTransitionsMetric(reg, ""))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")

	const name = "sng_leader_transitions_total"
	waitFor(t, func() bool {
		v, err := testutil.GatherAndCount(reg, name)
		return err == nil && v == 1
	}, "sng_leader_transitions_total to be registered and emitted")
}

func TestRunIfLeaderFenced_PassesLiveToken(t *testing.T) {
	cluster := newEpochCluster()
	e := New(cluster, WithCheckInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	waitFor(t, e.IsLeader, "elector to acquire leadership")

	var mu sync.Mutex
	var seen FencingToken
	gotToken := make(chan struct{}, 1)
	go e.RunIfLeaderFenced(ctx, "fenced-job", func(jctx context.Context, tok FencingToken) {
		mu.Lock()
		seen = tok
		mu.Unlock()
		select {
		case gotToken <- struct{}{}:
		default:
		}
		<-jctx.Done()
	})

	select {
	case <-gotToken:
	case <-time.After(2 * time.Second):
		t.Fatal("fenced job never received a token")
	}
	mu.Lock()
	tok := seen
	mu.Unlock()
	if !tok.Valid() || !e.HoldsToken(tok) {
		t.Fatalf("fenced job received an invalid/stale token: %+v", tok)
	}
	cancel()
}
