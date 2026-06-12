package leader

import (
	"context"
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
	ctx := context.Background()

	// occ takes the lock first; e then contends and stays a follower.
	occ := New(cluster, WithIdentity("occ"))
	occ.tick(ctx)
	e := New(cluster, WithIdentity("follower"))
	e.tick(ctx)
	if occ.IsLeader() == false || e.IsLeader() {
		t.Fatalf("setup: occ=%v e=%v, want occ leader / e follower", occ.IsLeader(), e.IsLeader())
	}

	tok, ok := e.FencingToken()
	if ok || tok.Valid() {
		t.Fatalf("follower returned a valid token: %+v ok=%v", tok, ok)
	}
}

func TestFencingToken_LeaderEpochFromEpochReader(t *testing.T) {
	cluster := newEpochCluster()
	e := New(cluster)
	ctx := context.Background()
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}

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
	e := New(cluster)
	ctx := context.Background()
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}

	tok, ok := e.FencingToken()
	if !ok || tok.Epoch == 0 {
		t.Fatalf("expected a valid fallback token, got %+v ok=%v", tok, ok)
	}
}

func TestHoldsToken_StaleAfterFlap(t *testing.T) {
	cluster := newEpochCluster()
	e := New(cluster)
	ctx := context.Background()
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}
	stale, _ := e.FencingToken()

	// Kill the lock-holding session: the lock is reclaimed and the
	// elector must step down on its next tick, then re-acquire with a
	// fresh, strictly newer epoch.
	killLeaderSession(t, e)
	e.tick(ctx)
	if e.IsLeader() {
		t.Fatal("elector did not step down after losing its session")
	}
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not re-acquire leadership")
	}

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
	e := New(cluster, WithTransitionsCounter(c))
	ctx := context.Background()
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}

	if got := testutil.ToFloat64(c); got != 1 {
		t.Errorf("transitions_total = %v, want 1", got)
	}
}

func TestWithTransitionsMetric_RegistersCanonicalName(t *testing.T) {
	reg := prometheus.NewRegistry()
	cluster := newEpochCluster()
	e := New(cluster, WithTransitionsMetric(reg, ""))
	ctx := context.Background()
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}

	const name = "sng_leader_transitions_total"
	v, err := testutil.GatherAndCount(reg, name)
	if err != nil || v != 1 {
		t.Fatalf("GatherAndCount(%s) = %d, err=%v; want 1, nil", name, v, err)
	}
}

func TestRunIfLeaderFenced_PassesLiveToken(t *testing.T) {
	cluster := newEpochCluster()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	poll := make(chan time.Time)
	e := New(cluster, withTicker(staticTicker(poll)))
	e.tick(ctx)
	if !e.IsLeader() {
		t.Fatal("elector did not acquire leadership")
	}

	gotToken := make(chan FencingToken, 1)
	go e.RunIfLeaderFenced(ctx, "fenced-job", func(jctx context.Context, tok FencingToken) {
		gotToken <- tok
		<-jctx.Done()
	})

	// Drive one supervision beat so the fenced job starts.
	poll <- time.Now()
	tok := <-gotToken
	if !tok.Valid() || !e.HoldsToken(tok) {
		t.Fatalf("fenced job received an invalid/stale token: %+v", tok)
	}
}
