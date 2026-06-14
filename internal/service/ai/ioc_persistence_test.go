package ai

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fakePersister is an in-process IOCPersister for unit tests. It
// records how many times SaveIOCs was called so shutdown-flush
// behaviour can be asserted without a real database.
type fakePersister struct {
	mu        sync.Mutex
	stored    []IOC
	saveCalls int
	loadErr   error
	saveErr   error
}

func (f *fakePersister) LoadIOCs(context.Context) ([]IOC, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	out := make([]IOC, len(f.stored))
	copy(out, f.stored)
	return out, nil
}

func (f *fakePersister) SaveIOCs(_ context.Context, iocs []IOC) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.stored = make([]IOC, len(iocs))
	copy(f.stored, iocs)
	return nil
}

func (f *fakePersister) snapshot() ([]IOC, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]IOC, len(f.stored))
	copy(out, f.stored)
	return out, f.saveCalls
}

func TestIOCStore_PersistRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	src := NewIOCStore(withStoreClock(clock))
	src.Upsert(
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) { i.LastSeen = now }),
		mkIOC(IOCTypeIP, "203.0.113.10", 0.8, func(i *IOC) { i.ExpiresAt = now.Add(24 * time.Hour) }),
		mkIOC(IOCTypeURL, "http://evil.example.com/x", 0.7),
		mkIOC(IOCTypeHash, "44d88612fea8a8f36de82e1278abb02f", 0.95),
	)

	fp := &fakePersister{}
	n, err := src.Persist(context.Background(), fp)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if n != 4 {
		t.Fatalf("persisted %d, want 4", n)
	}

	// A fresh store restoring from the same persister must reproduce
	// the identical active snapshot.
	dst := NewIOCStore(withStoreClock(clock))
	res, err := dst.Restore(context.Background(), fp)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Added != 4 {
		t.Fatalf("restored Added=%d, want 4", res.Added)
	}
	assertSameSnapshot(t, src.Snapshot(), dst.Snapshot())
}

func TestIOCStore_RestoreDropsExpired(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	// Persist a snapshot at t0 containing a short-TTL indicator.
	src := NewIOCStore(withStoreClock(func() time.Time { return t0 }))
	src.Upsert(
		mkIOC(IOCTypeIP, "203.0.113.10", 0.9, func(i *IOC) { i.ExpiresAt = t0.Add(time.Hour) }),
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9), // permanent (zero ExpiresAt)
	)
	fp := &fakePersister{}
	if _, err := src.Persist(context.Background(), fp); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Restore well after the TTL elapsed: the expired IP must be
	// dropped, the permanent domain kept.
	later := t0.Add(2 * time.Hour)
	dst := NewIOCStore(withStoreClock(func() time.Time { return later }))
	res, err := dst.Restore(context.Background(), fp)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Added != 1 {
		t.Fatalf("restored Added=%d, want 1 (expired IP dropped)", res.Added)
	}
	snap := dst.Snapshot()
	if len(snap.IPs) != 0 {
		t.Errorf("expired IP was restored: %#v", snap.IPs)
	}
	if len(snap.Domains) != 1 {
		t.Errorf("permanent domain not restored: %#v", snap.Domains)
	}
}

func TestIOCStore_PersistRestoreNilPersisterNoop(t *testing.T) {
	t.Parallel()
	s := NewIOCStore()
	s.Upsert(mkIOC(IOCTypeDomain, "evil.example.com", 0.9))
	if n, err := s.Persist(context.Background(), nil); err != nil || n != 0 {
		t.Fatalf("Persist(nil) = (%d,%v), want (0,nil)", n, err)
	}
	if res, err := s.Restore(context.Background(), nil); err != nil || res != (UpsertResult{}) {
		t.Fatalf("Restore(nil) = (%#v,%v), want (zero,nil)", res, err)
	}
}

func TestRepositoryPersister_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	repo := memory.NewThreatIOCRepository(memory.NewStore())
	p := NewRepositoryPersister(repo)

	in := []IOC{
		mkIOC(IOCTypeHash, "44d88612fea8a8f36de82e1278abb02f", 0.95, func(i *IOC) {
			i.LastSeen = now
			i.ThreatActor = "APT29"
			i.Campaign = "op-x"
		}),
		mkIOC(IOCTypeDomain, "evil.example.com", 0.6), // zero FirstSeen/LastSeen/ExpiresAt
	}
	if err := p.SaveIOCs(context.Background(), in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := p.LoadIOCs(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("loaded %d, want %d", len(out), len(in))
	}
	// Load into a store and compare snapshots so ordering does not
	// matter and the enum mapping (IOCType / HashAlgo) is exercised.
	want := NewIOCStore(withStoreClock(func() time.Time { return now }))
	want.Upsert(in...)
	got := NewIOCStore(withStoreClock(func() time.Time { return now }))
	got.Upsert(out...)
	assertSameSnapshot(t, want.Snapshot(), got.Snapshot())
}

func TestFeedManager_PersistsOnShutdown(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "evil.example.com", 0.9))
	fp := &fakePersister{}
	// Large interval so only the shutdown flush fires, not a tick.
	mgr := NewFeedManager(store, nil, WithPersister(fp, time.Hour))
	mgr.Start(context.Background())
	mgr.Stop()

	stored, calls := fp.snapshot()
	if calls < 1 {
		t.Fatalf("expected at least one persist on shutdown, got %d", calls)
	}
	if len(stored) != 1 || stored[0].Value != "evil.example.com" {
		t.Fatalf("shutdown flush stored %#v, want the single domain", stored)
	}
}

func TestFeedManager_RestoreFiresOnUpdate(t *testing.T) {
	t.Parallel()
	// Persister already holds a snapshot (as after a restart).
	fp := &fakePersister{stored: []IOC{
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9),
		mkIOC(IOCTypeIP, "203.0.113.10", 0.8),
	}}

	var (
		mu       sync.Mutex
		hookSnap IOCSnapshot
		hookHits int
	)
	store := NewIOCStore()
	mgr := NewFeedManager(store, nil,
		WithPersister(fp, time.Hour),
		WithOnUpdate(func(_ context.Context, snap IOCSnapshot) {
			mu.Lock()
			defer mu.Unlock()
			hookHits++
			hookSnap = snap
		}),
	)

	res, err := mgr.Restore(context.Background())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Added != 2 {
		t.Fatalf("restored Added=%d, want 2", res.Added)
	}
	mu.Lock()
	defer mu.Unlock()
	if hookHits != 1 {
		t.Fatalf("OnUpdate fired %d times after restore, want 1", hookHits)
	}
	// The hook must observe the restored indicators, not an empty
	// snapshot — that is what lets demotion enforcement re-sync at
	// once instead of waiting for the first feed warm-up.
	if len(hookSnap.Domains) != 1 || len(hookSnap.IPs) != 1 {
		t.Fatalf("OnUpdate saw %d domains / %d IPs, want 1 / 1",
			len(hookSnap.Domains), len(hookSnap.IPs))
	}
}

func TestFeedManager_RestoreNoHookWhenEmpty(t *testing.T) {
	t.Parallel()
	// Empty persister (cold start, nothing persisted yet) must not
	// fire the hook: there is nothing to enforce.
	fp := &fakePersister{}
	var hits int
	mgr := NewFeedManager(NewIOCStore(), nil,
		WithPersister(fp, time.Hour),
		WithOnUpdate(func(context.Context, IOCSnapshot) { hits++ }),
	)
	if _, err := mgr.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if hits != 0 {
		t.Fatalf("OnUpdate fired %d times on empty restore, want 0", hits)
	}
}

func TestFeedManager_PeriodicPersistGatedByLeader(t *testing.T) {
	t.Parallel()
	// A follower (leader check false) skips the PERIODIC flush but
	// must STILL perform the shutdown flush: on graceful shutdown the
	// elector relinquishes off the same context cancellation, so the
	// node may no longer report leader by the time the final flush
	// runs — gating it would silently drop the freshest snapshot.
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "evil.example.com", 0.9))
	fp := &fakePersister{}
	mgr := NewFeedManager(store, nil,
		WithPersister(fp, time.Hour),
		WithLeaderCheck(func() bool { return false }),
	)

	mgr.flushPersist(context.Background(), "interval")
	if _, calls := fp.snapshot(); calls != 0 {
		t.Fatalf("follower periodic flush calls=%d, want 0 (leader-gated)", calls)
	}

	mgr.flushPersist(context.Background(), "shutdown")
	stored, calls := fp.snapshot()
	if calls != 1 {
		t.Fatalf("follower shutdown flush calls=%d, want 1 (exempt from leader gate)", calls)
	}
	if len(stored) != 1 || stored[0].Value != "evil.example.com" {
		t.Fatalf("follower shutdown flush stored %#v, want the single domain", stored)
	}
}

func TestFeedManager_PeriodicPersistRunsWhenLeader(t *testing.T) {
	t.Parallel()
	// A leader (predicate true) flushes on the interval as well.
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "evil.example.com", 0.9))
	fp := &fakePersister{}
	mgr := NewFeedManager(store, nil,
		WithPersister(fp, time.Hour),
		WithLeaderCheck(func() bool { return true }),
	)

	mgr.flushPersist(context.Background(), "interval")
	stored, calls := fp.snapshot()
	if calls != 1 {
		t.Fatalf("leader periodic flush calls=%d, want 1", calls)
	}
	if len(stored) != 1 || stored[0].Value != "evil.example.com" {
		t.Fatalf("leader flush stored %#v, want the single domain", stored)
	}
}

// assertSameSnapshot compares two snapshots by (type,value) identity
// and the enforcement-relevant fields, independent of slice order.
func assertSameSnapshot(t *testing.T, a, b IOCSnapshot) {
	t.Helper()
	index := func(s IOCSnapshot) map[string]IOC {
		m := map[string]IOC{}
		for _, g := range [][]IOC{s.Domains, s.IPs, s.CIDRs, s.URLs, s.Hashes, s.JA3s} {
			for _, ioc := range g {
				m[ioc.Key()] = ioc
			}
		}
		return m
	}
	ma, mb := index(a), index(b)
	if len(ma) != len(mb) {
		t.Fatalf("snapshot size mismatch: %d vs %d", len(ma), len(mb))
	}
	for k, ia := range ma {
		ib, ok := mb[k]
		if !ok {
			t.Fatalf("indicator %q missing after round-trip", k)
		}
		if ia.Confidence != ib.Confidence || ia.Source != ib.Source ||
			ia.ThreatActor != ib.ThreatActor || ia.Campaign != ib.Campaign ||
			ia.HashAlgo != ib.HashAlgo || !ia.LastSeen.Equal(ib.LastSeen) ||
			!ia.ExpiresAt.Equal(ib.ExpiresAt) {
			t.Errorf("indicator %q changed across round-trip:\n got=%#v\nwant=%#v", k, ib, ia)
		}
	}
}
