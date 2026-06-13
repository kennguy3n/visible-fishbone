package hibernation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// memStore is an in-package in-memory hibernation.Store for the unit
// tests; the repository packages have their own (memory + postgres),
// but the controller/coordinator tests only need this minimal one so
// they stay free of any repository dependency.
type memStore struct {
	mu        sync.Mutex
	rows      map[uuid.UUID]Record
	failList  bool
	failWrite bool
}

func newMemStore() *memStore { return &memStore{rows: make(map[uuid.UUID]Record)} }

func (m *memStore) List(context.Context) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failList {
		return nil, errors.New("list boom")
	}
	out := make([]Record, 0, len(m.rows))
	for _, r := range m.rows {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) SetHibernated(_ context.Context, id uuid.UUID, reason string, at time.Time) (Record, error) {
	return m.set(id, StateHibernated, reason, at)
}

func (m *memStore) SetActive(_ context.Context, id uuid.UUID, reason string, at time.Time) (Record, error) {
	return m.set(id, StateActive, reason, at)
}

func (m *memStore) set(id uuid.UUID, state State, reason string, at time.Time) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrite {
		return Record{}, errors.New("write boom")
	}
	rec := m.rows[id]
	rec.TenantID = id
	rec.State = state
	rec.Reason = reason
	rec.UpdatedAt = at
	if state.Hibernated() {
		t := at
		rec.HibernatedAt = &t
	} else {
		t := at
		rec.WokeAt = &t
	}
	m.rows[id] = rec
	return rec, nil
}

func (m *memStore) get(id uuid.UUID) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	return r, ok
}

// listActivity is an in-memory ActivityLister.
type listActivity struct{ acts []TenantActivity }

func (l listActivity) ListTenantActivity(context.Context) ([]TenantActivity, error) {
	return l.acts, nil
}

// recordingSubs records condense/resume calls and can fail on demand.
type recordingSubs struct {
	mu           sync.Mutex
	condensed    []uuid.UUID
	resumed      []uuid.UUID
	failCondense bool
}

func (r *recordingSubs) Condense(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failCondense {
		return errors.New("condense boom")
	}
	r.condensed = append(r.condensed, id)
	return nil
}

func (r *recordingSubs) Resume(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resumed = append(r.resumed, id)
	return nil
}

func dormantClassifier() tenancy.Classifier {
	return tenancy.Classifier{IdleAfter: tenancy.DefaultIdleAfter, DormantAfter: tenancy.DefaultDormantAfter}
}

func ptr(t time.Time) *time.Time { return &t }

// TestControllerHibernatesDormant verifies a dormant tenant is parked
// (state persisted + subs condensed) while an active one is left alone.
func TestControllerHibernatesDormant(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dormant := uuid.New()
	active := uuid.New()
	never := uuid.New() // never seen → dormant

	store := newMemStore()
	subs := &recordingSubs{}
	ctrl, err := New(dormantClassifier(), store,
		listActivity{acts: []TenantActivity{
			{ID: dormant, LastActiveAt: ptr(now.Add(-30 * 24 * time.Hour))},
			{ID: active, LastActiveAt: ptr(now.Add(-time.Hour))},
			{ID: never, LastActiveAt: nil},
		}},
		WithSubscriptionController(subs),
		WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if rec, ok := store.get(dormant); !ok || !rec.State.Hibernated() {
		t.Fatalf("dormant tenant should be hibernated, got %+v ok=%v", rec, ok)
	}
	if rec, ok := store.get(never); !ok || !rec.State.Hibernated() {
		t.Fatalf("never-seen tenant should be hibernated, got %+v ok=%v", rec, ok)
	}
	if rec, ok := store.get(active); ok && rec.State.Hibernated() {
		t.Fatalf("active tenant must not be hibernated, got %+v", rec)
	}
	if len(subs.condensed) != 2 {
		t.Fatalf("expected 2 condense calls, got %d", len(subs.condensed))
	}
}

// TestControllerHibernateFailLeavesActive verifies the fail-safe: a
// failed condense leaves the tenant active and unpersisted.
func TestControllerHibernateFailLeavesActive(t *testing.T) {
	now := time.Now().UTC()
	dormant := uuid.New()
	store := newMemStore()
	subs := &recordingSubs{failCondense: true}
	ctrl, _ := New(dormantClassifier(), store,
		listActivity{acts: []TenantActivity{{ID: dormant, LastActiveAt: ptr(now.Add(-30 * 24 * time.Hour))}}},
		WithSubscriptionController(subs),
		WithClock(func() time.Time { return now }),
	)
	if err := ctrl.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.get(dormant); ok {
		t.Fatal("a failed hibernate must not persist any state (fail-safe toward active)")
	}
}

// TestControllerWakesReactivatedTenant verifies the controller backstop:
// a hibernated tenant that climbs back out of the dormant tier is woken.
func TestControllerWakesReactivatedTenant(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()
	store := newMemStore()
	if _, err := store.SetHibernated(context.Background(), id, "seed", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	subs := &recordingSubs{}
	ctrl, _ := New(dormantClassifier(), store,
		listActivity{acts: []TenantActivity{{ID: id, LastActiveAt: ptr(now)}}}, // active now
		WithSubscriptionController(subs),
		WithClock(func() time.Time { return now }),
	)
	if err := ctrl.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec, _ := store.get(id); rec.State.Hibernated() {
		t.Fatal("reactivated tenant should be woken by the controller backstop")
	}
	if len(subs.resumed) != 1 {
		t.Fatalf("expected 1 resume call, got %d", len(subs.resumed))
	}
}

// TestControllerGaugeCountsStoreHibernatedNotInActivityList verifies the
// hibernated_tenants gauge is seeded from the store's hibernated set, so a
// tenant whose hibernation row outlives its activity row (e.g. soft-deleted,
// excluded by ListTenantActivity) is still counted — matching what the
// Syncer/Registry would carry — rather than silently under-counted.
func TestControllerGaugeCountsStoreHibernatedNotInActivityList(t *testing.T) {
	now := time.Now().UTC()
	inList := uuid.New()  // dormant + in activity list → counted
	ghost := uuid.New()   // hibernated in store but absent from activity list
	leaving := uuid.New() // hibernated but now active → woken, not counted

	store := newMemStore()
	for _, id := range []uuid.UUID{inList, ghost, leaving} {
		if _, err := store.SetHibernated(context.Background(), id, "seed", now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, "sng")
	ctrl, _ := New(dormantClassifier(), store,
		listActivity{acts: []TenantActivity{
			{ID: inList, LastActiveAt: ptr(now.Add(-30 * 24 * time.Hour))}, // still dormant
			{ID: leaving, LastActiveAt: ptr(now)},                          // climbed out
		}},
		WithMetrics(m),
		WithClock(func() time.Time { return now }),
	)
	if err := ctrl.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// inList stays hibernated, ghost stays hibernated (never visited),
	// leaving is woken: 3 seeded - 1 woken = 2.
	if got := testutil.ToFloat64(m.hibernatedTenants); got != 2 {
		t.Fatalf("hibernated_tenants gauge = %v, want 2 (ghost tenant must stay counted)", got)
	}
}

// TestControllerGaugeUnchangedOnFailedWake verifies a failed backstop
// wake (store persist error) does NOT decrement the hibernated_tenants
// gauge: the tenant is still hibernated in the store, so it must stay
// counted until a later cycle actually persists the active state.
func TestControllerGaugeUnchangedOnFailedWake(t *testing.T) {
	now := time.Now().UTC()
	id := uuid.New()
	store := newMemStore()
	if _, err := store.SetHibernated(context.Background(), id, "seed", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	store.failWrite = true // SetActive will now fail

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, "sng")
	ctrl, _ := New(dormantClassifier(), store,
		listActivity{acts: []TenantActivity{{ID: id, LastActiveAt: ptr(now)}}}, // active → wake attempted
		WithMetrics(m),
		WithClock(func() time.Time { return now }),
	)
	if err := ctrl.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.hibernatedTenants); got != 1 {
		t.Fatalf("hibernated_tenants gauge = %v, want 1 (failed wake must not decrement)", got)
	}
}

// TestCoordinatorWakeOnActivity verifies the fast wake path clears the
// registry, persists active, resumes subs, and records a latency.
func TestCoordinatorWakeOnActivity(t *testing.T) {
	id := uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{id})
	store := newMemStore()
	_, _ = store.SetHibernated(context.Background(), id, "seed", time.Now())
	subs := &recordingSubs{}

	clock := time.Now()
	coord := NewCoordinator(reg, store,
		WithCoordinatorSubscriptionController(subs),
		WithCoordinatorClock(func() time.Time { return clock }),
	)

	woke, latency, err := coord.Wake(context.Background(), id, clock.Add(-50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if !woke {
		t.Fatal("expected woke=true for a hibernated tenant")
	}
	if latency != 50*time.Millisecond {
		t.Fatalf("expected 50ms latency, got %s", latency)
	}
	if reg.IsHibernated(id) {
		t.Fatal("registry should be cleared after wake")
	}
	if rec, _ := store.get(id); rec.State.Hibernated() {
		t.Fatal("store should be active after wake")
	}
	if len(subs.resumed) != 1 {
		t.Fatalf("expected 1 resume, got %d", len(subs.resumed))
	}

	// Idempotent: waking an already-active tenant is a no-op.
	woke2, _, err := coord.Wake(context.Background(), id, clock)
	if err != nil {
		t.Fatal(err)
	}
	if woke2 {
		t.Fatal("second wake should report woke=false")
	}
}

// TestCoordinatorNotifyEnqueuesOnlyHibernated verifies Notify is a cheap
// no-op for an active tenant and drives a wake for a parked one.
func TestCoordinatorNotifyEnqueuesOnlyHibernated(t *testing.T) {
	parked := uuid.New()
	live := uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{parked})
	store := newMemStore()
	_, _ = store.SetHibernated(context.Background(), parked, "seed", time.Now())

	coord := NewCoordinator(reg, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coord.Run(ctx)

	coord.Notify(live)   // active: should not enqueue
	coord.Notify(parked) // parked: should wake

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !reg.IsHibernated(parked) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if reg.IsHibernated(parked) {
		t.Fatal("Notify should have woken the parked tenant")
	}
}
