package ai

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

type stubRetroTenantLister struct {
	tenants []uuid.UUID
	err     error
}

func (s *stubRetroTenantLister) ListRetroHuntTenants(_ context.Context) ([]uuid.UUID, error) {
	return s.tenants, s.err
}

type captureSink struct {
	mu      sync.Mutex
	reports []RetroReport
}

func (c *captureSink) EmitRetroReport(_ context.Context, r RetroReport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, r)
}

func (c *captureSink) all() []RetroReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]RetroReport, len(c.reports))
	copy(out, c.reports)
	return out
}

func newTestCoordinator(t *testing.T, store *IOCStore, src RetroEventSource, tenants []uuid.UUID, sink RetroHitSink) *RetroHuntCoordinator {
	t.Helper()
	c := NewRetroHuntCoordinator(RetroHuntConfig{
		Hunter:        NewRetroHunter(src),
		Snapshot:      store.Snapshot,
		Tenants:       &stubRetroTenantLister{tenants: tenants},
		Sink:          sink,
		Lookback:      24 * time.Hour,
		MinConfidence: 0.5,
		Now:           func() time.Time { return time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC) },
	})
	if c == nil {
		t.Fatal("NewRetroHuntCoordinator returned nil")
	}
	return c
}

func TestRetroCoordinator_FirstTickPrimesWithoutHunting(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "preexisting.example", 0.9))
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC), "preexisting.example"),
	}}
	sink := &captureSink{}
	c := newTestCoordinator(t, store, src, []uuid.UUID{uuid.New()}, sink)

	if err := c.Tick(context.Background()); err != nil {
		t.Fatalf("prime tick: %v", err)
	}
	if src.calls != 0 {
		t.Errorf("baseline tick queried the event source %d times, want 0", src.calls)
	}
	if len(sink.all()) != 0 {
		t.Errorf("baseline tick emitted %d reports, want 0", len(sink.all()))
	}
}

func TestRetroCoordinator_HuntsOnlyNewIndicators(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "preexisting.example", 0.9))
	hitTime := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, hitTime, "preexisting.example"), // would hit, but already baselined
		dnsEnvelope(t, hitTime, "fresh-c2.example"),    // the new indicator
	}}
	sink := &captureSink{}
	tenant := uuid.New()
	c := newTestCoordinator(t, store, src, []uuid.UUID{tenant}, sink)

	// Prime baseline (records preexisting.example as seen).
	if err := c.Tick(context.Background()); err != nil {
		t.Fatalf("prime tick: %v", err)
	}
	// A new indicator lands.
	store.Upsert(mkIOC(IOCTypeDomain, "fresh-c2.example", 0.9))
	if err := c.Tick(context.Background()); err != nil {
		t.Fatalf("hunt tick: %v", err)
	}

	reports := sink.all()
	if len(reports) != 1 {
		t.Fatalf("emitted %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.TenantID != tenant {
		t.Errorf("report tenant = %s, want %s", r.TenantID, tenant)
	}
	if len(r.Hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(r.Hits))
	}
	if r.Hits[0].Indicator != "fresh-c2.example" {
		t.Errorf("hit indicator = %q, want fresh-c2.example", r.Hits[0].Indicator)
	}
}

func TestRetroCoordinator_NoNewIndicatorsSkipsSweep(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(mkIOC(IOCTypeDomain, "preexisting.example", 0.9))
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC), "preexisting.example"),
	}}
	sink := &captureSink{}
	c := newTestCoordinator(t, store, src, []uuid.UUID{uuid.New()}, sink)

	if err := c.Tick(context.Background()); err != nil { // prime
		t.Fatalf("prime tick: %v", err)
	}
	if err := c.Tick(context.Background()); err != nil { // no change
		t.Fatalf("steady tick: %v", err)
	}
	if src.calls != 0 {
		t.Errorf("steady-state tick queried the event source %d times, want 0", src.calls)
	}
	if len(sink.all()) != 0 {
		t.Errorf("steady-state tick emitted %d reports, want 0", len(sink.all()))
	}
}

func TestRetroCoordinator_EachIndicatorHuntedOnce(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	src := &stubEventSource{}
	sink := &captureSink{}
	c := newTestCoordinator(t, store, src, []uuid.UUID{uuid.New()}, sink)

	if err := c.Tick(context.Background()); err != nil { // prime (empty store)
		t.Fatalf("prime tick: %v", err)
	}
	store.Upsert(mkIOC(IOCTypeDomain, "fresh.example", 0.9))
	if err := c.Tick(context.Background()); err != nil {
		t.Fatalf("first hunt: %v", err)
	}
	firstCalls := src.calls
	if firstCalls == 0 {
		t.Fatal("expected the new indicator to trigger a sweep")
	}
	// Same indicator still present; must not be re-hunted.
	if err := c.Tick(context.Background()); err != nil {
		t.Fatalf("second hunt: %v", err)
	}
	if src.calls != firstCalls {
		t.Errorf("indicator re-hunted: calls went %d -> %d", firstCalls, src.calls)
	}
}

func TestRetroCoordinator_MissingDepsReturnsNil(t *testing.T) {
	t.Parallel()
	if c := NewRetroHuntCoordinator(RetroHuntConfig{}); c != nil {
		t.Error("expected nil coordinator when required deps are missing")
	}
}
