package casb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestMatchHost(t *testing.T) {
	cases := []struct {
		host    string
		wantApp string
		wantHit bool
	}{
		{"slack.com", "Slack", true},
		{"acme.slack.com", "Slack", true},
		{"files.edge.acme.slack.com", "Slack", true},
		{"SLACK.COM.", "Slack", true},              // case + trailing dot
		{"web.telegram.org:443", "Telegram", true}, // port stripped
		{"console.aws.amazon.com", "AWS Console", true},
		{"aws.amazon.com", "", false}, // bare apex is not a console host
		{"acme.atlassian.net", "Atlassian Cloud", true},
		{"drive.google.com", "Google Workspace", true},
		{"www.google.com", "", false}, // search, not Workspace
		{"example.com", "", false},
		{"", "", false},
		{"localhost", "", false},
	}
	for _, c := range cases {
		app, ok := matchHost(c.host)
		if ok != c.wantHit || app.Name != c.wantApp {
			t.Errorf("matchHost(%q) = (%q,%v), want (%q,%v)", c.host, app.Name, ok, c.wantApp, c.wantHit)
		}
	}
}

// fakeAppRepo captures Upsert calls for assertions.
type fakeAppRepo struct {
	mu      sync.Mutex
	upserts []repository.CASBDiscoveredApp
	tenants []uuid.UUID
	err     error
}

func (f *fakeAppRepo) Upsert(ctx context.Context, tenantID uuid.UUID, app repository.CASBDiscoveredApp) (repository.CASBDiscoveredApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return repository.CASBDiscoveredApp{}, f.err
	}
	app.ID = uuid.New()
	app.TenantID = tenantID
	f.upserts = append(f.upserts, app)
	f.tenants = append(f.tenants, tenantID)
	return app, nil
}

func (f *fakeAppRepo) find(name string) (repository.CASBDiscoveredApp, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.upserts {
		if a.Name == name {
			return a, true
		}
	}
	return repository.CASBDiscoveredApp{}, false
}

func TestShadowIT_ObserveAndFlush(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	tenant := uuid.New()
	dev1, dev2 := uuid.New(), uuid.New()
	t0 := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)

	// Two devices on Slack, one on GitHub. A non-SaaS host is ignored.
	d.ObserveHost(tenant, dev1, "acme.slack.com", t0)
	d.ObserveHost(tenant, dev2, "slack.com", t0.Add(time.Minute))
	d.ObserveHost(tenant, dev1, "slack.com", t0.Add(2*time.Minute)) // duplicate device
	d.ObserveHost(tenant, dev1, "github.com", t0.Add(3*time.Minute))
	d.ObserveHost(tenant, dev1, "example.com", t0.Add(4*time.Minute)) // ignored

	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	slack, ok := repo.find("Slack")
	if !ok {
		t.Fatal("expected Slack discovered app")
	}
	if slack.UsersCount != 2 {
		t.Errorf("Slack users_count = %d, want 2 (distinct devices)", slack.UsersCount)
	}
	if slack.Vendor != "Slack" || slack.Category != "collaboration" {
		t.Errorf("Slack metadata wrong: %+v", slack)
	}
	if slack.RiskScore == nil || *slack.RiskScore != 35 {
		t.Errorf("Slack risk = %v, want 35", slack.RiskScore)
	}
	if !slack.FirstSeen.Equal(t0) || !slack.LastSeen.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("Slack seen window wrong: first=%v last=%v", slack.FirstSeen, slack.LastSeen)
	}

	gh, ok := repo.find("GitHub")
	if !ok || gh.UsersCount != 1 {
		t.Errorf("expected GitHub with 1 device, got ok=%v %+v", ok, gh)
	}
	if _, ok := repo.find("example.com"); ok {
		t.Error("non-SaaS host should not be discovered")
	}
}

func TestShadowIT_FlushResetsWindow(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	tenant := uuid.New()

	d.ObserveHost(tenant, uuid.New(), "slack.com", time.Now())
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush 1: %v", err)
	}
	// Second flush with no new observations must not re-upsert.
	repo.mu.Lock()
	n := len(repo.upserts)
	repo.mu.Unlock()
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.upserts) != n {
		t.Errorf("empty window should not upsert: before=%d after=%d", n, len(repo.upserts))
	}
}

func TestShadowIT_TenantIsolation(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	tA, tB := uuid.New(), uuid.New()
	d.ObserveHost(tA, uuid.New(), "slack.com", time.Now())
	d.ObserveHost(tB, uuid.New(), "slack.com", time.Now())
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.tenants) != 2 || repo.tenants[0] == repo.tenants[1] {
		t.Fatalf("expected one upsert per tenant, got tenants=%v", repo.tenants)
	}
}

func TestShadowIT_FlushReturnsUpsertError(t *testing.T) {
	repo := &fakeAppRepo{err: errors.New("db down")}
	d := NewShadowITDiscoverer(repo, nil)
	d.ObserveHost(uuid.New(), uuid.New(), "slack.com", time.Now())
	if err := d.Flush(context.Background()); err == nil {
		t.Fatal("expected error from failing upsert")
	}
}

func TestShadowIT_NilTenantIgnored(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	d.ObserveHost(uuid.Nil, uuid.New(), "slack.com", time.Now())
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.upserts) != 0 {
		t.Errorf("nil tenant should be ignored, got %d upserts", len(repo.upserts))
	}
}

// TestShadowIT_StopFlushesFinalWindow locks in the shutdown-ordering
// guarantee: the loop's lifetime is controlled solely by Stop (not a
// process context), and Stop performs a final flush of observations
// made after Start even when the ticker never fired. This is the
// window that would be silently dropped if the loop exited on rootCtx
// cancellation while the telemetry consumer was still feeding it.
func TestShadowIT_StopFlushesFinalWindow(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	tenant := uuid.New()

	// A long interval guarantees the periodic ticker never fires, so
	// the only thing that can persist the observation is Stop's final
	// flush.
	d.Start(time.Hour)
	d.ObserveHost(tenant, uuid.New(), "slack.com", time.Now())
	d.Stop()

	if _, ok := repo.find("Slack"); !ok {
		t.Fatal("Stop must flush the final window; Slack observation was dropped")
	}
	// Stop is idempotent and must not block or double-flush.
	repo.mu.Lock()
	n := len(repo.upserts)
	repo.mu.Unlock()
	d.Stop()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.upserts) != n {
		t.Errorf("second Stop should be a no-op: before=%d after=%d", n, len(repo.upserts))
	}
}

func TestShadowIT_ConcurrentObserve(t *testing.T) {
	repo := &fakeAppRepo{}
	d := NewShadowITDiscoverer(repo, nil)
	tenant := uuid.New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.ObserveHost(tenant, uuid.New(), "acme.slack.com", time.Now())
		}()
	}
	wg.Wait()
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	slack, ok := repo.find("Slack")
	if !ok || slack.UsersCount != 50 {
		t.Errorf("expected 50 distinct devices, got ok=%v count=%d", ok, slack.UsersCount)
	}
}
