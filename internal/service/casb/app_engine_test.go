package casb_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// The memory and postgres backends must satisfy the service-owned
// NoOpsStore interface. Asserted in the external test package so the
// repository packages stay free of any import of casb (the cycle this
// design avoids).
var (
	_ casb.NoOpsStore = (*memory.CASBNoOpsStore)(nil)
	_ casb.NoOpsStore = (*postgres.CASBNoOpsStore)(nil)
)

// fakeEnforcer records EnsureProtection calls and returns a scripted
// result, standing in for *appdb.Service.
type fakeEnforcer struct {
	mu      sync.Mutex
	calls   []enforceCall
	created bool
	err     error
}

type enforceCall struct {
	tenantID uuid.UUID
	probe    string
	domains  []string
	target   repository.TrafficClass
}

func (f *fakeEnforcer) EnsureProtection(_ context.Context, tenantID uuid.UUID, _ *uuid.UUID, probe string, domains []string, target repository.TrafficClass, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, enforceCall{tenantID, probe, domains, target})
	return f.created, f.err
}

func (f *fakeEnforcer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type engineFixture struct {
	store    *memory.CASBNoOpsStore
	apps     *memory.CASBDiscoveredAppRepository
	tenants  *memory.TenantRepository
	audit    *memory.AuditLogRepository
	enforcer *fakeEnforcer
	engine   *casb.AppNoOpsEngine
	clock    time.Time
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	s := memory.NewStore()
	fx := &engineFixture{
		store:    memory.NewCASBNoOpsStore(),
		apps:     memory.NewCASBDiscoveredAppRepository(s),
		tenants:  memory.NewTenantRepository(s),
		audit:    memory.NewAuditLogRepository(s),
		enforcer: &fakeEnforcer{},
		clock:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	fx.engine = casb.NewAppNoOpsEngine(fx.store, fx.apps, fx.tenants, nil)
	fx.engine.SetClock(func() time.Time { return fx.clock })
	return fx
}

func (fx *engineFixture) newTenant(t *testing.T) uuid.UUID {
	t.Helper()
	tn, err := fx.tenants.Create(context.Background(), repository.Tenant{Name: "t-" + uuid.NewString()[:8], Slug: uuid.NewString()[:12]})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

func TestOnAppDiscovered_AutoProtectsHighRiskUnsanctioned(t *testing.T) {
	fx := newEngineFixture(t)
	fx.enforcer.created = true
	fx.engine.SetEnforcer(fx.enforcer)
	fx.engine.SetAuditLog(fx.audit)
	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 12
	app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
	meta := casb.AppDiscoveryMeta{Domains: []string{"telegram.org"}}
	fx.engine.OnAppDiscovered(ctx, tid, app, meta)

	// Classification persisted.
	cls, err := fx.store.GetClassification(ctx, tid, "Telegram")
	if err != nil {
		t.Fatalf("GetClassification: %v", err)
	}
	if cls.Sanction != casb.SanctionUnsanctioned {
		t.Fatalf("sanction = %q, want unsanctioned", cls.Sanction)
	}

	// One auto action recorded and applied.
	actions, err := fx.store.ListActions(ctx, tid, 10)
	if err != nil {
		t.Fatalf("ListActions: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	a := actions[0]
	if a.Mode != casb.ActionModeAuto || !a.Applied {
		t.Fatalf("action mode=%s applied=%v, want auto+applied", a.Mode, a.Applied)
	}
	if a.Enforcement != casb.ActionProtect || a.TrafficClass != repository.TrafficClassInspectFull {
		t.Fatalf("enforcement=%s class=%s, want protect/inspect_full", a.Enforcement, a.TrafficClass)
	}

	// Enforcer called with wildcard domain and inspect_full target.
	if fx.enforcer.callCount() != 1 {
		t.Fatalf("enforcer calls = %d, want 1", fx.enforcer.callCount())
	}
	call := fx.enforcer.calls[0]
	if call.target != repository.TrafficClassInspectFull {
		t.Fatalf("target = %s, want inspect_full", call.target)
	}
	if len(call.domains) != 1 || call.domains[0] != "*.telegram.org" {
		t.Fatalf("domains = %v, want [*.telegram.org]", call.domains)
	}

	// Global audit row written.
	page, err := fx.audit.List(ctx, tid, repository.AuditFilter{}, repository.Page{})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Action != "casb.app_noops_auto" {
		t.Fatalf("audit = %+v, want one casb.app_noops_auto", page.Items)
	}
}

func TestOnAppDiscovered_ConnectorSanctionedNoAction(t *testing.T) {
	fx := newEngineFixture(t)
	fx.engine.SetEnforcer(fx.enforcer)
	tid := fx.newTenant(t)
	ctx := context.Background()

	app := repository.CASBDiscoveredApp{Name: "GitHub", Category: "code_repository"}
	meta := casb.AppDiscoveryMeta{Domains: []string{"github.com"}, HasConnector: true}
	fx.engine.OnAppDiscovered(ctx, tid, app, meta)

	cls, err := fx.store.GetClassification(ctx, tid, "GitHub")
	if err != nil {
		t.Fatalf("GetClassification: %v", err)
	}
	if cls.Sanction != casb.SanctionSanctioned {
		t.Fatalf("sanction = %q, want sanctioned", cls.Sanction)
	}
	// Sanctioned sensitive (code_repository) => route recommendation, never auto.
	actions, _ := fx.store.ListActions(ctx, tid, 10)
	for _, a := range actions {
		if a.Mode == casb.ActionModeAuto {
			t.Fatalf("sanctioned app got an auto action: %+v", a)
		}
	}
	if fx.enforcer.callCount() != 0 {
		t.Fatalf("enforcer called %d times for sanctioned app, want 0", fx.enforcer.callCount())
	}
}

func TestOnAppDiscovered_NoEnforcerDegradesToRecommend(t *testing.T) {
	fx := newEngineFixture(t)
	// No enforcer wired.
	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 12
	app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
	meta := casb.AppDiscoveryMeta{Domains: []string{"telegram.org"}}
	fx.engine.OnAppDiscovered(ctx, tid, app, meta)

	actions, _ := fx.store.ListActions(ctx, tid, 10)
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	if actions[0].Mode != casb.ActionModeRecommend || actions[0].Applied {
		t.Fatalf("without enforcer want recommend+!applied, got mode=%s applied=%v", actions[0].Mode, actions[0].Applied)
	}
}

func TestOnAppDiscovered_AppendOnlyHistory(t *testing.T) {
	fx := newEngineFixture(t)
	fx.enforcer.created = true
	fx.engine.SetEnforcer(fx.enforcer)
	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 12
	app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
	meta := casb.AppDiscoveryMeta{Domains: []string{"telegram.org"}}

	fx.engine.OnAppDiscovered(ctx, tid, app, meta)
	fx.clock = fx.clock.Add(time.Hour)
	fx.engine.OnAppDiscovered(ctx, tid, app, meta)

	actions, _ := fx.store.ListActions(ctx, tid, 10)
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2 (append-only)", len(actions))
	}
	// Newest first.
	if !actions[0].CreatedAt.After(actions[1].CreatedAt) {
		t.Fatalf("ListActions not newest-first: %v then %v", actions[0].CreatedAt, actions[1].CreatedAt)
	}
}

func TestReconcileTenant_ProcessesInventory(t *testing.T) {
	fx := newEngineFixture(t)
	fx.engine.SetEnforcer(fx.enforcer)
	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 9
	for _, app := range []repository.CASBDiscoveredApp{
		{Name: "WeTransfer", Category: "file_transfer", ActiveDeviceCount: &devices},
		{Name: "Zoom", Category: "conferencing"},
	} {
		if _, err := fx.apps.Upsert(ctx, tid, app); err != nil {
			t.Fatalf("seed app: %v", err)
		}
	}

	if err := fx.engine.ReconcileTenant(ctx, tid); err != nil {
		t.Fatalf("ReconcileTenant: %v", err)
	}
	cls, err := fx.store.ListClassifications(ctx, tid)
	if err != nil {
		t.Fatalf("ListClassifications: %v", err)
	}
	if len(cls) != 2 {
		t.Fatalf("got %d classifications, want 2", len(cls))
	}
}

func TestReconcile_SkipsInactiveTenants(t *testing.T) {
	fx := newEngineFixture(t)
	ctx := context.Background()
	active := fx.newTenant(t)
	devices := 9
	if _, err := fx.apps.Upsert(ctx, active, repository.CASBDiscoveredApp{Name: "WeTransfer", Category: "file_transfer", ActiveDeviceCount: &devices}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := fx.engine.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	cls, _ := fx.store.ListClassifications(ctx, active)
	if len(cls) != 1 {
		t.Fatalf("active tenant classifications = %d, want 1", len(cls))
	}
}

func TestBuildDigest_SummariseAndAdvanceCursor(t *testing.T) {
	fx := newEngineFixture(t)
	fx.enforcer.created = true
	fx.engine.SetEnforcer(fx.enforcer)
	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 12
	fx.engine.OnAppDiscovered(ctx, tid, repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}, casb.AppDiscoveryMeta{Domains: []string{"telegram.org"}})

	fx.clock = fx.clock.Add(time.Minute)
	d1, err := fx.engine.BuildDigest(ctx, tid)
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	if d1.Actions != 1 || d1.AutoApplied != 1 {
		t.Fatalf("digest actions=%d auto=%d, want 1/1", d1.Actions, d1.AutoApplied)
	}
	if d1.DiscoveredApps != 1 {
		t.Fatalf("discovered apps = %d, want 1", d1.DiscoveredApps)
	}

	// Second digest with no new actions covers nothing.
	fx.clock = fx.clock.Add(time.Minute)
	d2, err := fx.engine.BuildDigest(ctx, tid)
	if err != nil {
		t.Fatalf("BuildDigest 2: %v", err)
	}
	if d2.Actions != 0 {
		t.Fatalf("second digest actions = %d, want 0 (cursor advanced)", d2.Actions)
	}
}
