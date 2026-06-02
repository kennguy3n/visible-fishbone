package appdb_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/appdb"
)

// newTestService builds an in-memory Service plus a tenant ID.
func newTestService(t *testing.T) (*appdb.Service, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "t-" + uuid.NewString()[:8],
		Slug: "t-" + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	svc := appdb.New(
		memory.NewAppRegistryRepository(s),
		memory.NewAppRegistryOverrideRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
	)
	return svc, tn.ID
}

func seedApp(t *testing.T, svc *appdb.Service, name string, cls repository.TrafficClass, domains ...string) repository.AppRegistry {
	t.Helper()
	app, err := svc.CreateApp(context.Background(), repository.AppRegistry{
		Name:         name,
		Vendor:       "test",
		TrafficClass: cls,
		Scope:        repository.AppRegistryScopeGlobal,
		Domains:      domains,
		IsSystem:     true,
	})
	if err != nil {
		t.Fatalf("seed app %q: %v", name, err)
	}
	return app
}

// TestResolveTrafficClass_Global covers the no-override path: a
// domain that matches a global app inherits that app's class.
func TestResolveTrafficClass_Global(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "outlook.office.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassTrustedDirect {
		t.Fatalf("class = %q, want trusted_direct", cls)
	}
}

// TestResolveTrafficClass_OverrideWins covers the tenant-override
// priority: a per-tenant demotion overrides the global class.
func TestResolveTrafficClass_OverrideWins(t *testing.T) {
	svc, tenantID := newTestService(t)
	app := seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")

	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		AppID:                &app.ID,
		TrafficClassOverride: repository.TrafficClassInspectFull,
		Reason:               "operator-mandated TLS inspection",
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "outlook.office.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("class = %q, want inspect_full", cls)
	}
}

// TestResolveTrafficClass_CustomDomainOverride covers the
// custom-domain path: an override that names a domain not present
// in the global catalog still applies.
func TestResolveTrafficClass_CustomDomainOverride(t *testing.T) {
	svc, tenantID := newTestService(t)
	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		CustomDomains:        []string{"shadow-it.example.com"},
		TrafficClassOverride: repository.TrafficClassBlock,
		Reason:               "shadow IT",
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "shadow-it.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassBlock {
		t.Fatalf("class = %q, want block", cls)
	}
}

// TestResolveTrafficClass_NoMatch falls back to inspect_full when
// nothing matches.
func TestResolveTrafficClass_NoMatch(t *testing.T) {
	svc, tenantID := newTestService(t)
	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "unknown.example.org")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("class = %q, want inspect_full", cls)
	}
}

// TestResolveTrafficClass_WildcardSuffix verifies that a wildcard
// pattern matches both the bare apex and nested subdomains.
func TestResolveTrafficClass_WildcardSuffix(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Slack", repository.TrafficClassTrustedDirect, "*.slack.com")

	for _, d := range []string{"slack.com", "files.slack.com", "edge.files.slack.com"} {
		cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, d)
		if err != nil {
			t.Fatalf("resolve %q: %v", d, err)
		}
		if cls != repository.TrafficClassTrustedDirect {
			t.Fatalf("resolve %q: class = %q, want trusted_direct", d, cls)
		}
	}
}

// TestCompileSteeringRules_TargetFiltering covers the per-target
// behaviour: the cloud target should not receive trusted_direct
// rules (those flows never reach the cloud proxy), while edge
// receives every class.
func TestCompileSteeringRules_TargetFiltering(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")
	seedApp(t, svc, "Generic", repository.TrafficClassInspectFull, "shop.example.com")

	edge, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if err != nil {
		t.Fatalf("compile edge: %v", err)
	}
	cloud, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetCloud)
	if err != nil {
		t.Fatalf("compile cloud: %v", err)
	}

	edgeClasses := classSet(edge)
	if !edgeClasses[repository.TrafficClassTrustedDirect] {
		t.Errorf("edge bundle missing trusted_direct: %v", edgeClasses)
	}
	if !edgeClasses[repository.TrafficClassInspectFull] {
		t.Errorf("edge bundle missing inspect_full: %v", edgeClasses)
	}

	cloudClasses := classSet(cloud)
	if cloudClasses[repository.TrafficClassTrustedDirect] {
		t.Errorf("cloud bundle should not carry trusted_direct: %v", cloudClasses)
	}
	if !cloudClasses[repository.TrafficClassInspectFull] {
		t.Errorf("cloud bundle missing inspect_full: %v", cloudClasses)
	}
}

func classSet(rs appdb.SteeringRuleSet) map[repository.TrafficClass]bool {
	out := map[repository.TrafficClass]bool{}
	for _, c := range rs.Classes {
		if len(c.Domains) > 0 || len(c.IPRanges) > 0 || len(c.Apps) > 0 {
			out[c.Class] = true
		}
	}
	return out
}

// TestCompileSteeringRules_ByteDeterminism re-compiles the same
// catalog twice and verifies the JSON bytes are identical.
func TestCompileSteeringRules_ByteDeterminism(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com", "outlook.office365.com")
	seedApp(t, svc, "Slack", repository.TrafficClassTrustedDirect, "*.slack.com")
	seedApp(t, svc, "YouTube", repository.TrafficClassTrustedMediaBypass, "*.youtube.com", "*.googlevideo.com")
	seedApp(t, svc, "Akamai", repository.TrafficClassInspectLite, "*.akamai.net")

	a, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if err != nil {
		t.Fatalf("compile a: %v", err)
	}
	b, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if err != nil {
		t.Fatalf("compile b: %v", err)
	}
	aBytes, err := a.Encode()
	if err != nil {
		t.Fatalf("encode a: %v", err)
	}
	bBytes, err := b.Encode()
	if err != nil {
		t.Fatalf("encode b: %v", err)
	}
	if string(aBytes) != string(bBytes) {
		t.Fatalf("non-deterministic encode:\n a=%s\n b=%s", aBytes, bBytes)
	}

	// Sanity: domains in each class are in sorted order.
	for _, c := range a.Classes {
		if !sort.StringsAreSorted(c.Domains) {
			t.Errorf("class %s: domains not sorted: %v", c.Class, c.Domains)
		}
		if !sort.StringsAreSorted(c.IPRanges) {
			t.Errorf("class %s: ip_ranges not sorted: %v", c.Class, c.IPRanges)
		}
	}
}

// TestCompileSteeringRules_IncludesIPRanges verifies that IP
// ranges seeded on the app land in the per-class bucket.
func TestCompileSteeringRules_IncludesIPRanges(t *testing.T) {
	svc, tenantID := newTestService(t)
	app := seedApp(t, svc, "GoogleMail", repository.TrafficClassTrustedDirect, "*.googlemail.com")
	app.IPRanges = []netip.Prefix{
		netip.MustParsePrefix("142.250.0.0/15"),
		netip.MustParsePrefix("2607:f8b0::/32"),
	}
	if _, err := svc.UpdateApp(context.Background(), app); err != nil {
		t.Fatalf("update: %v", err)
	}

	rs, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	found := false
	for _, c := range rs.Classes {
		if c.Class != repository.TrafficClassTrustedDirect {
			continue
		}
		for _, r := range c.IPRanges {
			if r == "142.250.0.0/15" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("missing 142.250.0.0/15 in trusted_direct bucket")
	}
}

// TestExpiringOverrideSweep verifies DeleteExpired removes
// overrides whose ExpiresAt has passed.
func TestExpiringOverrideSweep(t *testing.T) {
	svc, tenantID := newTestService(t)
	app := seedApp(t, svc, "Acme", repository.TrafficClassTrustedDirect, "*.acme.example")
	past := time.Now().Add(-1 * time.Hour)
	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		AppID:                &app.ID,
		TrafficClassOverride: repository.TrafficClassInspectFull,
		Reason:               "transient signal",
		ExpiresAt:            &past,
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	store := memory.NewAuditLogRepository(memory.NewStore()) // unused: just to keep references stable
	_ = store
	// The Service does not expose DeleteExpired directly today —
	// the demotion engine does. Verify via the engine.
	eng := appdb.NewDemotionEngine(svc, fakeTenantRepo{tn: tenantID}, appdb.NoopPublisher{}, appdb.DemotionPolicy{})
	n, err := eng.SweepExpired(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n == 0 {
		t.Fatalf("sweep removed nothing, expected the expired row to be cleaned up")
	}
}

// fakeTenantRepo satisfies the subset of repository.TenantRepository
// the demotion engine touches. The remaining methods return zero
// values so the fake compiles against the full interface — the
// engine never calls them.
type fakeTenantRepo struct{ tn uuid.UUID }

func (f fakeTenantRepo) Create(context.Context, repository.Tenant) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) Get(context.Context, uuid.UUID) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) GetBySlug(context.Context, string) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) Update(context.Context, uuid.UUID, repository.TenantPatch) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) UpdateSettingsKey(context.Context, uuid.UUID, string, json.RawMessage) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) DeleteSettingsKey(context.Context, uuid.UUID, string) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) UpdateStatus(context.Context, uuid.UUID, repository.TenantStatus) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) TransitionStatus(context.Context, uuid.UUID, repository.TenantStatus, repository.TenantStatus) (repository.Tenant, error) {
	return repository.Tenant{}, nil
}
func (f fakeTenantRepo) Delete(context.Context, uuid.UUID) error { return nil }
func (f fakeTenantRepo) List(context.Context, repository.Page) (repository.PageResult[repository.Tenant], error) {
	return repository.PageResult[repository.Tenant]{
		Items: []repository.Tenant{{ID: f.tn, Status: repository.TenantStatusActive}},
	}, nil
}

// TestDemotionEngine_TenantSignal installs a tenant-scoped override
// when a tenant-local signal (anomaly) is processed.
func TestDemotionEngine_TenantSignal(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Box", repository.TrafficClassTrustedDirect, "*.box.com")
	eng := appdb.NewDemotionEngine(svc, fakeTenantRepo{tn: tenantID}, appdb.NoopPublisher{}, appdb.DefaultDemotionPolicy())

	installed, err := eng.Apply(context.Background(), appdb.DemotionEvent{
		TenantID:    tenantID,
		Domain:      "files.box.com",
		Signal:      appdb.SignalAnomaly,
		TargetClass: repository.TrafficClassInspectFull,
		Reason:      "exfiltration pattern",
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(installed) != 1 {
		t.Fatalf("installed %d overrides, want 1", len(installed))
	}

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "files.box.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("class = %q, want inspect_full after demotion", cls)
	}
}

// TestDemotionEngine_GlobalSignal installs an override for every
// active tenant when a global signal fires.
func TestDemotionEngine_GlobalSignal(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Edge", repository.TrafficClassTrustedDirect, "*.edge.example")
	eng := appdb.NewDemotionEngine(svc, fakeTenantRepo{tn: tenantID}, appdb.NoopPublisher{}, appdb.DefaultDemotionPolicy())

	installed, err := eng.Apply(context.Background(), appdb.DemotionEvent{
		Domain: "cdn.edge.example",
		Signal: appdb.SignalThreatFeed,
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(installed) != 1 {
		t.Fatalf("installed %d overrides for fake single-tenant repo, want 1", len(installed))
	}
}

// captureAudit is a test-only AuditLogRepository that records
// every Append call, including the ones the Postgres + memory
// audit_log impls reject because they enforce a NOT-NULL
// tenant_id. Global app-catalog mutations (CreateApp,
// UpdateApp, SyncUpdateApp, DeleteApp) write with tenantID =
// uuid.Nil; we use this capture in tests so the audit-emission
// invariant is verifiable without depending on the schema
// extension that would let global audit rows land in the real
// audit_log table.
type captureAudit struct {
	entries []repository.AuditEntry
}

func (c *captureAudit) Append(_ context.Context, tenantID uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error) {
	e.TenantID = tenantID
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	c.entries = append(c.entries, e)
	return e, nil
}

func (c *captureAudit) List(context.Context, uuid.UUID, repository.AuditFilter, repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	return repository.PageResult[repository.AuditEntry]{Items: c.entries}, nil
}

// TestSyncUpdateApp_EmitsAuditEntry verifies that a sync-driven
// app update goes through the SyncUpdateApp method and writes an
// `app.synced` audit-log row with the canonical before/after
// counts — i.e. the audit-bypass that the syncer used to have
// (direct apps.Update call) cannot regress.
func TestSyncUpdateApp_EmitsAuditEntry(t *testing.T) {
	s := memory.NewStore()
	audit := &captureAudit{}
	svc := appdb.New(
		memory.NewAppRegistryRepository(s),
		memory.NewAppRegistryOverrideRepository(s),
		audit,
		nil,
	)
	app, err := svc.CreateApp(context.Background(), repository.AppRegistry{
		Name:         "Office",
		TrafficClass: repository.TrafficClassTrustedDirect,
		Scope:        repository.AppRegistryScopeGlobal,
		Domains:      []string{"*.office.com"},
		IsSystem:     true,
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	// Reset so we only see the sync entry.
	audit.entries = nil

	app.MetadataURL = "https://endpoints.office.com/endpoints/worldwide"
	app.Domains = []string{"*.office.com", "outlook.office365.com"}
	if _, err := svc.SyncUpdateApp(context.Background(), app, appdb.SyncAppMetadata{
		Source:         "endpoints.office.com",
		DomainsBefore:  1,
		DomainsAfter:   2,
		IPRangesBefore: 0,
		IPRangesAfter:  3,
	}); err != nil {
		t.Fatalf("sync update: %v", err)
	}

	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want exactly 1 `app.synced` row", len(audit.entries))
	}
	got := audit.entries[0]
	if got.Action != "app.synced" {
		t.Fatalf("audit action = %q, want app.synced", got.Action)
	}
	if got.ResourceType != "app_registry" {
		t.Fatalf("audit resource_type = %q, want app_registry", got.ResourceType)
	}
	if got.ResourceID == nil || *got.ResourceID != app.ID {
		t.Fatalf("audit resource_id = %v, want %s", got.ResourceID, app.ID)
	}
	var details map[string]any
	if err := json.Unmarshal(got.Details, &details); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if details["source"] != "endpoints.office.com" {
		t.Fatalf("audit source = %v, want endpoints.office.com", details["source"])
	}
	if d := details["domains_after"].(float64); d != 2 {
		t.Fatalf("audit domains_after = %v, want 2", d)
	}
	if d := details["ip_ranges_after"].(float64); d != 3 {
		t.Fatalf("audit ip_ranges_after = %v, want 3", d)
	}
}

// TestSteeringSnapshot_ReusedAcrossTargets verifies that a single
// snapshot can produce per-target rule sets for every bundle
// target and that those outputs are byte-identical to the
// single-shot CompileSteeringRules path. The intent is the
// performance fix called out in Devin Review on commit 02765a2:
// the policy compiler creates one snapshot and reuses it for all
// four targets instead of repeating the ListAll reads per target.
func TestSteeringSnapshot_ReusedAcrossTargets(t *testing.T) {
	svc, tenantID := newTestService(t)
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")
	seedApp(t, svc, "Generic", repository.TrafficClassInspectFull, "shop.example.com")
	seedApp(t, svc, "YouTube", repository.TrafficClassTrustedMediaBypass, "*.youtube.com")

	snap, err := svc.NewSteeringSnapshot(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	targets := []repository.PolicyBundleTarget{
		repository.PolicyBundleTargetEdge,
		repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud,
		repository.PolicyBundleTargetMobile,
	}
	for _, target := range targets {
		fromSnap, err := snap.CompileForTarget(target)
		if err != nil {
			t.Fatalf("snapshot compile %s: %v", target, err)
		}
		fromSingle, err := svc.CompileSteeringRules(context.Background(), tenantID, target)
		if err != nil {
			t.Fatalf("single compile %s: %v", target, err)
		}
		snapBytes, err := json.Marshal(fromSnap)
		if err != nil {
			t.Fatalf("marshal snap %s: %v", target, err)
		}
		singleBytes, err := json.Marshal(fromSingle)
		if err != nil {
			t.Fatalf("marshal single %s: %v", target, err)
		}
		if string(snapBytes) != string(singleBytes) {
			t.Fatalf("target %s: snapshot output differs from single-shot path\nsnap: %s\nsingle: %s",
				target, snapBytes, singleBytes)
		}
	}
}

// TestSyncer_SyncAll_SerialisesConcurrentInvocations verifies the
// syncMu contract: the periodic Run goroutine and the admin
// POST /admin/app-registry/sync endpoint cannot interleave SyncAll
// invocations, preventing double-fetch / duplicate-audit-entry
// races flagged by Devin Review. The assertion is structural — an
// httptest.Server with an in-flight counter — rather than timing,
// so the test is deterministic.
func TestSyncer_SyncAll_SerialisesConcurrentInvocations(t *testing.T) {
	var inflight atomic.Int32
	var maxInflight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := inflight.Add(1)
		// Track the high-water mark non-atomically — the
		// CAS-free load is fine because we only care about
		// whether it ever exceeds 1.
		for {
			prev := maxInflight.Load()
			if now <= prev || maxInflight.CompareAndSwap(prev, now) {
				break
			}
		}
		// Hold the response briefly so concurrent callers
		// have time to collide if the mutex were absent.
		time.Sleep(30 * time.Millisecond)
		inflight.Add(-1)
		_, _ = w.Write([]byte(`{"domains":["a.example.com"],"ip_ranges":["1.2.3.0/24"]}`))
	}))
	defer srv.Close()

	store := memory.NewStore()
	svc := appdb.New(
		memory.NewAppRegistryRepository(store),
		memory.NewAppRegistryOverrideRepository(store),
		nil,
		nil,
	)
	// Two apps so each SyncAll does multiple HTTP round-trips —
	// raises the probability of overlap if serialisation is
	// broken.
	for i := 0; i < 2; i++ {
		if _, err := svc.CreateApp(context.Background(), repository.AppRegistry{
			Name:         "app-" + uuid.NewString()[:8],
			TrafficClass: repository.TrafficClassInspectFull,
			Scope:        repository.AppRegistryScopeGlobal,
			Domains:      []string{"placeholder.example.com"},
			MetadataURL:  srv.URL,
			IsSystem:     true,
		}); err != nil {
			t.Fatalf("create app: %v", err)
		}
	}

	syncer := appdb.NewSyncer(svc, srv.Client())
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := syncer.SyncAll(context.Background()); err != nil {
				t.Errorf("SyncAll: %v", err)
			}
		}()
	}
	wg.Wait()

	if peak := maxInflight.Load(); peak > 1 {
		t.Fatalf("syncMu serialisation violated: max concurrent in-flight HTTP requests = %d, want ≤ 1", peak)
	}
}

// TestEnvelopeTrafficClassValidationCovers_AllRepositoryClasses keeps
// the closed set in schema.Envelope.Validate (which intentionally
// duplicates the canonical list to keep the transport package
// dependency-free) in sync with repository.AllTrafficClasses. If a
// new traffic class is added to the repository enum without also
// being added to the schema validator, every producer emitting that
// class would have its envelope rejected at Marshal time — a
// hard-to-diagnose failure. This test makes that failure mode loud
// and immediate.
func TestEnvelopeTrafficClassValidationCovers_AllRepositoryClasses(t *testing.T) {
	t.Parallel()
	for _, c := range repository.AllTrafficClasses() {
		env, err := schema.WrapFlowEvent(
			schema.Envelope{
				SchemaVersion: schema.SchemaVersion,
				EventID:       uuid.New(),
				TenantID:      uuid.New(),
				DeviceID:      uuid.New(),
				Timestamp:     time.Now().UTC(),
				Platform:      schema.PlatformLinux,
			},
			string(c),
			schema.FlowEvent{
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 1024, DstPort: 443,
				Protocol: "tcp", Verdict: schema.VerdictAllow,
			},
		)
		if err != nil {
			t.Fatalf("traffic class %q: WrapFlowEvent returned %v; the schema validator likely missed this class", c, err)
		}
		if _, err := schema.Marshal(env); err != nil {
			t.Fatalf("traffic class %q: Marshal returned %v; the schema validator likely missed this class", c, err)
		}
	}
}
