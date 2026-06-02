package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fixedClock returns a deterministic clock that advances by 1ms per
// call. Tests use it to assert stable CreatedAt/UpdatedAt ordering.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFixedClock(start time.Time) *fixedClock { return &fixedClock{t: start.UTC()} }

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

// newStore constructs a Store with a fixed clock.
func newStore(t *testing.T) *memory.Store {
	t.Helper()
	s := memory.NewStore()
	c := newFixedClock(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	s.SetClock(c.now)
	return s
}

func ctx() context.Context { return context.Background() }

// --- Tenant ---------------------------------------------------------------

func TestTenantRepository_CreateAndGet(t *testing.T) {
	s := newStore(t)
	repo := memory.NewTenantRepository(s)

	t1, err := repo.Create(ctx(), repository.Tenant{Name: "Acme", Slug: "acme", Tier: repository.TenantTierProfessional, Status: repository.TenantStatusActive})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if t1.ID == uuid.Nil {
		t.Fatal("create: id not assigned")
	}

	got, err := repo.Get(ctx(), t1.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Slug != "acme" {
		t.Errorf("slug: want acme, got %q", got.Slug)
	}

	// Missing ID -> NotFound.
	if _, err := repo.Get(ctx(), uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("get missing: want ErrNotFound, got %v", err)
	}
}

func TestTenantRepository_SlugConflict(t *testing.T) {
	s := newStore(t)
	repo := memory.NewTenantRepository(s)
	if _, err := repo.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter}); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	_, err := repo.Create(ctx(), repository.Tenant{Name: "A2", Slug: "a", Tier: repository.TenantTierStarter})
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup slug: want ErrConflict, got %v", err)
	}
}

func TestTenantRepository_UpdateStatusAndDelete(t *testing.T) {
	s := newStore(t)
	repo := memory.NewTenantRepository(s)
	t1, _ := repo.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	if _, err := repo.UpdateStatus(ctx(), t1.ID, repository.TenantStatusSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	got, _ := repo.Get(ctx(), t1.ID)
	if got.Status != repository.TenantStatusSuspended {
		t.Errorf("status: want suspended, got %q", got.Status)
	}
	if err := repo.Delete(ctx(), t1.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ = repo.Get(ctx(), t1.ID)
	if got.DeletedAt == nil {
		t.Error("deleted_at should be set after Delete")
	}
}

// TestTenantRepository_WritePathsReturnFreshPointers pins the
// cloneTenant invariant on all write paths (Update, UpdateStatus,
// TransitionStatus). The returned struct must own fresh-allocated
// DeletedAt and Settings backing memory so the caller can mutate
// the result without corrupting in-store state. Prior to round-5
// only the read paths cloned defensively; the write paths returned
// the struct directly with the in-store pointers, which meant a
// caller that wrote through `result.DeletedAt = nil` would silently
// resurrect a tombstone.
func TestTenantRepository_WritePathsReturnFreshPointers(t *testing.T) {
	s := newStore(t)
	repo := memory.NewTenantRepository(s)
	settings := json.RawMessage(`{"k":"v"}`)
	t1, err := repo.Create(ctx(), repository.Tenant{
		Name:     "A",
		Slug:     "wp",
		Tier:     repository.TenantTierStarter,
		Settings: settings,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// UpdateStatus(Deleted) populates DeletedAt; mutating the
	// returned pointer must not be visible to a subsequent Get.
	deleted, err := repo.UpdateStatus(ctx(), t1.ID, repository.TenantStatusDeleted)
	if err != nil {
		t.Fatalf("update status: %v", err)
	}
	if deleted.DeletedAt == nil {
		t.Fatalf("UpdateStatus(Deleted) did not set DeletedAt")
	}
	*deleted.DeletedAt = time.Time{}
	deleted.Settings[0] = 'X'
	got, err := repo.Get(ctx(), t1.ID)
	if err != nil {
		t.Fatalf("get after update status: %v", err)
	}
	if got.DeletedAt == nil || got.DeletedAt.IsZero() {
		t.Errorf("caller mutation of UpdateStatus result leaked into store: %v", got.DeletedAt)
	}
	if string(got.Settings) != `{"k":"v"}` {
		t.Errorf("caller mutation of UpdateStatus result.Settings leaked into store: %s", got.Settings)
	}

	// Update path: mutating Settings on the returned struct must
	// not affect the stored row.
	name := "Renamed"
	updated, err := repo.Update(ctx(), t1.ID, repository.TenantPatch{Name: &name})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.Settings) > 0 {
		updated.Settings[0] = 'Y'
	}
	got, err = repo.Get(ctx(), t1.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if string(got.Settings) != `{"k":"v"}` {
		t.Errorf("caller mutation of Update result.Settings leaked into store: %s", got.Settings)
	}
}

func TestTenantRepository_List_CursorPagination(t *testing.T) {
	s := newStore(t)
	repo := memory.NewTenantRepository(s)
	for i := 0; i < 7; i++ {
		_, err := repo.Create(ctx(), repository.Tenant{
			Name: "t" + uuid.NewString(),
			Slug: "t" + uuid.NewString(),
			Tier: repository.TenantTierStarter,
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	page1, err := repo.List(ctx(), repository.Page{Limit: 3})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Items) != 3 {
		t.Fatalf("page1 size: want 3, got %d", len(page1.Items))
	}
	if page1.NextCursor == "" {
		t.Error("page1: expected non-empty NextCursor")
	}
	page2, err := repo.List(ctx(), repository.Page{Limit: 3, After: page1.NextCursor})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Items) != 3 {
		t.Fatalf("page2 size: want 3, got %d", len(page2.Items))
	}
	// Pages must not overlap.
	seen := map[uuid.UUID]bool{}
	for _, x := range page1.Items {
		seen[x.ID] = true
	}
	for _, x := range page2.Items {
		if seen[x.ID] {
			t.Errorf("overlap: tenant %s appears in both pages", x.ID)
		}
	}
}

// --- Site -----------------------------------------------------------------

func TestSiteRepository_TenantIsolation(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	sr := memory.NewSiteRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	t2, _ := tr.Create(ctx(), repository.Tenant{Name: "B", Slug: "b", Tier: repository.TenantTierStarter})

	site1, err := sr.Create(ctx(), t1.ID, repository.Site{Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch})
	if err != nil {
		t.Fatalf("create site1: %v", err)
	}

	// Read from t1 succeeds, from t2 fails.
	if _, err := sr.Get(ctx(), t1.ID, site1.ID); err != nil {
		t.Errorf("get from owning tenant: %v", err)
	}
	if _, err := sr.Get(ctx(), t2.ID, site1.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("cross-tenant get: want ErrNotFound, got %v", err)
	}

	// Same slug in different tenants is allowed.
	if _, err := sr.Create(ctx(), t2.ID, repository.Site{Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch}); err != nil {
		t.Errorf("same slug across tenants: %v", err)
	}
}

func TestSiteRepository_SlugConflict(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	sr := memory.NewSiteRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	if _, err := sr.Create(ctx(), t1.ID, repository.Site{Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch}); err != nil {
		t.Fatal(err)
	}
	if _, err := sr.Create(ctx(), t1.ID, repository.Site{Name: "hq2", Slug: "hq", Template: repository.SiteTemplateBranch}); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup slug: want ErrConflict, got %v", err)
	}
}

func TestSiteRepository_Delete_DetachesDevices(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	sr := memory.NewSiteRepository(s)
	dr := memory.NewDeviceRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	site, _ := sr.Create(ctx(), t1.ID, repository.Site{Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch})
	dev, _ := dr.Create(ctx(), t1.ID, repository.Device{Name: "laptop", Platform: repository.DevicePlatformLinux, SiteID: &site.ID})
	if err := sr.Delete(ctx(), t1.ID, site.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := dr.Get(ctx(), t1.ID, dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if got.SiteID != nil {
		t.Errorf("device should have detached site_id, got %v", got.SiteID)
	}
}

// --- User -----------------------------------------------------------------

func TestUserRepository_CRUDAndConflict(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	ur := memory.NewUserRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})

	u, err := ur.Create(ctx(), t1.ID, repository.User{Email: "a@a.com", Name: "Ada"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Status != repository.UserStatusActive {
		t.Errorf("default status: %q", u.Status)
	}
	if _, err := ur.GetByEmail(ctx(), t1.ID, "A@a.com"); err != nil {
		t.Errorf("case-insensitive email lookup: %v", err)
	}
	if _, err := ur.Create(ctx(), t1.ID, repository.User{Email: "A@A.COM"}); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup email (case-insensitive): want ErrConflict, got %v", err)
	}
}

// --- Device ---------------------------------------------------------------

func TestDeviceRepository_PostureAndStatus(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	dr := memory.NewDeviceRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	d, err := dr.Create(ctx(), t1.ID, repository.Device{Name: "phone", Platform: repository.DevicePlatformIOS})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// UpdatePosture stores mobile signals.
	jailbroken := false
	if err := dr.UpdatePosture(ctx(), t1.ID, d.ID, repository.Posture{Jailbroken: &jailbroken, OSVersion: "iOS 18"}); err != nil {
		t.Fatalf("posture: %v", err)
	}
	got, _ := dr.Get(ctx(), t1.ID, d.ID)
	if got.Posture.OSVersion != "iOS 18" {
		t.Errorf("posture os: %q", got.Posture.OSVersion)
	}
	if got.Posture.Jailbroken == nil || *got.Posture.Jailbroken {
		t.Error("posture jailbroken: want false-ptr")
	}

	// Status active -> EnrolledAt populated.
	now := time.Now().UTC()
	if err := dr.UpdateLastSeen(ctx(), t1.ID, d.ID, now); err != nil {
		t.Fatalf("last seen: %v", err)
	}
	got, _ = dr.Get(ctx(), t1.ID, d.ID)
	if got.LastSeenAt == nil {
		t.Error("LastSeenAt not set")
	}
	updated, err := dr.UpdateStatus(ctx(), t1.ID, d.ID, repository.DeviceStatusActive)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if updated.EnrolledAt == nil {
		t.Error("EnrolledAt should be set on first transition to active")
	}
}

func TestDeviceRepository_List_FilterByPlatform(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	dr := memory.NewDeviceRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})

	for i, p := range []repository.DevicePlatform{
		repository.DevicePlatformWindows, repository.DevicePlatformMacOS,
		repository.DevicePlatformLinux, repository.DevicePlatformIOS,
		repository.DevicePlatformAndroid,
	} {
		if _, err := dr.Create(ctx(), t1.ID, repository.Device{Name: "d" + string(rune(48+i)), Platform: p}); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	res, err := dr.List(ctx(), t1.ID, repository.DeviceListFilter{Platform: repository.DevicePlatformAndroid}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Items) != 1 || res.Items[0].Platform != repository.DevicePlatformAndroid {
		t.Errorf("platform filter: want 1 android, got %d %+v", len(res.Items), res.Items)
	}
}

// --- Role -----------------------------------------------------------------

func TestRoleRepository_AssignRevokeHasPermission(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	ur := memory.NewUserRepository(s)
	rr := memory.NewRoleRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	u, _ := ur.Create(ctx(), t1.ID, repository.User{Email: "u@a.com"})
	role, err := rr.Create(ctx(), repository.Role{
		TenantID:    &t1.ID,
		Name:        "ops",
		Permissions: []string{"devices:read", "devices:write"},
		Scope:       repository.RoleScopeTenant,
	})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	if err := rr.AssignRole(ctx(), repository.UserRole{UserID: u.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Double-assign -> conflict.
	if err := rr.AssignRole(ctx(), repository.UserRole{UserID: u.ID, RoleID: role.ID}); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup assign: want ErrConflict, got %v", err)
	}

	ok, err := rr.HasPermission(ctx(), u.ID, "devices:read")
	if err != nil || !ok {
		t.Errorf("HasPermission devices:read: %v %v", ok, err)
	}
	ok, _ = rr.HasPermission(ctx(), u.ID, "tenants:write")
	if ok {
		t.Error("HasPermission tenants:write: want false")
	}

	if err := rr.RevokeRole(ctx(), u.ID, role.ID, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ok, _ = rr.HasPermission(ctx(), u.ID, "devices:read")
	if ok {
		t.Error("HasPermission after revoke: want false")
	}
}

func TestRoleRepository_WildcardPermission(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	ur := memory.NewUserRepository(s)
	rr := memory.NewRoleRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	u, _ := ur.Create(ctx(), t1.ID, repository.User{Email: "su@a.com"})
	role, _ := rr.Create(ctx(), repository.Role{TenantID: &t1.ID, Name: "admin", Permissions: []string{"*"}, Scope: repository.RoleScopeTenant})
	_ = rr.AssignRole(ctx(), repository.UserRole{UserID: u.ID, RoleID: role.ID})
	ok, _ := rr.HasPermission(ctx(), u.ID, "anything:goes")
	if !ok {
		t.Error("wildcard '*' permission should match any permission string")
	}
}

// --- Claim token ----------------------------------------------------------

func TestClaimTokenRepository_RedeemFlow(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	cr := memory.NewClaimTokenRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})

	hash := []byte{1, 2, 3, 4, 5}
	expires := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	tok, err := cr.Create(ctx(), t1.ID, repository.ClaimToken{TokenHash: hash, ExpiresAt: expires})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tok.ID == uuid.Nil {
		t.Fatal("id not assigned")
	}

	// Dup hash conflict.
	if _, err := cr.Create(ctx(), t1.ID, repository.ClaimToken{TokenHash: hash, ExpiresAt: expires}); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup hash: want ErrConflict, got %v", err)
	}

	// Redeem within validity.
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	redeemed, err := cr.Redeem(ctx(), t1.ID, hash, now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if redeemed.RedeemedAt == nil {
		t.Error("redeemed_at not set")
	}

	// Double-redeem -> forbidden.
	if _, err := cr.Redeem(ctx(), t1.ID, hash, now); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("double redeem: want ErrForbidden, got %v", err)
	}

	// Expired token.
	expHash := []byte{9, 9, 9, 9}
	_, _ = cr.Create(ctx(), t1.ID, repository.ClaimToken{TokenHash: expHash, ExpiresAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := cr.Redeem(ctx(), t1.ID, expHash, now); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("expired redeem: want ErrForbidden, got %v", err)
	}
}

// --- Audit ----------------------------------------------------------------

func TestAuditLogRepository_AppendAndList(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	ar := memory.NewAuditLogRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})

	for i := 0; i < 5; i++ {
		_, err := ar.Append(ctx(), t1.ID, repository.AuditEntry{
			Action: "device.enroll", ResourceType: "device",
			Details: json.RawMessage(`{"idx":` + string(rune('0'+i)) + `}`),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Filter by action.
	res, err := ar.List(ctx(), t1.ID, repository.AuditFilter{Action: "device.enroll"}, repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Items) != 5 {
		t.Errorf("filter: want 5, got %d", len(res.Items))
	}

	// Wrong action -> empty.
	res, _ = ar.List(ctx(), t1.ID, repository.AuditFilter{Action: "missing"}, repository.Page{Limit: 100})
	if len(res.Items) != 0 {
		t.Errorf("non-matching action: want 0, got %d", len(res.Items))
	}

	// Invalid append -> error (empty action).
	if _, err := ar.Append(ctx(), t1.ID, repository.AuditEntry{Action: "", ResourceType: "x"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("empty action: want ErrInvalidArgument, got %v", err)
	}
}

// --- Policy ---------------------------------------------------------------

func TestPolicyRepository_GraphAndBundleLifecycle(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	pr := memory.NewPolicyRepository(s)
	t1, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})

	g1, err := pr.CreateGraph(ctx(), t1.ID, repository.PolicyGraph{Graph: json.RawMessage(`{"rules":[]}`)})
	if err != nil {
		t.Fatalf("create graph 1: %v", err)
	}
	if g1.Version != 1 {
		t.Errorf("auto-version: want 1, got %d", g1.Version)
	}
	g2, _ := pr.CreateGraph(ctx(), t1.ID, repository.PolicyGraph{Graph: json.RawMessage(`{"rules":[{"action":"deny"}]}`)})
	if g2.Version != 2 {
		t.Errorf("auto-version next: want 2, got %d", g2.Version)
	}

	// Explicit duplicate version -> conflict.
	if _, err := pr.CreateGraph(ctx(), t1.ID, repository.PolicyGraph{Version: 2, Graph: json.RawMessage(`{}`)}); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup version: want ErrConflict, got %v", err)
	}

	current, _ := pr.GetCurrentGraph(ctx(), t1.ID)
	if current.Version != 2 {
		t.Errorf("current: want v2, got v%d", current.Version)
	}

	// Bundle creation for each target type.
	for _, tgt := range []repository.PolicyBundleTarget{
		repository.PolicyBundleTargetEdge,
		repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud,
		repository.PolicyBundleTargetMobile,
	} {
		_, err := pr.CreateBundle(ctx(), t1.ID, repository.PolicyBundle{
			PolicyGraphID: g2.ID,
			TargetType:    tgt,
			Bundle:        []byte("payload"),
			Signature:     []byte("sig"),
		})
		if err != nil {
			t.Errorf("bundle %s: %v", tgt, err)
		}
	}

	// Duplicate (graph, target) -> conflict.
	_, err = pr.CreateBundle(ctx(), t1.ID, repository.PolicyBundle{
		PolicyGraphID: g2.ID, TargetType: repository.PolicyBundleTargetMobile,
		Bundle: []byte("p2"), Signature: []byte("s2"),
	})
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("dup (graph,target): want ErrConflict, got %v", err)
	}

	// Latest mobile bundle is from g2 (newer version).
	latest, err := pr.GetLatestBundle(ctx(), t1.ID, repository.PolicyBundleTargetMobile)
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if latest.PolicyGraphID != g2.ID {
		t.Errorf("latest graph id: want g2 (%s), got %s", g2.ID, latest.PolicyGraphID)
	}
}

// --- Concurrency ----------------------------------------------------------

func TestStore_ThreadSafety(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, _ := tr.Create(ctx(), repository.Tenant{Name: "A", Slug: "a", Tier: repository.TenantTierStarter})
	dr := memory.NewDeviceRepository(s)

	const goroutines = 16
	const perGoroutine = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_, err := dr.Create(ctx(), tnt.ID, repository.Device{
					Name:     "d-" + uuid.NewString(),
					Platform: repository.DevicePlatformLinux,
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent create: %v", err)
	}
	page, err := dr.List(ctx(), tnt.ID, repository.DeviceListFilter{}, repository.Page{Limit: repository.MaxPageLimit})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) == 0 {
		t.Error("no devices visible after concurrent inserts")
	}
}

// --- Context cancellation -------------------------------------------------

func TestStore_ContextCancellation(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tr.Create(cctx, repository.Tenant{Name: "x", Slug: "x", Tier: repository.TenantTierStarter}); err == nil || !strings.Contains(err.Error(), "context") {
		t.Errorf("cancelled context: want context.* error, got %v", err)
	}
}

// TestTenantRepository_GetDeepCopiesPointerFields pins the round-4
// fix on tenant.go: Get must allocate fresh *uuid.UUID (MSPID) and
// *time.Time (DeletedAt) so a caller mutating either through the
// returned struct cannot corrupt the stored row. The previous
// implementation cloned Settings (the JSONB blob) but left both
// pointer fields aliasing the in-memory store.
func TestTenantRepository_GetDeepCopiesPointerFields(t *testing.T) {
	s := newStore(t)
	tenants := memory.NewTenantRepository(s)
	msps := memory.NewMSPRepository(s)

	tn, err := tenants.Create(ctx(), repository.Tenant{Name: "Acme", Slug: "acme-clone", Tier: repository.TenantTierStarter})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	m, err := msps.Create(ctx(), repository.MSP{Name: "Aperture", Slug: "aperture-clone"})
	if err != nil {
		t.Fatalf("create msp: %v", err)
	}
	if _, err := msps.AssignTenant(ctx(), m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign tenant: %v", err)
	}

	// Drive the tenant into a soft-deleted state so DeletedAt is
	// non-nil and we exercise that pointer too. UpdateStatus
	// sets DeletedAt via the in-place store; the subsequent Get
	// must hand back a fresh pointer.
	if _, err := tenants.UpdateStatus(ctx(), tn.ID, repository.TenantStatusDeleted); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	got, err := tenants.Get(ctx(), tn.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MSPID == nil {
		t.Fatal("post-condition: MSPID nil; expected the bound MSP id")
	}
	if got.DeletedAt == nil {
		t.Fatal("post-condition: DeletedAt nil; expected non-nil after soft-delete")
	}

	// Mutate the returned pointers' targets. If Get returned
	// aliased pointers (the pre-fix behaviour), a subsequent
	// Get would observe the mutation.
	*got.MSPID = uuid.Nil
	mutatedTs := got.DeletedAt.Add(24 * 365 * 100 * time.Hour) // +100y
	*got.DeletedAt = mutatedTs

	again, err := tenants.Get(ctx(), tn.ID)
	if err != nil {
		t.Fatalf("re-get: %v", err)
	}
	if again.MSPID == nil || *again.MSPID != m.ID {
		t.Fatalf("MSPID alias leaked: again.MSPID = %v, want %v (round-4 deep-copy fix)",
			again.MSPID, m.ID)
	}
	if again.DeletedAt == nil || again.DeletedAt.Equal(mutatedTs) {
		t.Fatalf("DeletedAt alias leaked: again.DeletedAt = %v, mutated copy = %v (round-4 deep-copy fix)",
			again.DeletedAt, mutatedTs)
	}
}
