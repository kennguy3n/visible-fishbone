//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func bgCtx() context.Context { return context.Background() }

func mustTenant(t *testing.T, repo repository.TenantRepository) repository.Tenant {
	t.Helper()
	slug := "t-" + uuid.NewString()[:8]
	tnt, err := repo.Create(bgCtx(), repository.Tenant{
		Name: slug, Slug: slug, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tnt
}

// TestPostgres_Integration runs the full battery against a single
// container instance. Subtests stay isolated by carving out their
// own tenants.
func TestPostgres_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	t.Run("Tenant_CRUD", func(t *testing.T) {
		repo := store.NewTenantRepository()
		tnt := mustTenant(t, repo)

		got, err := repo.Get(bgCtx(), tnt.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Slug != tnt.Slug {
			t.Errorf("slug: want %q got %q", tnt.Slug, got.Slug)
		}

		// duplicate slug -> conflict
		if _, err := repo.Create(bgCtx(), repository.Tenant{
			Name: "dup", Slug: tnt.Slug, Tier: repository.TenantTierStarter,
		}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("dup slug: want ErrConflict got %v", err)
		}

		// update name (sparse PATCH: only Name is set; other
		// columns must be preserved exactly).
		newName := "Renamed"
		updated, err := repo.Update(bgCtx(), tnt.ID, repository.TenantPatch{Name: &newName})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if updated.Name != "Renamed" {
			t.Errorf("update name: %q", updated.Name)
		}

		// Round-trip the explicit-clear contract for Region:
		// set it, then PATCH with `Region = &""` and verify
		// the stored value is empty. This is the Postgres-side
		// counterpart of the memory repo's TenantPatch test —
		// the COALESCE(NULLIF(...,'') based predecessor query
		// silently dropped the clear and left the column intact.
		region := "us-east-2"
		seeded, err := repo.Update(bgCtx(), tnt.ID, repository.TenantPatch{Region: &region})
		if err != nil {
			t.Fatalf("update region: %v", err)
		}
		if seeded.Region != region {
			t.Fatalf("seed region: %q", seeded.Region)
		}
		empty := ""
		cleared, err := repo.Update(bgCtx(), tnt.ID, repository.TenantPatch{Region: &empty})
		if err != nil {
			t.Fatalf("clear region: %v", err)
		}
		if cleared.Region != "" {
			t.Errorf("clear region: want empty, got %q (the COALESCE-based predecessor silently dropped this PATCH)", cleared.Region)
		}

		// suspend then delete
		if _, err := repo.UpdateStatus(bgCtx(), tnt.ID, repository.TenantStatusSuspended); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		if err := repo.Delete(bgCtx(), tnt.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, _ = repo.Get(bgCtx(), tnt.ID)
		if got.DeletedAt == nil {
			t.Error("DeletedAt should be set after Delete")
		}
		if got.Status != repository.TenantStatusDeleted {
			t.Errorf("status after delete: %q", got.Status)
		}
	})

	t.Run("Tenant_List_Cursor", func(t *testing.T) {
		repo := store.NewTenantRepository()
		// Seed N tenants for this subtest.
		ids := make(map[uuid.UUID]bool, 8)
		for i := 0; i < 8; i++ {
			tnt := mustTenant(t, repo)
			ids[tnt.ID] = true
		}
		seen := map[uuid.UUID]bool{}
		var cursor string
		for {
			res, err := repo.List(bgCtx(), repository.Page{Limit: 3, After: cursor})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(res.Items) == 0 {
				break
			}
			for _, t1 := range res.Items {
				seen[t1.ID] = true
			}
			if res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		}
		for id := range ids {
			if !seen[id] {
				t.Errorf("tenant %s missing from paginated list", id)
			}
		}
	})

	t.Run("Site_TenantIsolation_RLS", func(t *testing.T) {
		tr := store.NewTenantRepository()
		sr := store.NewSiteRepository()
		t1 := mustTenant(t, tr)
		t2 := mustTenant(t, tr)
		site1, err := sr.Create(bgCtx(), t1.ID, repository.Site{
			Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch,
		})
		if err != nil {
			t.Fatalf("create site: %v", err)
		}

		// Same tenant -> visible.
		if _, err := sr.Get(bgCtx(), t1.ID, site1.ID); err != nil {
			t.Errorf("get from owner: %v", err)
		}
		// Different tenant -> RLS hides it -> NotFound.
		if _, err := sr.Get(bgCtx(), t2.ID, site1.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("cross-tenant: want ErrNotFound got %v", err)
		}

		// Same slug across tenants is allowed.
		if _, err := sr.Create(bgCtx(), t2.ID, repository.Site{
			Name: "hq", Slug: "hq", Template: repository.SiteTemplateBranch,
		}); err != nil {
			t.Errorf("same slug across tenants: %v", err)
		}
		// Duplicate within same tenant -> conflict.
		if _, err := sr.Create(bgCtx(), t1.ID, repository.Site{
			Name: "hq2", Slug: "hq", Template: repository.SiteTemplateBranch,
		}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("dup slug: want ErrConflict got %v", err)
		}
	})

	t.Run("IDPConfig_CRUD_RLS", func(t *testing.T) {
		tr := store.NewTenantRepository()
		cr := store.NewIDPConfigRepository()
		t1 := mustTenant(t, tr)
		t2 := mustTenant(t, tr)

		cfg, err := cr.Create(bgCtx(), t1.ID, repository.IDPConfig{
			ProviderType:   repository.IDPProviderGoogleWorkspace,
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "client-a",
			AllowedDomains: []string{"acme.com"},
			GroupClaimPath: "groups",
			Enabled:        true,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// Same tenant -> visible, round-tripped fields intact.
		got, err := cr.Get(bgCtx(), t1.ID, cfg.ID)
		if err != nil {
			t.Fatalf("get from owner: %v", err)
		}
		if got.ClientID != "client-a" || len(got.AllowedDomains) != 1 || got.AllowedDomains[0] != "acme.com" {
			t.Errorf("round-trip mismatch: %+v", got)
		}

		// RLS: different tenant cannot see it.
		if _, err := cr.Get(bgCtx(), t2.ID, cfg.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("cross-tenant get: want ErrNotFound got %v", err)
		}

		// Same issuer within the same tenant -> unique conflict.
		if _, err := cr.Create(bgCtx(), t1.ID, repository.IDPConfig{
			ProviderType: repository.IDPProviderGoogleWorkspace,
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "client-a2",
		}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("dup issuer same tenant: want ErrConflict got %v", err)
		}

		// Same issuer across tenants -> allowed.
		if _, err := cr.Create(bgCtx(), t2.ID, repository.IDPConfig{
			ProviderType: repository.IDPProviderGoogleWorkspace,
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "client-b",
		}); err != nil {
			t.Errorf("same issuer across tenants: %v", err)
		}

		// Invalid provider_type rejected before hitting the CHECK.
		if _, err := cr.Create(bgCtx(), t1.ID, repository.IDPConfig{
			ProviderType: repository.IDPProviderType("bogus"),
			IssuerURL:    "https://other.example.com",
			ClientID:     "c",
		}); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Errorf("bad provider_type: want ErrInvalidArgument got %v", err)
		}

		// List is tenant-scoped: t1 sees exactly its one config.
		list, err := cr.List(bgCtx(), t1.ID)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 1 || list[0].ID != cfg.ID {
			t.Errorf("list scope: want [%v] got %+v", cfg.ID, list)
		}

		// Update toggles enabled and persists.
		cfg.Enabled = false
		cfg.ClientID = "client-a-rotated"
		updated, err := cr.Update(bgCtx(), t1.ID, cfg)
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if updated.Enabled || updated.ClientID != "client-a-rotated" {
			t.Errorf("update not applied: %+v", updated)
		}

		// Delete, then it is gone.
		if err := cr.Delete(bgCtx(), t1.ID, cfg.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := cr.Get(bgCtx(), t1.ID, cfg.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("get after delete: want ErrNotFound got %v", err)
		}
		if err := cr.Delete(bgCtx(), t1.ID, cfg.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("delete missing: want ErrNotFound got %v", err)
		}
	})

	t.Run("User_CaseInsensitive_Email", func(t *testing.T) {
		tr := store.NewTenantRepository()
		ur := store.NewUserRepository()
		tnt := mustTenant(t, tr)
		if _, err := ur.Create(bgCtx(), tnt.ID, repository.User{Email: "ada@example.com", Name: "Ada"}); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := ur.GetByEmail(bgCtx(), tnt.ID, "ADA@example.com"); err != nil {
			t.Errorf("case-insensitive lookup: %v", err)
		}
		if _, err := ur.Create(bgCtx(), tnt.ID, repository.User{Email: "ADA@EXAMPLE.COM"}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("dup email: want ErrConflict got %v", err)
		}
	})

	t.Run("Device_Lifecycle", func(t *testing.T) {
		tr := store.NewTenantRepository()
		dr := store.NewDeviceRepository()
		tnt := mustTenant(t, tr)

		// Mobile device with iOS posture.
		jail := false
		passcode := true
		dev, err := dr.Create(bgCtx(), tnt.ID, repository.Device{
			Name:     "iphone",
			Platform: repository.DevicePlatformIOS,
			Posture: repository.Posture{
				OSVersion:   "iOS 18",
				Jailbroken:  &jail,
				PasscodeSet: &passcode,
			},
		})
		if err != nil {
			t.Fatalf("create device: %v", err)
		}

		// Heartbeat.
		now := time.Now().UTC().Truncate(time.Millisecond)
		if err := dr.UpdateLastSeen(bgCtx(), tnt.ID, dev.ID, now); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		got, err := dr.Get(bgCtx(), tnt.ID, dev.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.LastSeenAt == nil {
			t.Error("LastSeenAt should be set")
		}

		// Posture update.
		root := true
		if err := dr.UpdatePosture(bgCtx(), tnt.ID, dev.ID, repository.Posture{
			OSVersion:     "iOS 18.1",
			Jailbroken:    &root,
			DiskEncrypted: &passcode,
		}); err != nil {
			t.Fatalf("posture: %v", err)
		}
		got, _ = dr.Get(bgCtx(), tnt.ID, dev.ID)
		if got.Posture.Jailbroken == nil || !*got.Posture.Jailbroken {
			t.Error("posture Jailbroken should update to true")
		}

		// Status transition fills EnrolledAt.
		updated, err := dr.UpdateStatus(bgCtx(), tnt.ID, dev.ID, repository.DeviceStatusActive)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if updated.EnrolledAt == nil {
			t.Error("EnrolledAt should be set on first active transition")
		}

		// List with platform filter.
		res, err := dr.List(bgCtx(), tnt.ID, repository.DeviceListFilter{
			Platform: repository.DevicePlatformIOS,
		}, repository.Page{Limit: 10})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(res.Items) != 1 {
			t.Errorf("filter: want 1 got %d", len(res.Items))
		}
	})

	t.Run("Device_PublicKey_Mobile", func(t *testing.T) {
		tr := store.NewTenantRepository()
		dr := store.NewDeviceRepository()
		tntA := mustTenant(t, tr)
		tntB := mustTenant(t, tr)
		key := "bW9iaWxlLWRldmljZS1rZXktMQ==" // arbitrary base64 device key

		devA, err := dr.Create(bgCtx(), tntA.ID, repository.Device{
			Name: "iphone-A", Platform: repository.DevicePlatformIOS,
			PublicKeyEd25519: key, Status: repository.DeviceStatusActive,
		})
		if err != nil {
			t.Fatalf("create device A: %v", err)
		}

		// GetByPublicKey resolves the device within the tenant.
		got, err := dr.GetByPublicKey(bgCtx(), tntA.ID, key)
		if err != nil {
			t.Fatalf("GetByPublicKey: %v", err)
		}
		if got.ID != devA.ID {
			t.Errorf("GetByPublicKey id = %s, want %s", got.ID, devA.ID)
		}

		// Unknown key → ErrNotFound.
		if _, err := dr.GetByPublicKey(bgCtx(), tntA.ID, "ZG9lcy1ub3QtZXhpc3Q="); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("unknown key err = %v, want ErrNotFound", err)
		}

		// Per-tenant uniqueness (migration 035): the same key cannot be
		// inserted twice within a tenant.
		if _, err := dr.Create(bgCtx(), tntA.ID, repository.Device{
			Name: "iphone-A-dup", Platform: repository.DevicePlatformIOS, PublicKeyEd25519: key,
		}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("duplicate key err = %v, want ErrConflict", err)
		}

		// The SAME key in a DIFFERENT tenant is a distinct device and
		// must succeed; tenant B must not see tenant A's device.
		if _, err := dr.Create(bgCtx(), tntB.ID, repository.Device{
			Name: "iphone-B", Platform: repository.DevicePlatformIOS, PublicKeyEd25519: key,
		}); err != nil {
			t.Fatalf("create device B with same key: %v", err)
		}
		gotB, err := dr.GetByPublicKey(bgCtx(), tntB.ID, key)
		if err != nil {
			t.Fatalf("GetByPublicKey B: %v", err)
		}
		if gotB.ID == devA.ID {
			t.Error("tenant B resolved tenant A's device by key (RLS leak)")
		}
	})

	t.Run("Device_TransitionStatus_CAS", func(t *testing.T) {
		tr := store.NewTenantRepository()
		dr := store.NewDeviceRepository()
		tnt := mustTenant(t, tr)

		dev, err := dr.Create(bgCtx(), tnt.ID, repository.Device{
			Name: "android", Platform: repository.DevicePlatformAndroid,
			Status: repository.DeviceStatusPending,
		})
		if err != nil {
			t.Fatalf("create device: %v", err)
		}

		// Matching precondition: pending -> active succeeds and stamps
		// enrolled_at via the conditional UPDATE.
		out, err := dr.TransitionStatus(bgCtx(), tnt.ID, dev.ID, repository.DeviceStatusPending, repository.DeviceStatusActive)
		if err != nil {
			t.Fatalf("matching transition: %v", err)
		}
		if out.Status != repository.DeviceStatusActive || out.EnrolledAt == nil {
			t.Fatalf("after transition: status=%q enrolled_at=%v", out.Status, out.EnrolledAt)
		}

		// Stale precondition (still expecting pending) must not clobber
		// the now-active row: the CAS affects 0 rows -> ErrForbidden.
		if _, err := dr.TransitionStatus(bgCtx(), tnt.ID, dev.ID, repository.DeviceStatusPending, repository.DeviceStatusSuspended); !errors.Is(err, repository.ErrForbidden) {
			t.Fatalf("stale-from transition: err=%v, want ErrForbidden", err)
		}
		got, _ := dr.Get(bgCtx(), tnt.ID, dev.ID)
		if got.Status != repository.DeviceStatusActive {
			t.Fatalf("status after failed CAS = %q, want active (must be untouched)", got.Status)
		}

		// Unknown id -> ErrNotFound.
		if _, err := dr.TransitionStatus(bgCtx(), tnt.ID, uuid.New(), repository.DeviceStatusActive, repository.DeviceStatusSuspended); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("unknown id transition: err=%v, want ErrNotFound", err)
		}
	})

	t.Run("Role_Permission", func(t *testing.T) {
		tr := store.NewTenantRepository()
		ur := store.NewUserRepository()
		rr := store.NewRoleRepository()
		tnt := mustTenant(t, tr)
		u, _ := ur.Create(bgCtx(), tnt.ID, repository.User{Email: "u@" + tnt.Slug + ".test"})
		role, err := rr.Create(bgCtx(), repository.Role{
			TenantID:    &tnt.ID,
			Name:        "ops-" + uuid.NewString()[:6],
			Permissions: []string{"devices:read"},
			Scope:       repository.RoleScopeTenant,
		})
		if err != nil {
			t.Fatalf("create role: %v", err)
		}
		if err := rr.AssignRole(bgCtx(), repository.UserRole{UserID: u.ID, RoleID: role.ID}); err != nil {
			t.Fatalf("assign: %v", err)
		}
		ok, err := rr.HasPermission(bgCtx(), u.ID, "devices:read")
		if err != nil || !ok {
			t.Errorf("HasPermission: want true err=nil got %v %v", ok, err)
		}
		ok, _ = rr.HasPermission(bgCtx(), u.ID, "policy:compile")
		if ok {
			t.Error("HasPermission policy:compile: want false")
		}

		// Revoke removes permission.
		if err := rr.RevokeRole(bgCtx(), u.ID, role.ID, nil); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		ok, _ = rr.HasPermission(bgCtx(), u.ID, "devices:read")
		if ok {
			t.Error("HasPermission after revoke: want false")
		}
	})

	t.Run("ClaimToken_Redeem", func(t *testing.T) {
		tr := store.NewTenantRepository()
		cr := store.NewClaimTokenRepository()
		tnt := mustTenant(t, tr)

		// Generate a random claim token, hash it, store.
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("rand: %v", err)
		}
		hash := sha256.Sum256(secret)

		expires := time.Now().Add(1 * time.Hour).UTC()
		if _, err := cr.Create(bgCtx(), tnt.ID, repository.ClaimToken{
			TokenHash: hash[:], ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("create: %v", err)
		}

		now := time.Now().UTC()
		redeemed, err := cr.Redeem(bgCtx(), tnt.ID, hash[:], now)
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if redeemed.RedeemedAt == nil {
			t.Error("RedeemedAt should be set")
		}
		// Double redeem -> Forbidden.
		if _, err := cr.Redeem(bgCtx(), tnt.ID, hash[:], now); !errors.Is(err, repository.ErrForbidden) {
			t.Errorf("double redeem: want ErrForbidden got %v", err)
		}
	})

	t.Run("Audit_AppendList", func(t *testing.T) {
		tr := store.NewTenantRepository()
		ar := store.NewAuditLogRepository()
		tnt := mustTenant(t, tr)
		for i := 0; i < 5; i++ {
			if _, err := ar.Append(bgCtx(), tnt.ID, repository.AuditEntry{
				Action: "device.enroll", ResourceType: "device",
				Details: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
			}); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		res, err := ar.List(bgCtx(), tnt.ID, repository.AuditFilter{Action: "device.enroll"}, repository.Page{Limit: 100})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(res.Items) != 5 {
			t.Errorf("want 5 got %d", len(res.Items))
		}
		// Descending order: first item is the most recent.
		for i := 1; i < len(res.Items); i++ {
			if res.Items[i-1].CreatedAt.Before(res.Items[i].CreatedAt) {
				t.Error("expected DESC order by created_at")
			}
		}
	})

	t.Run("Policy_Graph_Bundle", func(t *testing.T) {
		tr := store.NewTenantRepository()
		pr := store.NewPolicyRepository()
		tnt := mustTenant(t, tr)
		g1, err := pr.CreateGraph(bgCtx(), tnt.ID, repository.PolicyGraph{Graph: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatalf("g1: %v", err)
		}
		if g1.Version != 1 {
			t.Errorf("auto-version v1: got %d", g1.Version)
		}
		g2, _ := pr.CreateGraph(bgCtx(), tnt.ID, repository.PolicyGraph{Graph: json.RawMessage(`{"r":1}`)})
		if g2.Version != 2 {
			t.Errorf("auto-version v2: got %d", g2.Version)
		}

		// Dup version -> conflict.
		if _, err := pr.CreateGraph(bgCtx(), tnt.ID, repository.PolicyGraph{Version: 2, Graph: json.RawMessage(`{}`)}); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("dup version: want ErrConflict got %v", err)
		}

		// Bundle for each target.
		for _, tgt := range []repository.PolicyBundleTarget{
			repository.PolicyBundleTargetEdge,
			repository.PolicyBundleTargetEndpoint,
			repository.PolicyBundleTargetCloud,
			repository.PolicyBundleTargetMobile,
		} {
			if _, err := pr.CreateBundle(bgCtx(), tnt.ID, repository.PolicyBundle{
				PolicyGraphID: g2.ID, TargetType: tgt,
				Bundle: []byte("payload"), Signature: []byte("sig"),
			}); err != nil {
				t.Errorf("bundle %s: %v", tgt, err)
			}
		}
		latest, err := pr.GetLatestBundle(bgCtx(), tnt.ID, repository.PolicyBundleTargetMobile)
		if err != nil {
			t.Fatalf("latest: %v", err)
		}
		if latest.PolicyGraphID != g2.ID {
			t.Errorf("latest mobile bundle should be from g2 (latest version)")
		}
	})

	t.Run("Webhook_Endpoint_Delivery_RLS", func(t *testing.T) {
		tr := store.NewTenantRepository()
		er := store.NewWebhookEndpointRepository()
		dr := store.NewWebhookDeliveryRepository()
		tntA := mustTenant(t, tr)
		tntB := mustTenant(t, tr)

		// Provision an active endpoint in tenant A.
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("rand: %v", err)
		}
		epA, err := er.Create(bgCtx(), tntA.ID, repository.WebhookEndpoint{
			URL: "https://a.example/hook", Events: []string{"tenant.created", "site.updated"},
			SigningSecret: secret, Status: repository.WebhookEndpointStatusActive,
		})
		if err != nil {
			t.Fatalf("create endpoint A: %v", err)
		}
		// Tenant B endpoint subscribed to a different event.
		if _, err := er.Create(bgCtx(), tntB.ID, repository.WebhookEndpoint{
			URL: "https://b.example/hook", Events: []string{"device.heartbeat"},
			SigningSecret: secret, Status: repository.WebhookEndpointStatusActive,
		}); err != nil {
			t.Fatalf("create endpoint B: %v", err)
		}

		// RLS: Get from wrong tenant must return ErrNotFound.
		if _, err := er.Get(bgCtx(), tntB.ID, epA.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("cross-tenant Get: want ErrNotFound, got %v", err)
		}

		// ListActive scoped to tenant A returns only A's endpoint.
		active, err := er.ListActive(bgCtx(), tntA.ID, []string{"tenant.created"})
		if err != nil {
			t.Fatalf("ListActive: %v", err)
		}
		if len(active) != 1 || active[0].ID != epA.ID {
			t.Errorf("ListActive returned %d items, want 1 (A)", len(active))
		}

		// Enqueue a delivery for tenant A.
		now := time.Now().UTC()
		del, err := dr.Create(bgCtx(), tntA.ID, repository.WebhookDelivery{
			EndpointID:  epA.ID,
			EventType:   "tenant.created",
			Payload:     json.RawMessage(`{"id":"abc"}`),
			Status:      repository.WebhookDeliveryStatusPending,
			NextRetryAt: now,
		})
		if err != nil {
			t.Fatalf("create delivery: %v", err)
		}

		// ListPending uses the system-role GUC bypass to cross
		// tenants — the worker must see the row even though no
		// per-tenant context is set. processingTimeout=5m is
		// the production default; the row is freshly pending so
		// the reaper window is irrelevant for this assertion.
		pending, err := dr.ListPending(bgCtx(), 10, 5*time.Minute)
		if err != nil {
			t.Fatalf("ListPending: %v", err)
		}
		if len(pending) == 0 {
			t.Fatalf("ListPending returned 0 items, want >= 1")
		}
		found := false
		for _, p := range pending {
			if p.ID == del.ID {
				found = true
				// The atomic-claim invariant flips the
				// returned row to 'processing'.
				if p.Status != repository.WebhookDeliveryStatusProcessing {
					t.Errorf("claimed row status = %v, want processing", p.Status)
				}
				break
			}
		}
		if !found {
			t.Errorf("ListPending did not return the queued delivery")
		}

		// UpdateStatus to delivered closes the loop.
		if err := dr.UpdateStatus(bgCtx(), tntA.ID, del.ID,
			repository.WebhookDeliveryStatusDelivered, 1, "", 200, now); err != nil {
			t.Fatalf("UpdateStatus: %v", err)
		}
		got, err := dr.Get(bgCtx(), tntA.ID, del.ID)
		if err != nil {
			t.Fatalf("post-update get: %v", err)
		}
		if got.Status != repository.WebhookDeliveryStatusDelivered || got.Attempts != 1 {
			t.Errorf("post-update row = %+v", got)
		}
	})

	t.Run("PolicySigningKey_Lifecycle_RLS", func(t *testing.T) {
		tr := store.NewTenantRepository()
		kr := store.NewPolicySigningKeyRepository()
		pr := store.NewPolicyRepository()
		tntA := mustTenant(t, tr)
		tntB := mustTenant(t, tr)

		// Helper to manufacture a deterministic public/private
		// pair for the table assertions — the actual ed25519
		// integration lives in the service tests; this subtest
		// only exercises the repository invariants.
		mkKey := func(keyID string) repository.PolicySigningKey {
			pub := make([]byte, 32)
			priv := make([]byte, 32)
			for i := range pub {
				pub[i] = byte(i)
				priv[i] = byte(i + 1)
			}
			return repository.PolicySigningKey{
				KeyID: keyID, Algorithm: "ed25519",
				PublicKey: pub, PrivateKey: priv,
				Status: repository.PolicySigningKeyStatusActive,
			}
		}

		// 1. Create initial active key for tenant A.
		k1, err := kr.Create(bgCtx(), tntA.ID, mkKey("ka-1"))
		if err != nil {
			t.Fatalf("create k1: %v", err)
		}
		if k1.Status != repository.PolicySigningKeyStatusActive {
			t.Errorf("k1 status: %q", k1.Status)
		}

		// 2. Partial unique index rejects a second active key.
		if _, err := kr.Create(bgCtx(), tntA.ID, mkKey("ka-2")); !errors.Is(err, repository.ErrConflict) {
			t.Errorf("second active create: want ErrConflict, got %v", err)
		}

		// 3. Atomic rotation: old key → rotated, new key → active,
		//    in a single transaction.
		rotAt := time.Now().UTC().Truncate(time.Microsecond)
		k2, err := kr.Rotate(bgCtx(), tntA.ID, mkKey("ka-2"), rotAt)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if k2.Status != repository.PolicySigningKeyStatusActive || k2.KeyID != "ka-2" {
			t.Errorf("rotate result: %+v", k2)
		}
		old, err := kr.GetByKeyID(bgCtx(), tntA.ID, "ka-1")
		if err != nil {
			t.Fatalf("get old: %v", err)
		}
		if old.Status != repository.PolicySigningKeyStatusRotated {
			t.Errorf("old status: %q", old.Status)
		}
		if old.RotatedAt == nil || !old.RotatedAt.Equal(rotAt) {
			t.Errorf("RotatedAt: got %v, want %v", old.RotatedAt, rotAt)
		}

		// 4. Revoking the active key surfaces ErrNotFound on GetActive.
		if _, err := kr.Revoke(bgCtx(), tntA.ID, "ka-2", time.Now().UTC()); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := kr.GetActive(bgCtx(), tntA.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("post-revoke GetActive: want ErrNotFound, got %v", err)
		}

		// 5. RLS: tenant B cannot see tenant A's keys.
		if _, err := kr.GetByKeyID(bgCtx(), tntB.ID, "ka-1"); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("cross-tenant lookup: want ErrNotFound, got %v", err)
		}
		listB, err := kr.List(bgCtx(), tntB.ID)
		if err != nil {
			t.Fatalf("list B: %v", err)
		}
		if len(listB) != 0 {
			t.Errorf("tenant B sees %d keys from tenant A's set", len(listB))
		}

		// 6. Bundle carries key_id round-trip through the
		//    PolicyRepository: stamp the active key id on a
		//    fresh bundle and confirm GetLatestBundle returns it.
		g, err := pr.CreateGraph(bgCtx(), tntA.ID, repository.PolicyGraph{Graph: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatalf("create graph: %v", err)
		}
		// Re-provision an active key so the bundle has something
		// real to point at (the revoke in step 4 emptied it).
		k3, err := kr.Create(bgCtx(), tntA.ID, mkKey("ka-3"))
		if err != nil {
			t.Fatalf("re-create active: %v", err)
		}
		saved, err := pr.CreateBundle(bgCtx(), tntA.ID, repository.PolicyBundle{
			PolicyGraphID: g.ID, TargetType: repository.PolicyBundleTargetEdge,
			Bundle: []byte("payload"), Signature: []byte("sig"),
			KeyID: k3.KeyID,
		})
		if err != nil {
			t.Fatalf("create bundle: %v", err)
		}
		if saved.KeyID != k3.KeyID {
			t.Errorf("KeyID not persisted on CreateBundle: got %q, want %q", saved.KeyID, k3.KeyID)
		}
		got, err := pr.GetLatestBundle(bgCtx(), tntA.ID, repository.PolicyBundleTargetEdge)
		if err != nil {
			t.Fatalf("get latest: %v", err)
		}
		if got.KeyID != k3.KeyID {
			t.Errorf("KeyID round-trip: got %q, want %q", got.KeyID, k3.KeyID)
		}
	})

	t.Run("TenantAPIKey_RLS_And_CrossTenantLookup", func(t *testing.T) {
		tr := store.NewTenantRepository()
		kr := store.NewTenantAPIKeyRepository()
		tntA := mustTenant(t, tr)
		tntB := mustTenant(t, tr)

		// Provision a key in each tenant with distinct hashes so
		// the cross-tenant LookupByHash test below can match by
		// hash without ambiguity.
		hashA := make([]byte, 32)
		hashB := make([]byte, 32)
		if _, err := rand.Read(hashA); err != nil {
			t.Fatalf("rand A: %v", err)
		}
		if _, err := rand.Read(hashB); err != nil {
			t.Fatalf("rand B: %v", err)
		}

		keyA, err := kr.Create(bgCtx(), tntA.ID, repository.TenantAPIKey{
			Name: "ci-bot", Subject: "bot:a", Hash: hashA,
			Status: repository.TenantAPIKeyStatusActive,
		})
		if err != nil {
			t.Fatalf("create key A: %v", err)
		}
		keyB, err := kr.Create(bgCtx(), tntB.ID, repository.TenantAPIKey{
			Name: "ci-bot", Subject: "bot:b", Hash: hashB,
			Status: repository.TenantAPIKeyStatusActive,
		})
		if err != nil {
			t.Fatalf("create key B: %v", err)
		}

		// RLS: Get from wrong tenant must return ErrNotFound. Even
		// with the API key's ID known, tenant A cannot peek at
		// tenant B's key.
		if _, err := kr.Get(bgCtx(), tntA.ID, keyB.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("cross-tenant Get: want ErrNotFound, got %v", err)
		}

		// RLS: List scoped to tenant A returns only A's key.
		listA, err := kr.List(bgCtx(), tntA.ID)
		if err != nil {
			t.Fatalf("List A: %v", err)
		}
		if len(listA) != 1 || listA[0].ID != keyA.ID {
			t.Errorf("List(A) returned %d items, want 1 (A)", len(listA))
		}

		// LookupByHash uses the system-role GUC bypass to scan
		// across tenants — the auth middleware must be able to
		// resolve a key without knowing which tenant owns it.
		looked, err := kr.LookupByHash(bgCtx(), hashB)
		if err != nil {
			t.Fatalf("LookupByHash(B): %v", err)
		}
		if looked.ID != keyB.ID || looked.TenantID != tntB.ID {
			t.Errorf("LookupByHash returned wrong row: got id=%s tenant=%s, want id=%s tenant=%s",
				looked.ID, looked.TenantID, keyB.ID, tntB.ID)
		}

		// TouchLastUsed updates the row even though the auth
		// middleware doesn't know which tenant owns the key —
		// the repo plumbs the tenantID in (resolved from
		// LookupByHash).
		now := time.Now().UTC()
		if err := kr.TouchLastUsed(bgCtx(), tntB.ID, keyB.ID, now); err != nil {
			t.Fatalf("TouchLastUsed: %v", err)
		}
		got, err := kr.Get(bgCtx(), tntB.ID, keyB.ID)
		if err != nil {
			t.Fatalf("Get(B): %v", err)
		}
		if got.LastUsedAt == nil {
			t.Fatalf("LastUsedAt not stamped")
		}

		// Revoke is idempotent — second call returns the row
		// with the same RevokedAt as the first.
		first, err := kr.Revoke(bgCtx(), tntA.ID, keyA.ID, now)
		if err != nil {
			t.Fatalf("first Revoke: %v", err)
		}
		if first.Status != repository.TenantAPIKeyStatusRevoked || first.RevokedAt == nil {
			t.Fatalf("revoke did not flip status/timestamp: %+v", first)
		}
		later := now.Add(time.Minute)
		second, err := kr.Revoke(bgCtx(), tntA.ID, keyA.ID, later)
		if err != nil {
			t.Fatalf("second Revoke: %v", err)
		}
		if !second.RevokedAt.Equal(*first.RevokedAt) {
			t.Errorf("idempotent Revoke should keep first RevokedAt, got %s then %s",
				*first.RevokedAt, *second.RevokedAt)
		}

		// LookupByHash returns the revoked row — the service
		// layer (not the repo) decides what to do with status.
		afterRevoke, err := kr.LookupByHash(bgCtx(), hashA)
		if err != nil {
			t.Fatalf("LookupByHash(A) post-revoke: %v", err)
		}
		if afterRevoke.Status != repository.TenantAPIKeyStatusRevoked {
			t.Errorf("LookupByHash on revoked row should return Revoked status, got %s", afterRevoke.Status)
		}

		// Unknown hash → ErrNotFound.
		unknown := make([]byte, 32)
		if _, err := rand.Read(unknown); err != nil {
			t.Fatalf("rand unknown: %v", err)
		}
		if _, err := kr.LookupByHash(bgCtx(), unknown); !errors.Is(err, repository.ErrNotFound) {
			t.Errorf("unknown hash: want ErrNotFound, got %v", err)
		}
	})

	t.Run("AISuggestion_TransitionPreservesAttribution", func(t *testing.T) {
		tnt := mustTenant(t, store.NewTenantRepository())
		repo := store.NewAISuggestionRepository()

		// reviewer_id is a FK to users(id); create a real reviewer.
		usr, err := store.NewUserRepository().Create(bgCtx(), tnt.ID,
			repository.User{Email: "reviewer@example.com", Name: "Reviewer"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}

		created, err := repo.Create(bgCtx(), tnt.ID, repository.AISuggestion{
			RuleID:         "rule-1",
			Category:       "unused",
			SuggestionJSON: json.RawMessage(`{"action":"remove_rule"}`),
			Confidence:     0.9,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		// Approve records reviewer attribution and feedback.
		reviewer := usr.ID
		feedback := "looks good"
		if err := repo.UpdateStatus(bgCtx(), tnt.ID, created.ID,
			string(repository.AISuggestionStatusPending),
			string(repository.AISuggestionStatusApproved),
			&reviewer, &feedback,
		); err != nil {
			t.Fatalf("approve: %v", err)
		}

		// Apply carries no attribution (nil reviewer + nil feedback);
		// the earlier approve attribution must be preserved, not nulled.
		if err := repo.UpdateStatus(bgCtx(), tnt.ID, created.ID,
			string(repository.AISuggestionStatusApproved),
			string(repository.AISuggestionStatusApplied),
			nil, nil,
		); err != nil {
			t.Fatalf("apply: %v", err)
		}

		got, err := repo.Get(bgCtx(), tnt.ID, created.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != repository.AISuggestionStatusApplied {
			t.Errorf("status: want applied, got %s", got.Status)
		}
		if got.ReviewerID == nil || *got.ReviewerID != reviewer {
			t.Errorf("reviewer_id not preserved across apply: got %v want %s", got.ReviewerID, reviewer)
		}
		if got.Feedback == nil || *got.Feedback != feedback {
			t.Errorf("feedback not preserved across apply: got %v want %q", got.Feedback, feedback)
		}
	})
}
