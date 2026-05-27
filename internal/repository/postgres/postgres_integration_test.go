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

		// update name
		updated, err := repo.Update(bgCtx(), repository.Tenant{ID: tnt.ID, Name: "Renamed"})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if updated.Name != "Renamed" {
			t.Errorf("update name: %q", updated.Name)
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
		// per-tenant context is set.
		pending, err := dr.ListPending(bgCtx(), 10)
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
}
