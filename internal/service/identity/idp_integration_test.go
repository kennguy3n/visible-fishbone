package identity

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// integrationEnv wires a SCIMService and a SyncService over one shared
// store so the SCIM endpoint and the directory sync interoperate exactly
// as they do in production (same users / roles / audit tables).
type integrationEnv struct {
	tid    uuid.UUID
	scim   *SCIMService
	sync   *SyncService
	users  repository.UserRepository
	roles  repository.RoleRepository
	pub    *capturePublisher
	client *fakeDirectoryClient
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "Integration", Slug: "integration", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "client",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	pub := newCapturePublisher()
	client := &fakeDirectoryClient{}
	scim := NewSCIMService(
		memory.NewUserRepository(store),
		memory.NewRoleRepository(store),
		memory.NewAuditLogRepository(store),
		WithRevocationPublisher(pub),
	)
	sync := NewSyncService(
		configs,
		memory.NewUserRepository(store),
		memory.NewRoleRepository(store),
		memory.NewAuditLogRepository(store),
		singleTenant{id: tn.ID},
		staticCreds{},
		fakeFactory{client: client},
		pub,
		nil,
	)
	return &integrationEnv{
		tid:    tn.ID,
		scim:   scim,
		sync:   sync,
		users:  memory.NewUserRepository(store),
		roles:  memory.NewRoleRepository(store),
		pub:    pub,
		client: client,
	}
}

// userGroups resolves a user's assigned role names — the entitlement set
// the ZTNA access path evaluates group policy against.
func (e *integrationEnv) userGroups(t *testing.T, userID uuid.UUID) map[string]bool {
	t.Helper()
	urs, err := e.roles.GetUserRoles(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	out := map[string]bool{}
	for _, ur := range urs {
		r, gerr := e.roles.Get(context.Background(), ur.RoleID)
		if gerr != nil {
			t.Fatalf("get role: %v", gerr)
		}
		out[r.Name] = true
	}
	return out
}

// Okta push -> directory sync provisions -> the user is active and
// carries the IdP group as an entitlement (ZTNA access granted).
func TestIntegrationOktaPushGrantsAccess(t *testing.T) {
	t.Parallel()
	e := newIntegrationEnv(t)
	e.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", DisplayName: "Alice", Active: true, Groups: []string{"vpn-users"}},
	}
	if _, err := e.sync.SyncTenant(context.Background(), e.tid); err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}

	u, err := e.users.GetByEmail(context.Background(), e.tid, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u.Status != repository.UserStatusActive {
		t.Fatalf("status = %q, want active", u.Status)
	}
	if !e.userGroups(t, u.ID)["vpn-users"] {
		t.Errorf("expected vpn-users entitlement (ZTNA access), got %v", e.userGroups(t, u.ID))
	}
}

// SCIM create then SCIM delete -> user soft-deleted AND a revocation is
// pushed to the ZTNA plane (sessions revoked).
func TestIntegrationSCIMDeleteRevokesSessions(t *testing.T) {
	t.Parallel()
	e := newIntegrationEnv(t)
	created, err := e.scim.CreateUser(context.Background(), e.tid, SCIMUser{
		UserName: "bob@example.com",
		Active:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)

	if err := e.scim.DeleteUser(context.Background(), e.tid, uid); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	got, err := e.users.Get(context.Background(), e.tid, uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != repository.UserStatusDeleted {
		t.Errorf("status = %q, want deleted", got.Status)
	}
	if !e.pub.was(uid) {
		t.Errorf("expected revocation published on SCIM delete for %s", uid)
	}
	if e.pub.reasons[uid] != "scim_user_deleted" {
		t.Errorf("revocation reason = %q, want scim_user_deleted", e.pub.reasons[uid])
	}
}

// A directory group change re-evaluates entitlements for a user that was
// originally created via SCIM: the SCIM-provisioned user is reconciled
// to the directory's group set on the next sync.
func TestIntegrationGroupChangeReevaluatesEntitlements(t *testing.T) {
	t.Parallel()
	e := newIntegrationEnv(t)

	// Directory onboards Carol with the "contractors" group.
	e.client.users = []DirectoryUser{
		{ExternalID: "okta-9", Email: "carol@example.com", Active: true, Groups: []string{"contractors"}},
	}
	if _, err := e.sync.SyncTenant(context.Background(), e.tid); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	carol, err := e.users.GetByEmail(context.Background(), e.tid, "carol@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if !e.userGroups(t, carol.ID)["contractors"] {
		t.Fatalf("precondition: expected contractors entitlement, got %v", e.userGroups(t, carol.ID))
	}

	// Carol is promoted: directory swaps contractors -> employees.
	e.client.users = []DirectoryUser{
		{ExternalID: "okta-9", Email: "carol@example.com", Active: true, Groups: []string{"employees"}},
	}
	if _, err := e.sync.SyncTenant(context.Background(), e.tid); err != nil {
		t.Fatalf("re-eval sync: %v", err)
	}
	groups := e.userGroups(t, carol.ID)
	if !groups["employees"] {
		t.Errorf("expected employees entitlement after change, got %v", groups)
	}
	if groups["contractors"] {
		t.Errorf("expected contractors entitlement revoked after change, got %v", groups)
	}
}
