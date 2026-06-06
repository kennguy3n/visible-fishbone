package identity

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fakeProvisioner is an in-memory IdentityProvisioner recording the
// calls the SCIM bridge makes against iam-core.
type fakeProvisioner struct {
	users      map[string]iamcore.ManagementUser // user_id -> user
	byEmail    map[string]string                 // email -> user_id
	nextID     int
	created    []string
	updated    []string
	blocked    []string
	unblocked  []string
	deleted    []string
	failCreate bool
}

func newFakeProvisioner() *fakeProvisioner {
	return &fakeProvisioner{
		users:   map[string]iamcore.ManagementUser{},
		byEmail: map[string]string{},
	}
}

func (f *fakeProvisioner) FindUserByEmail(_ context.Context, iamTenantID, email string) (iamcore.ManagementUser, bool, error) {
	id, ok := f.byEmail[email]
	if !ok {
		return iamcore.ManagementUser{}, false, nil
	}
	return f.users[id], true, nil
}

func (f *fakeProvisioner) CreateUser(_ context.Context, iamTenantID string, in iamcore.CreateManagementUser) (iamcore.ManagementUser, error) {
	if f.failCreate {
		return iamcore.ManagementUser{}, &iamcore.APIError{Op: "create", StatusCode: http.StatusBadGateway}
	}
	f.nextID++
	id := "iam-user-" + string(rune('a'+f.nextID-1))
	u := iamcore.ManagementUser{UserID: id, TenantID: iamTenantID, Email: in.Email, Name: in.Name}
	f.users[id] = u
	f.byEmail[in.Email] = id
	f.created = append(f.created, id)
	return u, nil
}

func (f *fakeProvisioner) UpdateUser(_ context.Context, iamTenantID, userID string, in iamcore.UpdateManagementUser) (iamcore.ManagementUser, error) {
	u, ok := f.users[userID]
	if !ok {
		return iamcore.ManagementUser{}, &iamcore.APIError{Op: "update", StatusCode: http.StatusNotFound}
	}
	if in.Name != nil {
		u.Name = *in.Name
	}
	f.users[userID] = u
	f.updated = append(f.updated, userID)
	return u, nil
}

func (f *fakeProvisioner) BlockUser(_ context.Context, iamTenantID, userID string) error {
	f.blocked = append(f.blocked, userID)
	return nil
}

func (f *fakeProvisioner) UnblockUser(_ context.Context, iamTenantID, userID string) error {
	f.unblocked = append(f.unblocked, userID)
	return nil
}

func (f *fakeProvisioner) DeleteUser(_ context.Context, iamTenantID, userID string) error {
	delete(f.users, userID)
	f.deleted = append(f.deleted, userID)
	return nil
}

// fakeTenantMapper maps every SNG tenant to one fixed iam-core tenant.
type fakeTenantMapper struct {
	iamTenant string
	calls     int
}

func (m *fakeTenantMapper) IAMCoreTenantID(_ context.Context, _ uuid.UUID) (string, error) {
	m.calls++
	return m.iamTenant, nil
}

func newBridgedSCIM(t *testing.T, prov IdentityProvisioner, mapper IAMCoreTenantMapper) (*SCIMService, repository.UserRepository, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Bridge Test", Slug: "bridge-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	users := memory.NewUserRepository(s)
	svc := NewSCIMService(users, memory.NewRoleRepository(s), memory.NewAuditLogRepository(s),
		WithIAMCoreBridge(prov, mapper))
	return svc, users, tn.ID
}

func TestSCIMBridge_CreatePropagatesAndStoresIAMUserID(t *testing.T) {
	t.Parallel()
	prov := newFakeProvisioner()
	mapper := &fakeTenantMapper{iamTenant: "iam-tenant-1"}
	svc, users, tid := newBridgedSCIM(t, prov, mapper)

	su, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName: "carol@example.com",
		Name:     SCIMName{GivenName: "Carol", FamilyName: "Smith"},
		Active:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if len(prov.created) != 1 {
		t.Fatalf("expected 1 upstream create, got %d", len(prov.created))
	}
	// The iam-core user_id must be persisted as the local IDPSubject.
	uid := uuid.MustParse(su.ID)
	stored, err := users.Get(context.Background(), tid, uid)
	if err != nil {
		t.Fatalf("get stored user: %v", err)
	}
	if stored.IDPSubject != prov.created[0] {
		t.Errorf("IDPSubject = %q, want %q", stored.IDPSubject, prov.created[0])
	}
}

func TestSCIMBridge_CreateReusesExistingUpstreamUser(t *testing.T) {
	t.Parallel()
	prov := newFakeProvisioner()
	// Pre-seed an upstream user with the same email (IdP retry case).
	prov.users["iam-existing"] = iamcore.ManagementUser{UserID: "iam-existing", Email: "dup@example.com"}
	prov.byEmail["dup@example.com"] = "iam-existing"
	mapper := &fakeTenantMapper{iamTenant: "iam-tenant-1"}
	svc, users, tid := newBridgedSCIM(t, prov, mapper)

	su, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "dup@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if len(prov.created) != 0 {
		t.Errorf("expected reuse (no upstream create), got %d creates", len(prov.created))
	}
	stored, _ := users.Get(context.Background(), tid, uuid.MustParse(su.ID))
	if stored.IDPSubject != "iam-existing" {
		t.Errorf("IDPSubject = %q, want iam-existing", stored.IDPSubject)
	}
}

func TestSCIMBridge_CreateFailClosed_NoLocalUser(t *testing.T) {
	t.Parallel()
	prov := newFakeProvisioner()
	prov.failCreate = true
	mapper := &fakeTenantMapper{iamTenant: "iam-tenant-1"}
	svc, users, tid := newBridgedSCIM(t, prov, mapper)

	_, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "fail@example.com"})
	if err == nil {
		t.Fatal("expected error when upstream provisioning fails")
	}
	// No local user must be created when upstream provisioning fails.
	res, lerr := users.List(context.Background(), tid, repository.Page{Limit: 10})
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	if len(res.Items) != 0 {
		t.Errorf("expected 0 local users on fail-closed create, got %d", len(res.Items))
	}
}

func TestSCIMBridge_DeactivateBlocksUpstream(t *testing.T) {
	t.Parallel()
	prov := newFakeProvisioner()
	mapper := &fakeTenantMapper{iamTenant: "iam-tenant-1"}
	svc, _, tid := newBridgedSCIM(t, prov, mapper)

	su, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "dave@example.com", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	iamID := prov.created[0]
	if _, err := svc.UpdateUser(context.Background(), tid, uuid.MustParse(su.ID), SCIMUser{
		UserName: "dave@example.com",
		Active:   boolPtr(false),
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if len(prov.blocked) != 1 || prov.blocked[0] != iamID {
		t.Errorf("expected block of %q, got %v", iamID, prov.blocked)
	}
}

func TestSCIMBridge_DeletePropagatesUpstreamDelete(t *testing.T) {
	t.Parallel()
	prov := newFakeProvisioner()
	mapper := &fakeTenantMapper{iamTenant: "iam-tenant-1"}
	svc, _, tid := newBridgedSCIM(t, prov, mapper)

	su, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "erin@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	iamID := prov.created[0]
	if err := svc.DeleteUser(context.Background(), tid, uuid.MustParse(su.ID)); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if len(prov.deleted) != 1 || prov.deleted[0] != iamID {
		t.Errorf("expected upstream delete of %q, got %v", iamID, prov.deleted)
	}
}

func TestSCIMBridge_DisabledIsLocalOnly(t *testing.T) {
	t.Parallel()
	// No bridge option: behaves as pure local SCIM.
	svc, tid := newSCIMService(t)
	if _, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "local@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}
