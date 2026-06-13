package identity

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// --- test doubles ---------------------------------------------------------

type fakeDirectoryClient struct {
	users []DirectoryUser
	err   error
}

func (f *fakeDirectoryClient) ListUsers(_ context.Context) ([]DirectoryUser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.users, nil
}

type fakeFactory struct{ client DirectoryClient }

func (f fakeFactory) Build(_ repository.IDPConfig, _ DirectoryCredential) (DirectoryClient, error) {
	return f.client, nil
}

type staticCreds struct{}

func (staticCreds) Resolve(_ context.Context, _ uuid.UUID, _ repository.IDPConfig) (DirectoryCredential, error) {
	return DirectoryCredential{BaseURL: "https://acme.okta.com", Token: "tok"}, nil
}

type singleTenant struct{ id uuid.UUID }

func (s singleTenant) ListTenants(_ context.Context) ([]uuid.UUID, error) {
	return []uuid.UUID{s.id}, nil
}

type capturePublisher struct {
	mu      sync.Mutex
	revoked []uuid.UUID
	reasons map[uuid.UUID]string
}

func newCapturePublisher() *capturePublisher {
	return &capturePublisher{reasons: map[uuid.UUID]string{}}
}

func (p *capturePublisher) PublishRevocation(_ context.Context, _, userID uuid.UUID, reason string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, userID)
	p.reasons[userID] = reason
	return nil
}

func (p *capturePublisher) was(userID uuid.UUID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.reasons[userID]
	return ok
}

// syncFixture wires a SyncService over memory repos with a fake
// directory client, returning the service, tenant id, repos, and the
// revocation capture.
type syncFixture struct {
	svc    *SyncService
	tid    uuid.UUID
	users  repository.UserRepository
	roles  repository.RoleRepository
	pub    *capturePublisher
	client *fakeDirectoryClient
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "Sync Test", Slug: "sync-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType:   repository.IDPProviderOkta,
		IssuerURL:      "https://acme.okta.com",
		ClientID:       "client-okta",
		GroupClaimPath: "groups",
		Enabled:        true,
	}); err != nil {
		t.Fatalf("seed idp config: %v", err)
	}

	client := &fakeDirectoryClient{}
	pub := newCapturePublisher()
	svc := NewSyncService(
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
	return &syncFixture{
		svc:    svc,
		tid:    tn.ID,
		users:  memory.NewUserRepository(store),
		roles:  memory.NewRoleRepository(store),
		pub:    pub,
		client: client,
	}
}

func (f *syncFixture) userByEmail(t *testing.T, email string) repository.User {
	t.Helper()
	u, err := f.users.GetByEmail(context.Background(), f.tid, email)
	if err != nil {
		t.Fatalf("GetByEmail %s: %v", email, err)
	}
	return u
}

// --- tests ----------------------------------------------------------------

// Okta push -> SCIM create equivalent -> ZTNA access (groups) granted.
func TestSyncProvisionsUsersAndGroups(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "Alice@Example.com", DisplayName: "Alice", Active: true, Groups: []string{"Engineering", "Admins"}},
	}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.UsersProvisioned != 1 {
		t.Fatalf("provisioned = %d, want 1 (errors: %v)", report.UsersProvisioned, report.Errors)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", report.Errors)
	}

	u := f.userByEmail(t, "alice@example.com")
	if u.Status != repository.UserStatusActive {
		t.Errorf("status = %q, want active", u.Status)
	}
	if u.IDPSubject != "okta-1" {
		t.Errorf("IDPSubject = %q, want okta-1", u.IDPSubject)
	}

	roles, err := f.roles.GetUserRoles(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("user roles = %d, want 2", len(roles))
	}
}

// SCIM delete equivalent: user absent from directory -> deactivated +
// revocation pushed.
func TestSyncOffboardsAbsentUser(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true, Groups: []string{"Engineering"}},
	}
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	alice := f.userByEmail(t, "alice@example.com")

	// Next pull no longer lists Alice.
	f.client.users = nil
	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.UsersOffboarded != 1 {
		t.Fatalf("offboarded = %d, want 1", report.UsersOffboarded)
	}
	got := f.userByEmail(t, "alice@example.com")
	if got.Status != repository.UserStatusDeleted {
		t.Errorf("status = %q, want deleted", got.Status)
	}
	if !f.pub.was(alice.ID) {
		t.Errorf("expected revocation published for %s", alice.ID)
	}
}

// A user the directory reports as deactivated is off-boarded too.
func TestSyncOffboardsDeactivatedUser(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true, Groups: []string{"Engineering"}},
	}
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	alice := f.userByEmail(t, "alice@example.com")

	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: false},
	}
	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.UsersOffboarded != 1 {
		t.Fatalf("offboarded = %d, want 1", report.UsersOffboarded)
	}
	if !f.pub.was(alice.ID) {
		t.Errorf("expected revocation for deactivated user %s", alice.ID)
	}
}

// Group change -> entitlement re-evaluated: directory-managed role added
// and removed; a locally-granted role is left intact.
func TestSyncReconcilesGroupChanges(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true, Groups: []string{"Engineering"}},
	}
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	alice := f.userByEmail(t, "alice@example.com")

	// Grant a local-only role that no directory group maps to.
	localRole, err := f.roles.Create(context.Background(), repository.Role{
		TenantID: &f.tid, Name: "LocalOnly", Scope: repository.RoleScopeTenant,
	})
	if err != nil {
		t.Fatalf("create local role: %v", err)
	}
	if err := f.roles.AssignRole(context.Background(), repository.UserRole{UserID: alice.ID, RoleID: localRole.ID}); err != nil {
		t.Fatalf("assign local role: %v", err)
	}

	// Directory now drops Engineering and adds Admins.
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true, Groups: []string{"Admins"}},
	}
	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.GroupsAssigned != 1 {
		t.Errorf("assigned = %d, want 1", report.GroupsAssigned)
	}
	if report.GroupsRevoked != 1 {
		t.Errorf("revoked = %d, want 1", report.GroupsRevoked)
	}

	roles, err := f.roles.GetUserRoles(context.Background(), alice.ID)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	names := map[string]bool{}
	for _, ur := range roles {
		r, gerr := f.roles.Get(context.Background(), ur.RoleID)
		if gerr != nil {
			t.Fatalf("get role: %v", gerr)
		}
		names[r.Name] = true
	}
	if !names["Admins"] {
		t.Errorf("expected Admins assigned, got %v", names)
	}
	if names["Engineering"] {
		t.Errorf("expected Engineering revoked, got %v", names)
	}
	if !names["LocalOnly"] {
		t.Errorf("expected locally-granted role preserved, got %v", names)
	}
}

// A reactivated upstream user is restored to active locally.
func TestSyncReactivatesUser(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
	}
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	alice := f.userByEmail(t, "alice@example.com")

	// Offboard.
	f.client.users = nil
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("offboard sync: %v", err)
	}
	if got := f.userByEmail(t, "alice@example.com"); got.Status != repository.UserStatusDeleted {
		t.Fatalf("precondition: status = %q, want deleted", got.Status)
	}

	// Reappears active.
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
	}
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("reactivate sync: %v", err)
	}
	got := f.userByEmail(t, "alice@example.com")
	if got.Status != repository.UserStatusActive {
		t.Errorf("status = %q, want active after reactivation", got.Status)
	}
	_ = alice
}

// Disabled IdP configs are skipped entirely.
func TestSyncSkipsDisabledConfig(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "Disabled", Slug: "disabled", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "client",
		Enabled:      false,
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	client := &fakeDirectoryClient{users: []DirectoryUser{{Email: "x@example.com", Active: true}}}
	svc := NewSyncService(configs, memory.NewUserRepository(store), memory.NewRoleRepository(store),
		memory.NewAuditLogRepository(store), singleTenant{id: tn.ID}, staticCreds{}, fakeFactory{client: client}, newCapturePublisher(), nil)

	report, err := svc.SyncTenant(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.ConfigsProcessed != 0 {
		t.Errorf("configs processed = %d, want 0 (disabled)", report.ConfigsProcessed)
	}
	if report.UsersSeen != 0 {
		t.Errorf("users seen = %d, want 0", report.UsersSeen)
	}
}

// noCreds resolves nothing — it models a provider config enabled for
// token validation but never opted into directory sync.
type noCreds struct{}

func (noCreds) Resolve(_ context.Context, _ uuid.UUID, _ repository.IDPConfig) (DirectoryCredential, error) {
	return DirectoryCredential{}, ErrNoDirectoryCredential
}

// An enabled config with no stored directory credential is counted as
// skipped, not errored: the sync loop must stay quiet for the common
// case of token-validation-only providers.
func TestSyncSkipsConfigWithoutCredential(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "NoCred", Slug: "nocred", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
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
	client := &fakeDirectoryClient{users: []DirectoryUser{{Email: "x@example.com", Active: true}}}
	svc := NewSyncService(configs, memory.NewUserRepository(store), memory.NewRoleRepository(store),
		memory.NewAuditLogRepository(store), singleTenant{id: tn.ID}, noCreds{}, fakeFactory{client: client}, newCapturePublisher(), nil)

	report, err := svc.SyncTenant(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.ConfigsProcessed != 1 {
		t.Errorf("configs processed = %d, want 1", report.ConfigsProcessed)
	}
	if report.ConfigsSkipped != 1 {
		t.Errorf("configs skipped = %d, want 1", report.ConfigsSkipped)
	}
	if len(report.Errors) != 0 {
		t.Errorf("errors = %v, want none (missing credential is not an error)", report.Errors)
	}
	if report.UsersSeen != 0 {
		t.Errorf("users seen = %d, want 0 (skipped before directory call)", report.UsersSeen)
	}
}

// --- directory observer ---------------------------------------------------

type dirListRecord struct {
	provider string
	users    int
	err      error
}

type recordingDirObserver struct {
	mu      sync.Mutex
	records []dirListRecord
}

func (o *recordingDirObserver) ObserveDirectoryList(provider string, users int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, dirListRecord{provider: provider, users: users, err: err})
}

// A successful directory read reports one observation tagged with the
// provider and the number of users returned, with a nil error.
func TestSyncDirectoryObserverRecordsSuccess(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	obs := &recordingDirObserver{}
	f.svc.WithDirectoryObserver(obs)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
		{ExternalID: "okta-2", Email: "bob@example.com", Active: true},
	}

	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if len(obs.records) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs.records))
	}
	rec := obs.records[0]
	if rec.provider != string(repository.IDPProviderOkta) || rec.users != 2 || rec.err != nil {
		t.Errorf("record = %+v, want {okta 2 <nil>}", rec)
	}
}

// A failed directory read still reports one observation, tagged with the
// error and zero users, so an errored connector is visible in metrics.
func TestSyncDirectoryObserverRecordsError(t *testing.T) {
	t.Parallel()
	f := newSyncFixture(t)
	obs := &recordingDirObserver{}
	f.svc.WithDirectoryObserver(obs)
	f.client.err = context.DeadlineExceeded

	// The list failure surfaces as a per-config error on the report, but
	// SyncTenant itself does not fail the whole tenant.
	if _, err := f.svc.SyncTenant(context.Background(), f.tid); err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if len(obs.records) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs.records))
	}
	rec := obs.records[0]
	if rec.provider != string(repository.IDPProviderOkta) || rec.users != 0 || rec.err == nil {
		t.Errorf("record = %+v, want {okta 0 <non-nil err>}", rec)
	}
}
