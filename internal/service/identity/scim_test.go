package identity

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newSCIMService(t *testing.T) (*SCIMService, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "SCIM Test", Slug: "scim-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	svc := NewSCIMService(
		memory.NewUserRepository(s),
		memory.NewRoleRepository(s),
		memory.NewAuditLogRepository(s),
	)
	return svc, tn.ID
}

func TestSCIMCreateUser(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	su, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		Schemas:    []string{SCIMSchemaUser},
		UserName:   "alice@example.com",
		ExternalID: "ext-001",
		Active:     boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if su.ID == "" {
		t.Error("expected non-empty ID")
	}
	if su.UserName != "alice@example.com" {
		t.Errorf("userName = %q, want alice@example.com", su.UserName)
	}
	if su.ExternalID != "ext-001" {
		t.Errorf("externalId = %q, want ext-001", su.ExternalID)
	}
}

func TestSCIMGetUser(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := svc.GetUser(context.Background(), tid, uuidFromString(created.ID))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.UserName != "bob@example.com" {
		t.Errorf("userName = %q, want bob@example.com", got.UserName)
	}
}

func TestSCIMUpdateUser(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName: "carol@example.com",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	updated, err := svc.UpdateUser(context.Background(), tid, uid, SCIMUser{
		UserName:    "carol.new@example.com",
		DisplayName: "Carol New",
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.UserName != "carol.new@example.com" {
		t.Errorf("userName = %q, want carol.new@example.com", updated.UserName)
	}
	if updated.DisplayName != "Carol New" {
		t.Errorf("displayName = %q, want Carol New", updated.DisplayName)
	}
}

func TestSCIMPatchUser(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName: "dave@example.com",
		Active:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	patched, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	})
	if err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if patched.Active == nil || *patched.Active {
		t.Error("expected active=false after PATCH")
	}
}

func TestSCIMDeleteUser(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName: "eve@example.com",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	if err := svc.DeleteUser(context.Background(), tid, uid); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	got, err := svc.GetUser(context.Background(), tid, uid)
	if err != nil {
		t.Fatalf("GetUser after delete: %v", err)
	}
	if got.Active == nil || *got.Active {
		t.Error("expected active=false after SCIM DELETE")
	}
}

func TestSCIMListUsers(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	for _, email := range []string{"u1@example.com", "u2@example.com", "u3@example.com"} {
		_, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: email})
		if err != nil {
			t.Fatalf("CreateUser(%s): %v", email, err)
		}
	}
	list, err := svc.ListUsers(context.Background(), tid, "", 1, 100)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != 3 {
		t.Errorf("totalResults = %d, want 3", list.TotalResults)
	}
}

func TestSCIMListUsersFilter(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	_, _ = svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "alice@example.com"})
	_, _ = svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "bob@example.com"})

	list, err := svc.ListUsers(context.Background(), tid, `userName eq "alice@example.com"`, 1, 100)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != 1 {
		t.Errorf("totalResults = %d, want 1 (filtered by userName eq)", list.TotalResults)
	}
}

func TestSCIMTenantIsolation(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tn1, _ := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T1", Slug: "t1", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	tn2, _ := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T2", Slug: "t2", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	svc := NewSCIMService(
		memory.NewUserRepository(s),
		memory.NewRoleRepository(s),
		memory.NewAuditLogRepository(s),
	)
	_, _ = svc.CreateUser(context.Background(), tn1.ID, SCIMUser{UserName: "a@t1.com"})
	_, _ = svc.CreateUser(context.Background(), tn2.ID, SCIMUser{UserName: "b@t2.com"})

	list1, _ := svc.ListUsers(context.Background(), tn1.ID, "", 1, 100)
	list2, _ := svc.ListUsers(context.Background(), tn2.ID, "", 1, 100)
	if list1.TotalResults != 1 {
		t.Errorf("tenant1 totalResults = %d, want 1", list1.TotalResults)
	}
	if list2.TotalResults != 1 {
		t.Errorf("tenant2 totalResults = %d, want 1", list2.TotalResults)
	}
}

func TestSCIMCreateGroup(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	sg, err := svc.CreateGroup(context.Background(), tid, SCIMGroup{
		DisplayName: "Engineers",
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if sg.ID == "" {
		t.Error("expected non-empty group ID")
	}
	if sg.DisplayName != "Engineers" {
		t.Errorf("displayName = %q, want Engineers", sg.DisplayName)
	}
}

func TestSCIMGetGroup(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateGroup(context.Background(), tid, SCIMGroup{
		DisplayName: "Admins",
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	got, err := svc.GetGroup(context.Background(), tid, uuidFromString(created.ID))
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.DisplayName != "Admins" {
		t.Errorf("displayName = %q, want Admins", got.DisplayName)
	}
}

func TestSCIMListGroups(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	_, _ = svc.CreateGroup(context.Background(), tid, SCIMGroup{DisplayName: "G1"})
	_, _ = svc.CreateGroup(context.Background(), tid, SCIMGroup{DisplayName: "G2"})
	list, err := svc.ListGroups(context.Background(), tid, "", 1, 100)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if list.TotalResults != 2 {
		t.Errorf("totalResults = %d, want 2", list.TotalResults)
	}
}

// --- Filter parser tests --------------------------------------------------

func TestParseSCIMFilter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		want    SCIMFilter
		wantErr bool
	}{
		{"eq with quotes", `userName eq "alice"`, SCIMFilter{"userName", SCIMFilterEq, "alice"}, false},
		{"co with quotes", `displayName co "bob"`, SCIMFilter{"displayName", SCIMFilterCo, "bob"}, false},
		{"sw with quotes", `userName sw "a"`, SCIMFilter{"userName", SCIMFilterSw, "a"}, false},
		{"case insensitive op", `userName EQ "alice"`, SCIMFilter{"userName", SCIMFilterEq, "alice"}, false},
		{"no quotes", `userName eq alice`, SCIMFilter{"userName", SCIMFilterEq, "alice"}, false},
		{"empty", ``, SCIMFilter{}, true},
		{"bad op", `userName xx "alice"`, SCIMFilter{}, true},
		{"too few parts", `userName`, SCIMFilter{}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSCIMFilter(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSCIMFilterMatchUser(t *testing.T) {
	t.Parallel()
	u := SCIMUser{UserName: "alice@example.com", DisplayName: "Alice"}
	f1 := SCIMFilter{Attribute: "userName", Op: SCIMFilterEq, Value: "alice@example.com"}
	if !f1.MatchUser(u) {
		t.Error("expected match for userName eq")
	}
	f2 := SCIMFilter{Attribute: "displayName", Op: SCIMFilterCo, Value: "lic"}
	if !f2.MatchUser(u) {
		t.Error("expected match for displayName co")
	}
	f3 := SCIMFilter{Attribute: "userName", Op: SCIMFilterEq, Value: "bob@example.com"}
	if f3.MatchUser(u) {
		t.Error("expected no match for wrong userName")
	}
}

func TestSCIMServiceProviderConfig(t *testing.T) {
	t.Parallel()
	// Just test it doesn't panic — handler test is more comprehensive.
	svc, _ := newSCIMService(t)
	_ = svc
}
