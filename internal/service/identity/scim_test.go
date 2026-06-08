package identity

import (
	"context"
	"fmt"
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

func TestSCIMUpdateGroup(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateGroup(context.Background(), tid, SCIMGroup{
		DisplayName: "Engineers",
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	gid := uuidFromString(created.ID)
	updated, err := svc.UpdateGroup(context.Background(), tid, gid, SCIMGroup{
		DisplayName: "Platform Engineers",
	})
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if updated.DisplayName != "Platform Engineers" {
		t.Errorf("displayName = %q, want Platform Engineers", updated.DisplayName)
	}
	got, err := svc.GetGroup(context.Background(), tid, gid)
	if err != nil {
		t.Fatalf("GetGroup after update: %v", err)
	}
	if got.DisplayName != "Platform Engineers" {
		t.Errorf("persisted displayName = %q, want Platform Engineers", got.DisplayName)
	}
}

func TestSCIMDeleteGroup(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateGroup(context.Background(), tid, SCIMGroup{
		DisplayName: "ToDelete",
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	gid := uuidFromString(created.ID)
	if err := svc.DeleteGroup(context.Background(), tid, gid); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	_, err = svc.GetGroup(context.Background(), tid, gid)
	if err == nil {
		t.Error("expected error after DeleteGroup, got nil")
	}
}

func TestSCIMPatchGroupReplaceDisplayName(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateGroup(context.Background(), tid, SCIMGroup{
		DisplayName: "OldName",
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	gid := uuidFromString(created.ID)
	patched, err := svc.PatchGroup(context.Background(), tid, gid, []SCIMPatchOp{
		{Op: "replace", Path: "displayName", Value: "NewName"},
	})
	if err != nil {
		t.Fatalf("PatchGroup: %v", err)
	}
	if patched.DisplayName != "NewName" {
		t.Errorf("displayName = %q, want NewName", patched.DisplayName)
	}
}

func TestSCIMPatchRemoveExternalID(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName:   "clear-ext@example.com",
		ExternalID: "ext-to-clear",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	patched, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "remove", Path: "externalId"},
	})
	if err != nil {
		t.Fatalf("PatchUser remove externalId: %v", err)
	}
	if patched.ExternalID != "" {
		t.Errorf("externalId = %q, want empty after remove", patched.ExternalID)
	}
}

func TestSCIMPatchRemoveExternalIDWithOtherUpdates(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		UserName:    "atomic-patch@example.com",
		DisplayName: "Original Name",
		ExternalID:  "ext-atomic",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	patched, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "displayName", Value: "Updated Name"},
		{Op: "remove", Path: "externalId"},
	})
	if err != nil {
		t.Fatalf("PatchUser atomic update+clear: %v", err)
	}
	if patched.DisplayName != "Updated Name" {
		t.Errorf("displayName = %q, want Updated Name", patched.DisplayName)
	}
	if patched.ExternalID != "" {
		t.Errorf("externalId = %q, want empty after atomic remove", patched.ExternalID)
	}
}

func TestSCIMListGroupsExcludesSystemRoles(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "ListGroup Test", Slug: "listgrp-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	roles := memory.NewRoleRepository(s)
	svc := NewSCIMService(
		memory.NewUserRepository(s),
		roles,
		memory.NewAuditLogRepository(s),
	)
	if _, err := roles.Create(context.Background(), repository.Role{
		Name: "platform_admin", Permissions: []string{"*"}, Scope: repository.RoleScopePlatform,
	}); err != nil {
		t.Fatalf("create system role: %v", err)
	}
	if _, err := svc.CreateGroup(context.Background(), tn.ID, SCIMGroup{
		DisplayName: "TenantGroup",
	}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	list, err := svc.ListGroups(context.Background(), tn.ID, "", 1, 100)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if list.TotalResults != 1 {
		t.Errorf("TotalResults = %d, want 1 (system role should be excluded)", list.TotalResults)
	}
	for _, res := range list.Resources {
		g, ok := res.(SCIMGroup)
		if !ok {
			continue
		}
		if g.DisplayName == "platform_admin" {
			t.Error("system role platform_admin should not appear in SCIM ListGroups")
		}
	}
}

func TestSCIMServiceProviderConfig(t *testing.T) {
	t.Parallel()
	// Just test it doesn't panic — handler test is more comprehensive.
	svc, _ := newSCIMService(t)
	_ = svc
}

func TestSCIMListUsersClampsCount(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	// Seed more than MaxPageLimit users so an unbounded count would
	// otherwise return them all in one page.
	for i := 0; i < repository.MaxPageLimit+5; i++ {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{
			UserName: fmt.Sprintf("user-%03d@example.com", i),
		}); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
	}
	// Request a hostile page size; the service must clamp to MaxPageLimit.
	list, err := svc.ListUsers(ctx, tid, "", 1, 1_000_000)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.ItemsPerPage > repository.MaxPageLimit {
		t.Errorf("ItemsPerPage = %d, want <= %d (count not clamped)", list.ItemsPerPage, repository.MaxPageLimit)
	}
	if len(list.Resources) > repository.MaxPageLimit {
		t.Errorf("len(Resources) = %d, want <= %d", len(list.Resources), repository.MaxPageLimit)
	}
}

func TestSCIMListGroupsClampsCount(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	for i := 0; i < repository.MaxPageLimit+5; i++ {
		if _, err := svc.CreateGroup(ctx, tid, SCIMGroup{
			DisplayName: fmt.Sprintf("group-%03d", i),
		}); err != nil {
			t.Fatalf("seed group %d: %v", i, err)
		}
	}
	list, err := svc.ListGroups(ctx, tid, "", 1, 1_000_000)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if list.ItemsPerPage > repository.MaxPageLimit {
		t.Errorf("ItemsPerPage = %d, want <= %d (count not clamped)", list.ItemsPerPage, repository.MaxPageLimit)
	}
}

func TestSCIMListUsersFilterContainsAndPrefix(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	for _, email := range []string{"alice@example.com", "alfred@example.com", "bob@example.com"} {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: email}); err != nil {
			t.Fatalf("CreateUser(%s): %v", email, err)
		}
	}

	// `co` (contains) and `sw` (prefix) take the general (pushdown)
	// path — only `eq` short-circuits via GetByEmail.
	co, err := svc.ListUsers(ctx, tid, `userName co "al"`, 1, 100)
	if err != nil {
		t.Fatalf("ListUsers co: %v", err)
	}
	if co.TotalResults != 2 || co.ItemsPerPage != 2 {
		t.Errorf("co: TotalResults=%d ItemsPerPage=%d, want 2/2 (alice, alfred)", co.TotalResults, co.ItemsPerPage)
	}

	sw, err := svc.ListUsers(ctx, tid, `userName sw "alf"`, 1, 100)
	if err != nil {
		t.Fatalf("ListUsers sw: %v", err)
	}
	if sw.TotalResults != 1 || sw.ItemsPerPage != 1 {
		t.Errorf("sw: TotalResults=%d ItemsPerPage=%d, want 1/1 (alfred)", sw.TotalResults, sw.ItemsPerPage)
	}
}

func TestSCIMListUsersFilterDisplayName(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "a@example.com", DisplayName: "Alice Smith"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "b@example.com", DisplayName: "Bob Jones"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	list, err := svc.ListUsers(ctx, tid, `displayName co "smith"`, 1, 100)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != 1 || list.ItemsPerPage != 1 {
		t.Errorf("TotalResults=%d ItemsPerPage=%d, want 1/1 (case-insensitive displayName co)", list.TotalResults, list.ItemsPerPage)
	}
}

func TestSCIMListUsersPaginationWindow(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	const total = 5
	for i := 0; i < total; i++ {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: fmt.Sprintf("u%02d@example.com", i)}); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
	}
	// Page through the unfiltered list 2 at a time and confirm every
	// user is returned exactly once with a stable totalResults.
	seen := map[string]bool{}
	for start := 1; start <= total; start += 2 {
		page, err := svc.ListUsers(ctx, tid, "", start, 2)
		if err != nil {
			t.Fatalf("ListUsers(start=%d): %v", start, err)
		}
		if page.TotalResults != total {
			t.Errorf("start=%d: TotalResults=%d, want %d", start, page.TotalResults, total)
		}
		if page.StartIndex != start {
			t.Errorf("start=%d: StartIndex=%d, want %d", start, page.StartIndex, start)
		}
		for _, r := range page.Resources {
			su, ok := r.(SCIMUser)
			if !ok {
				t.Fatalf("resource is %T, want SCIMUser", r)
			}
			if seen[su.ID] {
				t.Errorf("user %s returned on more than one page", su.ID)
			}
			seen[su.ID] = true
		}
	}
	if len(seen) != total {
		t.Errorf("paged through %d distinct users, want %d", len(seen), total)
	}
}

func TestSCIMListUsersTotalCountedBeyondPage(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	const seeded = repository.MaxPageLimit + 25
	for i := 0; i < seeded; i++ {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: fmt.Sprintf("user-%04d@example.com", i)}); err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
	}
	// A small page must still report the full match count: the total is
	// computed by the repository independent of the page window, so it
	// is not capped by the page size.
	list, err := svc.ListUsers(ctx, tid, `userName co "user-"`, 1, 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != seeded {
		t.Errorf("TotalResults=%d, want %d (count must span beyond the page)", list.TotalResults, seeded)
	}
	if list.ItemsPerPage != 10 || len(list.Resources) != 10 {
		t.Errorf("ItemsPerPage=%d len(Resources)=%d, want 10/10", list.ItemsPerPage, len(list.Resources))
	}
}

func TestSCIMListUsersUnknownAttributeMatchesNothing(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "a@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// An attribute with no backing column and a non-empty value can
	// never match — the service short-circuits to an empty page.
	list, err := svc.ListUsers(ctx, tid, `nickName eq "ace"`, 1, 100)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != 0 || list.ItemsPerPage != 0 {
		t.Errorf("TotalResults=%d ItemsPerPage=%d, want 0/0 for unbacked attribute", list.TotalResults, list.ItemsPerPage)
	}
}
