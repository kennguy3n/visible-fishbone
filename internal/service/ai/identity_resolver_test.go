package ai

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// fakeUserDirectory is a narrow in-memory userDirectory. It records
// every SearchUsers field queried so a test can assert which columns
// were (and were not) consulted.
type fakeUserDirectory struct {
	byEmail      map[string]repository.User
	byEmailErr   error
	search       map[repository.UserSearchField][]repository.User
	searchErr    error
	queriedField []repository.UserSearchField
}

func (f *fakeUserDirectory) GetByEmail(_ context.Context, _ uuid.UUID, email string) (repository.User, error) {
	if f.byEmailErr != nil {
		return repository.User{}, f.byEmailErr
	}
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return repository.User{}, repository.ErrNotFound
}

func (f *fakeUserDirectory) SearchUsers(_ context.Context, _ uuid.UUID, filter repository.UserSearchFilter, _, _ int) ([]repository.User, int, error) {
	f.queriedField = append(f.queriedField, filter.Field)
	if f.searchErr != nil {
		return nil, 0, f.searchErr
	}
	items := f.search[filter.Field]
	return items, len(items), nil
}

type fakeRoleDirectory struct {
	roles map[uuid.UUID][]repository.UserRole
	err   error
}

func (f *fakeRoleDirectory) GetUserRoles(_ context.Context, userID uuid.UUID) ([]repository.UserRole, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.roles[userID], nil
}

func TestDirectoryResolver_EmailHit_FoldsRoles(t *testing.T) {
	t.Parallel()
	uid := uuid.New()
	r1, r2 := uuid.New(), uuid.New()
	users := &fakeUserDirectory{byEmail: map[string]repository.User{
		"alice@corp": {ID: uid, Email: "alice@corp", Name: "Alice"},
	}}
	roles := &fakeRoleDirectory{roles: map[uuid.UUID][]repository.UserRole{
		uid: {{UserID: uid, RoleID: r1}, {UserID: uid, RoleID: r2}},
	}}
	got, err := NewDirectoryIdentityResolver(users, roles).ResolveUser(context.Background(), uuid.New(), "alice@corp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Principal == nil {
		t.Fatalf("expected a resolved identity with a principal, got %+v", got)
	}
	if got.Principal.UserID != uid {
		t.Fatalf("principal user id = %s, want %s", got.Principal.UserID, uid)
	}
	if got.RoleCount != 2 || len(got.Principal.RoleIDs) != 2 {
		t.Fatalf("expected 2 roles folded, got %d", got.RoleCount)
	}
	if got.Display != "alice@corp" {
		t.Fatalf("display = %q, want the email", got.Display)
	}
	if len(users.queriedField) != 0 {
		t.Fatalf("an email hit must not fall through to SearchUsers, queried %v", users.queriedField)
	}
}

func TestDirectoryResolver_EmailMiss_SkipsRedundantEmailSearch(t *testing.T) {
	t.Parallel()
	uid := uuid.New()
	users := &fakeUserDirectory{
		byEmail: map[string]repository.User{}, // GetByEmail → ErrNotFound
		search: map[repository.UserSearchField][]repository.User{
			repository.UserSearchFieldName: {{ID: uid, Name: "weird@name-as-username"}},
		},
	}
	roles := &fakeRoleDirectory{}
	got, err := NewDirectoryIdentityResolver(users, roles).ResolveUser(context.Background(), uuid.New(), "weird@name-as-username")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Principal == nil || got.Principal.UserID != uid {
		t.Fatalf("expected resolution via name, got %+v", got)
	}
	// The email-shaped ref was already tried via GetByEmail, so the
	// fallthrough search must not re-query the email column.
	for _, f := range users.queriedField {
		if f == repository.UserSearchFieldEmail {
			t.Fatalf("email column must be skipped after a GetByEmail miss; queried %v", users.queriedField)
		}
	}
	if len(users.queriedField) == 0 || users.queriedField[0] != repository.UserSearchFieldName {
		t.Fatalf("expected the search to start at the name column, queried %v", users.queriedField)
	}
}

func TestDirectoryResolver_NonEmailRef_SearchesEmailFirst(t *testing.T) {
	t.Parallel()
	uid := uuid.New()
	users := &fakeUserDirectory{
		search: map[repository.UserSearchField][]repository.User{
			repository.UserSearchFieldExternalID: {{ID: uid, ExternalID: "ext-123"}},
		},
	}
	got, err := NewDirectoryIdentityResolver(users, &fakeRoleDirectory{}).ResolveUser(context.Background(), uuid.New(), "ext-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Principal == nil || got.Principal.UserID != uid {
		t.Fatalf("expected resolution via external id, got %+v", got)
	}
	if len(users.queriedField) == 0 || users.queriedField[0] != repository.UserSearchFieldEmail {
		t.Fatalf("a non-email ref must search the email column first, queried %v", users.queriedField)
	}
}

func TestDirectoryResolver_Ambiguous_Unresolved(t *testing.T) {
	t.Parallel()
	users := &fakeUserDirectory{
		search: map[repository.UserSearchField][]repository.User{
			repository.UserSearchFieldName: {{ID: uuid.New()}, {ID: uuid.New()}},
		},
	}
	got, err := NewDirectoryIdentityResolver(users, &fakeRoleDirectory{}).ResolveUser(context.Background(), uuid.New(), "Common Name")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("an ambiguous match must resolve to nil (unresolved), got %+v", got)
	}
}

func TestDirectoryResolver_DisplayFallsBackToID(t *testing.T) {
	t.Parallel()
	uid := uuid.New()
	users := &fakeUserDirectory{byEmail: map[string]repository.User{
		"x@y": {ID: uid}, // no Email, no Name populated
	}}
	got, err := NewDirectoryIdentityResolver(users, &fakeRoleDirectory{}).ResolveUser(context.Background(), uuid.New(), "x@y")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected a resolved identity")
	}
	if got.Display != uid.String() {
		t.Fatalf("display must fall back to the user id, got %q", got.Display)
	}
}

func TestDirectoryResolver_BackendError_Propagates(t *testing.T) {
	t.Parallel()
	users := &fakeUserDirectory{byEmailErr: errors.New("directory backend down")}
	_, err := NewDirectoryIdentityResolver(users, &fakeRoleDirectory{}).ResolveUser(context.Background(), uuid.New(), "alice@corp")
	if err == nil {
		t.Fatalf("a backend failure must propagate as an error")
	}
}
