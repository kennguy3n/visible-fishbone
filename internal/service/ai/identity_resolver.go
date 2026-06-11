// Package ai — identity_resolver.go resolves a natural-language
// policy query's free-form user reference (an email, display name, or
// external/IdP ID) to a concrete tenant directory identity so that
// user-subject policy rules can actually be evaluated against it.
//
// This closes the "identity depth" gap in the NL policy-query path:
// the synthesized access envelope can't carry user identity, so before
// this the evaluator skipped every user-subject rule and the verdict
// reflected only app/device + default-action matching. Resolving the
// named user into a policy.Principal (its own ID plus the IDs of the
// roles/groups it belongs to) lets the evaluator match both per-user
// and per-group user subjects.

package ai

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// ResolvedIdentity is the outcome of resolving a query's user
// reference to a concrete tenant directory identity.
type ResolvedIdentity struct {
	// Principal is the identity threaded into the policy evaluator so
	// user-subject rules match against the user and its roles/groups.
	Principal *policy.Principal
	// Display is the resolved user's email (preferred) or name, used in
	// the verdict explanation as auditable evidence of who was matched.
	Display string
	// RoleCount is the number of roles/groups folded into the principal,
	// surfaced in the explanation.
	RoleCount int
}

// IdentityResolver maps a free-form user reference from a policy query
// to a concrete principal. ResolveUser returns (nil, nil) when the
// reference does not uniquely identify exactly one tenant user
// (unknown or ambiguous) so the caller degrades gracefully to
// app/device-only evaluation; a non-nil error is reserved for an
// actual directory backend failure.
type IdentityResolver interface {
	ResolveUser(ctx context.Context, tenantID uuid.UUID, ref string) (*ResolvedIdentity, error)
}

// userDirectory is the read-only slice of the user repository the
// resolver needs. Kept narrow so the resolver never gains a write path
// into the directory.
type userDirectory interface {
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (repository.User, error)
	SearchUsers(ctx context.Context, tenantID uuid.UUID, filter repository.UserSearchFilter, offset, limit int) (items []repository.User, total int, err error)
}

// roleDirectory is the read-only slice of the role repository the
// resolver needs to fold a user's role/group membership into the
// principal.
type roleDirectory interface {
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]repository.UserRole, error)
}

// DirectoryIdentityResolver resolves user references against the
// tenant's user + role directories.
type DirectoryIdentityResolver struct {
	users userDirectory
	roles roleDirectory
}

// NewDirectoryIdentityResolver wires the resolver to the user and role
// repositories.
func NewDirectoryIdentityResolver(users userDirectory, roles roleDirectory) *DirectoryIdentityResolver {
	return &DirectoryIdentityResolver{users: users, roles: roles}
}

// ResolveUser resolves ref to exactly one tenant user and folds its
// role/group IDs into a principal. An email-shaped ref is resolved by
// exact email first; otherwise (and as a fallback) an exact,
// case-insensitive match is attempted against email, name, then
// external ID, requiring a unique hit. A non-unique or absent match
// yields (nil, nil) — the caller treats the user as unresolved.
func (r *DirectoryIdentityResolver) ResolveUser(ctx context.Context, tenantID uuid.UUID, ref string) (*ResolvedIdentity, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil
	}
	user, ok, err := r.lookup(ctx, tenantID, ref)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	roles, err := r.roles.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	roleIDs := make([]uuid.UUID, 0, len(roles))
	for _, ur := range roles {
		roleIDs = append(roleIDs, ur.RoleID)
	}

	display := user.Email
	if display == "" {
		display = user.Name
	}
	return &ResolvedIdentity{
		Principal: &policy.Principal{UserID: user.ID, RoleIDs: roleIDs},
		Display:   display,
		RoleCount: len(roleIDs),
	}, nil
}

// lookup finds the unique tenant user identified by ref. It returns
// (user, true, nil) on a unique match, (_, false, nil) when the ref is
// unknown or ambiguous, and a non-nil error only on a backend failure.
func (r *DirectoryIdentityResolver) lookup(ctx context.Context, tenantID uuid.UUID, ref string) (repository.User, bool, error) {
	if strings.Contains(ref, "@") {
		switch u, err := r.users.GetByEmail(ctx, tenantID, ref); {
		case err == nil:
			return u, true, nil
		case errors.Is(err, repository.ErrNotFound):
			// Not an email we know; fall through to the generic
			// exact-match search (the ref might be an unusual username).
		default:
			return repository.User{}, false, err
		}
	}

	// Exact, case-insensitive match against the identifier columns, most
	// specific first. total counts all matches independent of the page
	// window, so total == 1 is a unique hit; total > 1 is ambiguous and
	// we decline to guess.
	for _, field := range []repository.UserSearchField{
		repository.UserSearchFieldEmail,
		repository.UserSearchFieldName,
		repository.UserSearchFieldExternalID,
	} {
		items, total, err := r.users.SearchUsers(ctx, tenantID, repository.UserSearchFilter{
			Field: field,
			Op:    repository.TextMatchEquals,
			Value: ref,
		}, 0, 1)
		if err != nil {
			return repository.User{}, false, err
		}
		if total == 1 && len(items) == 1 {
			return items[0], true, nil
		}
	}
	return repository.User{}, false, nil
}
