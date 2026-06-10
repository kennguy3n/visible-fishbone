package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// roleReconciler maps IdP directory group names onto the tenant's roles
// (SNG models a SCIM group as a role) and reconciles a user's role
// assignments to match the directory.
//
// It is built once per tenant sync from a snapshot of the directory's
// full group set so it can distinguish *directory-managed* roles (those
// named by some group in the snapshot) from roles granted by other means
// (SCIM, console, API). Off-boarding a user from a group therefore only
// ever revokes directory-managed roles, never a locally-granted one.
type roleReconciler struct {
	svc      *SyncService
	tenantID uuid.UUID
	// byName resolves a normalized group name to its role id, creating
	// the role just-in-time the first time the directory references it.
	byName map[string]uuid.UUID
	// managed is the set of role ids the directory governs this pass.
	managed map[uuid.UUID]struct{}
}

// newRoleReconciler loads the tenant's role table and indexes every role
// named by a group in the directory snapshot, creating any missing ones
// so memberships can be assigned. Roles are matched case-insensitively
// on either name or SCIM externalId.
func (s *SyncService) newRoleReconciler(ctx context.Context, tenantID uuid.UUID, dirUsers []DirectoryUser) (*roleReconciler, error) {
	existing, err := s.roles.List(ctx, &tenantID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}

	rc := &roleReconciler{
		svc:      s,
		tenantID: tenantID,
		byName:   make(map[string]uuid.UUID),
		managed:  make(map[uuid.UUID]struct{}),
	}

	// Index existing roles by both name and externalId so an IdP group
	// reconciles to a role provisioned through any path. A role with a
	// non-empty externalId is IdP-sourced and therefore directory-
	// managed: its assignment is governed by the directory even on a
	// pass where no group currently references it (so dropping a user
	// from that group revokes the role). A role with an empty externalId
	// was granted locally (console / API) and is never stripped by sync.
	roleID := make(map[string]uuid.UUID)
	for _, r := range existing {
		roleID[normGroup(r.Name)] = r.ID
		if r.ExternalID != "" {
			roleID[normGroup(r.ExternalID)] = r.ID
			rc.managed[r.ID] = struct{}{}
		}
	}

	// Collect the distinct group names the directory references.
	wantGroups := make(map[string]string) // norm -> original display
	for _, du := range dirUsers {
		if !du.Active {
			continue
		}
		for _, g := range du.Groups {
			name := strings.TrimSpace(g)
			if name == "" {
				continue
			}
			wantGroups[normGroup(name)] = name
		}
	}

	for norm, display := range wantGroups {
		if id, ok := roleID[norm]; ok {
			rc.byName[norm] = id
			rc.managed[id] = struct{}{}
			continue
		}
		created, cerr := s.roles.Create(ctx, repository.Role{
			TenantID:   &tenantID,
			Name:       display,
			ExternalID: display,
			Scope:      repository.RoleScopeTenant,
		})
		if cerr != nil {
			// A concurrent create (or a name collision from another
			// path) is recoverable: re-list and resolve by name.
			if errors.Is(cerr, repository.ErrConflict) {
				if id, rerr := s.resolveRoleByName(ctx, tenantID, norm); rerr == nil {
					rc.byName[norm] = id
					rc.managed[id] = struct{}{}
					continue
				}
			}
			return nil, fmt.Errorf("create role %q: %w", display, cerr)
		}
		rc.byName[norm] = created.ID
		rc.managed[created.ID] = struct{}{}
	}
	return rc, nil
}

// resolveRoleByName re-lists the tenant roles and returns the id of the
// role whose name or externalId matches norm.
func (s *SyncService) resolveRoleByName(ctx context.Context, tenantID uuid.UUID, norm string) (uuid.UUID, error) {
	roles, err := s.roles.List(ctx, &tenantID)
	if err != nil {
		return uuid.Nil, err
	}
	for _, r := range roles {
		if normGroup(r.Name) == norm || (r.ExternalID != "" && normGroup(r.ExternalID) == norm) {
			return r.ID, nil
		}
	}
	return uuid.Nil, repository.ErrNotFound
}

// reconcileUserGroups makes the user's directory-managed role
// assignments exactly match wantGroups: it assigns missing roles and
// revokes directory-managed roles the user no longer has upstream.
// Roles granted outside the directory are left untouched.
func (rc *roleReconciler) reconcileUserGroups(ctx context.Context, userID uuid.UUID, wantGroups []string, report *SyncReport) error {
	want := make(map[uuid.UUID]struct{}, len(wantGroups))
	for _, g := range wantGroups {
		norm := normGroup(g)
		if norm == "" {
			continue
		}
		if id, ok := rc.byName[norm]; ok {
			want[id] = struct{}{}
		}
	}

	current, err := rc.svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user roles: %w", err)
	}
	have := make(map[uuid.UUID]struct{}, len(current))
	for _, ur := range current {
		have[ur.RoleID] = struct{}{}
	}

	// Assign roles the directory grants that the user lacks.
	for roleID := range want {
		if _, ok := have[roleID]; ok {
			continue
		}
		if err := rc.svc.roles.AssignRole(ctx, repository.UserRole{
			UserID: userID,
			RoleID: roleID,
		}); err != nil && !errors.Is(err, repository.ErrConflict) {
			return fmt.Errorf("assign role %s: %w", roleID, err)
		}
		report.GroupsAssigned++
	}

	// Revoke directory-managed roles the user no longer has upstream.
	// Only roles the directory governs this pass are eligible, so a
	// console/SCIM-granted role is never stripped by a directory sync.
	for roleID := range have {
		if _, ok := want[roleID]; ok {
			continue
		}
		if _, managed := rc.managed[roleID]; !managed {
			continue
		}
		if err := rc.svc.roles.RevokeRole(ctx, userID, roleID, nil); err != nil && !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("revoke role %s: %w", roleID, err)
		}
		report.GroupsRevoked++
	}
	return nil
}

// normGroup normalizes a group / role name for case-insensitive,
// whitespace-insensitive matching between the directory and the role
// table.
func normGroup(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
