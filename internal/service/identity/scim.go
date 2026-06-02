package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SCIMService implements inbound SCIM 2.0 user + group provisioning
// (RFC 7643 / 7644). All operations are tenant-isolated via the
// existing tenant context pattern.
type SCIMService struct {
	users   repository.UserRepository
	roles   repository.RoleRepository
	audit   repository.AuditLogRepository
	nowFunc func() time.Time
}

// NewSCIMService returns a ready-to-use SCIM provisioning service.
func NewSCIMService(
	users repository.UserRepository,
	roles repository.RoleRepository,
	audit repository.AuditLogRepository,
) *SCIMService {
	return &SCIMService{
		users:   users,
		roles:   roles,
		audit:   audit,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// --- User operations ------------------------------------------------------

// CreateUser provisions a SCIM user into the tenant.
func (s *SCIMService) CreateUser(ctx context.Context, tenantID uuid.UUID, su SCIMUser) (SCIMUser, error) {
	if su.UserName == "" {
		return SCIMUser{}, fmt.Errorf("userName is required: %w", repository.ErrInvalidArgument)
	}
	email := su.UserName
	if len(su.Emails) > 0 {
		for _, e := range su.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
	}
	active := true
	if su.Active != nil {
		active = *su.Active
	}
	status := repository.UserStatusActive
	if !active {
		status = repository.UserStatusSuspended
	}
	displayName := su.DisplayName
	if displayName == "" {
		displayName = su.Name.Formatted
		if displayName == "" && (su.Name.GivenName != "" || su.Name.FamilyName != "") {
			displayName = strings.TrimSpace(su.Name.GivenName + " " + su.Name.FamilyName)
		}
	}
	u, err := s.users.Create(ctx, tenantID, repository.User{
		Email:      email,
		Name:       displayName,
		ExternalID: su.ExternalID,
		Status:     status,
	})
	if err != nil {
		return SCIMUser{}, err
	}
	return userToSCIM(u), nil
}

// GetUser returns a SCIM user by ID.
func (s *SCIMService) GetUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (SCIMUser, error) {
	u, err := s.users.Get(ctx, tenantID, userID)
	if err != nil {
		return SCIMUser{}, err
	}
	return userToSCIM(u), nil
}

// UpdateUser replaces a SCIM user (PUT semantics).
func (s *SCIMService) UpdateUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, su SCIMUser) (SCIMUser, error) {
	email := su.UserName
	if len(su.Emails) > 0 {
		for _, e := range su.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
	}
	active := true
	if su.Active != nil {
		active = *su.Active
	}
	status := repository.UserStatusActive
	if !active {
		status = repository.UserStatusSuspended
	}
	displayName := su.DisplayName
	if displayName == "" {
		displayName = su.Name.Formatted
		if displayName == "" && (su.Name.GivenName != "" || su.Name.FamilyName != "") {
			displayName = strings.TrimSpace(su.Name.GivenName + " " + su.Name.FamilyName)
		}
	}
	u := repository.User{
		ID:         userID,
		Email:      email,
		Name:       displayName,
		ExternalID: su.ExternalID,
		Status:     status,
	}
	var updated repository.User
	var err error
	if su.ExternalID == "" {
		updated, err = s.users.UpdateAndClearExternalID(ctx, tenantID, u)
	} else {
		updated, err = s.users.Update(ctx, tenantID, u)
	}
	if err != nil {
		return SCIMUser{}, err
	}
	return userToSCIM(updated), nil
}

// PatchUser applies a SCIM PATCH operation (RFC 7644 §3.5.2).
func (s *SCIMService) PatchUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ops []SCIMPatchOp) (SCIMUser, error) {
	u, err := s.users.Get(ctx, tenantID, userID)
	if err != nil {
		return SCIMUser{}, err
	}
	clearExternalID := false
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace":
			applyUserReplace(&u, op)
		case "add":
			applyUserReplace(&u, op) // add semantics = replace for single-valued
		case "remove":
			if strings.EqualFold(op.Path, "externalid") {
				clearExternalID = true
			} else {
				applyUserRemove(&u, op)
			}
		default:
			return SCIMUser{}, fmt.Errorf("unsupported SCIM PatchOp: %s: %w", op.Op, repository.ErrInvalidArgument)
		}
	}
	var updated repository.User
	if clearExternalID {
		updated, err = s.users.UpdateAndClearExternalID(ctx, tenantID, u)
	} else {
		updated, err = s.users.Update(ctx, tenantID, u)
	}
	if err != nil {
		return SCIMUser{}, err
	}
	return userToSCIM(updated), nil
}

// DeleteUser deactivates a SCIM user (SCIM DELETE = set active=false).
func (s *SCIMService) DeleteUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error {
	_, err := s.users.Update(ctx, tenantID, repository.User{
		ID:     userID,
		Status: repository.UserStatusDeleted,
	})
	return err
}

// ListUsers returns a SCIM list response for users matching the filter.
func (s *SCIMService) ListUsers(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (SCIMListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = repository.DefaultPageLimit
	}

	var parsed *SCIMFilter
	if filter != "" {
		f, err := ParseSCIMFilter(filter)
		if err != nil {
			return SCIMListResponse{}, fmt.Errorf("invalid filter: %w: %w", err, repository.ErrInvalidArgument)
		}
		parsed = &f
	}

	// Fast path: userName eq "x" — the standard IdP dedup lookup
	// (Okta, Azure AD, OneLogin). Use GetByEmail for O(1) indexed
	// lookup instead of paginating through all users.
	if parsed != nil && parsed.Op == SCIMFilterEq &&
		strings.EqualFold(parsed.Attribute, "username") {
		u, err := s.users.GetByEmail(ctx, tenantID, parsed.Value)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return SCIMListResponse{
					Schemas:      []string{SCIMSchemaList},
					TotalResults: 0,
					StartIndex:   startIndex,
					ItemsPerPage: 0,
					Resources:    []any{},
				}, nil
			}
			return SCIMListResponse{}, err
		}
		return SCIMListResponse{
			Schemas:      []string{SCIMSchemaList},
			TotalResults: 1,
			StartIndex:   startIndex,
			ItemsPerPage: 1,
			Resources:    []any{userToSCIM(u)},
		}, nil
	}

	// General path: paginate through all users, applying filter
	// in-memory. This handles co/sw filters and unfiltered lists.
	var allUsers []repository.User
	after := ""
	for {
		page := repository.Page{Limit: repository.MaxPageLimit, After: after}
		res, err := s.users.List(ctx, tenantID, page)
		if err != nil {
			return SCIMListResponse{}, err
		}
		allUsers = append(allUsers, res.Items...)
		if res.NextCursor == "" || len(res.Items) == 0 {
			break
		}
		after = res.NextCursor
	}

	allMatching := make([]any, 0, len(allUsers))
	for _, u := range allUsers {
		su := userToSCIM(u)
		if parsed != nil && !parsed.MatchUser(su) {
			continue
		}
		allMatching = append(allMatching, su)
	}

	// Apply RFC 7644 §3.4.2 pagination window.
	totalResults := len(allMatching)
	start := startIndex - 1 // SCIM startIndex is 1-based
	if start > totalResults {
		start = totalResults
	}
	end := start + count
	if end > totalResults {
		end = totalResults
	}
	page := allMatching[start:end]

	return SCIMListResponse{
		Schemas:      []string{SCIMSchemaList},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	}, nil
}

// --- Group operations -----------------------------------------------------

// CreateGroup provisions a SCIM group into the tenant.
func (s *SCIMService) CreateGroup(ctx context.Context, tenantID uuid.UUID, sg SCIMGroup) (SCIMGroup, error) {
	if sg.DisplayName == "" {
		return SCIMGroup{}, fmt.Errorf("displayName is required: %w", repository.ErrInvalidArgument)
	}
	r, err := s.roles.Create(ctx, repository.Role{
		TenantID:    &tenantID,
		Name:        sg.DisplayName,
		ExternalID:  sg.ExternalID,
		Permissions: []string{},
		Scope:       repository.RoleScopeTenant,
	})
	if err != nil {
		return SCIMGroup{}, err
	}
	return roleToSCIMGroup(r), nil
}

// GetGroup returns a SCIM group by ID.
func (s *SCIMService) GetGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID) (SCIMGroup, error) {
	r, err := s.roles.Get(ctx, groupID)
	if err != nil {
		return SCIMGroup{}, err
	}
	if r.TenantID == nil || *r.TenantID != tenantID {
		return SCIMGroup{}, repository.ErrNotFound
	}
	return roleToSCIMGroup(r), nil
}

// UpdateGroup replaces a SCIM group (PUT semantics).
func (s *SCIMService) UpdateGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID, sg SCIMGroup) (SCIMGroup, error) {
	r, err := s.roles.Get(ctx, groupID)
	if err != nil {
		return SCIMGroup{}, err
	}
	if r.TenantID == nil || *r.TenantID != tenantID {
		return SCIMGroup{}, repository.ErrNotFound
	}
	name := sg.DisplayName
	if name == "" {
		name = r.Name
	}
	if name != r.Name || sg.ExternalID != r.ExternalID {
		r, err = s.roles.Update(ctx, groupID, name, sg.ExternalID)
		if err != nil {
			return SCIMGroup{}, err
		}
	}
	return roleToSCIMGroup(r), nil
}

// PatchGroup applies a SCIM PATCH operation to a group.
func (s *SCIMService) PatchGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID, ops []SCIMPatchOp) (SCIMGroup, error) {
	r, err := s.roles.Get(ctx, groupID)
	if err != nil {
		return SCIMGroup{}, err
	}
	if r.TenantID == nil || *r.TenantID != tenantID {
		return SCIMGroup{}, repository.ErrNotFound
	}
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "add":
			if strings.EqualFold(op.Path, "members") {
				members := extractMembers(op.Value)
				for _, m := range members {
					uid := uuidFromString(m.Value)
					if uid == uuid.Nil {
						continue
					}
					if err := s.roles.AssignRole(ctx, repository.UserRole{
						UserID: uid,
						RoleID: groupID,
					}); err != nil && !errors.Is(err, repository.ErrConflict) {
						return SCIMGroup{}, fmt.Errorf("assign member %s: %w", m.Value, err)
					}
				}
			}
		case "remove":
			if strings.EqualFold(op.Path, "members") {
				members := extractMembers(op.Value)
				for _, m := range members {
					uid := uuidFromString(m.Value)
					if uid == uuid.Nil {
						continue
					}
					if err := s.roles.RevokeRole(ctx, uid, groupID, nil); err != nil && !errors.Is(err, repository.ErrNotFound) {
						return SCIMGroup{}, fmt.Errorf("remove member %s: %w", m.Value, err)
					}
				}
			}
		case "replace":
			if strings.EqualFold(op.Path, "displayname") {
				if val, ok := op.Value.(string); ok && val != "" {
					r, err = s.roles.Update(ctx, groupID, val, r.ExternalID)
					if err != nil {
						return SCIMGroup{}, err
					}
				}
			} else if strings.EqualFold(op.Path, "externalid") {
				if val, ok := op.Value.(string); ok {
					r, err = s.roles.Update(ctx, groupID, r.Name, val)
					if err != nil {
						return SCIMGroup{}, err
					}
				}
			}
		}
	}
	return roleToSCIMGroup(r), nil
}

// DeleteGroup removes a SCIM group and all its role assignments.
func (s *SCIMService) DeleteGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID) error {
	r, err := s.roles.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if r.TenantID == nil || *r.TenantID != tenantID {
		return repository.ErrNotFound
	}
	return s.roles.Delete(ctx, groupID)
}

// ListGroups returns a SCIM list response for groups matching the filter.
func (s *SCIMService) ListGroups(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (SCIMListResponse, error) {
	roles, err := s.roles.List(ctx, &tenantID)
	if err != nil {
		return SCIMListResponse{}, err
	}

	var parsed *SCIMFilter
	if filter != "" {
		f, err := ParseSCIMFilter(filter)
		if err != nil {
			return SCIMListResponse{}, fmt.Errorf("invalid filter: %w: %w", err, repository.ErrInvalidArgument)
		}
		parsed = &f
	}

	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = repository.DefaultPageLimit
	}

	allMatching := make([]any, 0, len(roles))
	for _, r := range roles {
		if r.TenantID == nil {
			continue
		}
		sg := roleToSCIMGroup(r)
		if parsed != nil && !parsed.MatchGroup(sg) {
			continue
		}
		allMatching = append(allMatching, sg)
	}

	// Apply RFC 7644 §3.4.2 pagination window.
	totalResults := len(allMatching)
	start := startIndex - 1
	if start > totalResults {
		start = totalResults
	}
	end := start + count
	if end > totalResults {
		end = totalResults
	}
	page := allMatching[start:end]

	return SCIMListResponse{
		Schemas:      []string{SCIMSchemaList},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	}, nil
}

// --- Conversion helpers ---------------------------------------------------

func userToSCIM(u repository.User) SCIMUser {
	active := u.Status == repository.UserStatusActive
	su := SCIMUser{
		Schemas:     []string{SCIMSchemaUser},
		ID:          u.ID.String(),
		ExternalID:  u.ExternalID,
		UserName:    u.Email,
		DisplayName: u.Name,
		Active:      &active,
		Emails: []SCIMEmail{{
			Value:   u.Email,
			Type:    "work",
			Primary: true,
		}},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt.Format(time.RFC3339),
			LastModified: u.UpdatedAt.Format(time.RFC3339),
		},
	}
	return su
}

func roleToSCIMGroup(r repository.Role) SCIMGroup {
	return SCIMGroup{
		Schemas:     []string{SCIMSchemaGroup},
		ID:          r.ID.String(),
		ExternalID:  r.ExternalID,
		DisplayName: r.Name,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Created:      r.CreatedAt.Format(time.RFC3339),
		},
	}
}

// applyUserReplace applies a "replace" (or "add") patch operation to
// a repository User.
func applyUserReplace(u *repository.User, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)
	val, _ := op.Value.(string)
	switch path {
	case "username":
		if val != "" {
			u.Email = val
		}
	case "displayname", "name.formatted":
		if val != "" {
			u.Name = val
		}
	case "externalid":
		u.ExternalID = val
	case "active":
		switch v := op.Value.(type) {
		case bool:
			if v {
				u.Status = repository.UserStatusActive
			} else {
				u.Status = repository.UserStatusSuspended
			}
		case string:
			if strings.EqualFold(v, "true") {
				u.Status = repository.UserStatusActive
			} else {
				u.Status = repository.UserStatusSuspended
			}
		}
	case "emails":
		// replace all emails — use first primary.
		members := extractEmails(op.Value)
		for _, e := range members {
			if e.Primary || len(members) == 1 {
				u.Email = e.Value
				break
			}
		}
	}
}

func applyUserRemove(u *repository.User, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)
	switch path {
	case "externalid":
		u.ExternalID = ""
	}
}

func extractMembers(val any) []SCIMGroupMember {
	switch v := val.(type) {
	case []any:
		out := make([]SCIMGroupMember, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				member := SCIMGroupMember{}
				if s, ok := m["value"].(string); ok {
					member.Value = s
				}
				if s, ok := m["display"].(string); ok {
					member.Display = s
				}
				out = append(out, member)
			}
		}
		return out
	}
	return nil
}

func extractEmails(val any) []SCIMEmail {
	switch v := val.(type) {
	case []any:
		out := make([]SCIMEmail, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				e := SCIMEmail{}
				if s, ok := m["value"].(string); ok {
					e.Value = s
				}
				if s, ok := m["type"].(string); ok {
					e.Type = s
				}
				if b, ok := m["primary"].(bool); ok {
					e.Primary = b
				}
				out = append(out, e)
			}
		}
		return out
	}
	return nil
}
