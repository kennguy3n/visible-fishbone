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
//
// Session 2A: when an iam-core bridge is configured (WithIAMCoreBridge),
// SNG remains the SCIM endpoint but user lifecycle (create / profile
// update / (de)activate / delete) is propagated to the upstream
// iam-core identity store via its Management API. The iam-core user_id
// is persisted on the local user's IDPSubject so subsequent updates
// address the same upstream identity.
type SCIMService struct {
	users   repository.UserRepository
	roles   repository.RoleRepository
	audit   repository.AuditLogRepository
	nowFunc func() time.Time

	// bridge is the optional upstream propagation collaborator. Nil
	// disables propagation (pure local SCIM, unchanged behaviour).
	bridge *iamCoreBridge

	// revoker, when set, receives a revocation when a user is
	// de-provisioned (SCIM DELETE / deactivating PATCH) so the ZTNA
	// enforcement plane drops the user's live sessions immediately
	// rather than waiting for token expiry. Nil keeps the prior
	// behaviour (soft-delete only).
	revoker RevocationPublisher
}

// WithRevocationPublisher wires a RevocationPublisher so user
// de-provisioning pushes a revocation downstream to the ZTNA plane.
func WithRevocationPublisher(r RevocationPublisher) SCIMOption {
	return func(s *SCIMService) { s.revoker = r }
}

// revokeOnDeactivation publishes a ZTNA revocation when a SCIM mutation
// de-provisions a user, so the enforcement plane drops the user's live
// sessions immediately rather than waiting for token expiry. It backs
// all three de-provisioning paths — the active=false PATCH/PUT that Okta
// and Microsoft Entra actually send (they de-provision this way, not by
// issuing a SCIM DELETE) and DeleteUser — each calling it before its
// optional iam-core bridge step. Without it a de-provisioned user keeps
// every live session and grant until its tokens expire.
//
// The decision is driven by the operation's *requested* state, never by
// the prior persisted state. That keeps it retry-safe: if a later step
// (the iam-core bridge sync, or the publish itself) fails and the IdP
// retries, the retried request still asserts active=false and
// re-publishes. The downstream revocation is idempotent, so a duplicate
// is harmless — the property that matters for de-provisioning is that a
// deactivated user can never be stranded with live sessions by a
// transient failure. A reactivation or a profile-only change passes
// deactivating=false and is a no-op, as is the case when no revoker is
// wired.
func (s *SCIMService) revokeOnDeactivation(ctx context.Context, tenantID, userID uuid.UUID, deactivating bool, reason string) error {
	if s.revoker == nil || !deactivating {
		return nil
	}
	if err := s.revoker.PublishRevocation(ctx, tenantID, userID, reason); err != nil {
		return fmt.Errorf("revocation publish failed: %w", err)
	}
	return nil
}

// patchActiveIntent reports the active state a PATCH asserts, if any. It
// returns (value, true) when an op sets the `active` attribute and
// (_, false) when no op touches it, mirroring applyUserReplace's parsing
// (a JSON bool, a string compared case-insensitively to "true", Azure
// AD's path-less {"value":{"active":...}} shape, and core-schema
// URN-qualified paths via canonicalAttr). Basing the revoke decision on
// what the request asserts — rather than on the prior persisted status —
// is what makes deactivation revocation retry-safe, and routing the path
// through canonicalAttr keeps it in lockstep with applyUserReplace so the
// status change and the revocation never disagree.
func patchActiveIntent(ops []SCIMPatchOp) (active bool, set bool) {
	var apply func(op SCIMPatchOp)
	apply = func(op SCIMPatchOp) {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
		default:
			return
		}
		switch canonicalAttr(op.Path) {
		case "":
			if m, ok := op.Value.(map[string]any); ok {
				for k, v := range m {
					apply(SCIMPatchOp{Op: op.Op, Path: k, Value: v})
				}
			}
		case "active":
			switch v := op.Value.(type) {
			case bool:
				active, set = v, true
			case string:
				active, set = strings.EqualFold(v, "true"), true
			}
		}
	}
	for _, op := range ops {
		apply(op)
	}
	return active, set
}

// SCIMOption configures optional SCIMService behaviour without
// breaking the base constructor signature used across the codebase.
type SCIMOption func(*SCIMService)

// NewSCIMService returns a ready-to-use SCIM provisioning service.
func NewSCIMService(
	users repository.UserRepository,
	roles repository.RoleRepository,
	audit repository.AuditLogRepository,
	opts ...SCIMOption,
) *SCIMService {
	s := &SCIMService{
		users:   users,
		roles:   roles,
		audit:   audit,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
	newUser := repository.User{
		Email:      email,
		Name:       displayName,
		ExternalID: su.ExternalID,
		Status:     status,
	}
	// Session 2A: provision (or reuse) the upstream iam-core identity
	// FIRST so its user_id is stored on the local user at creation
	// time. iam-core is the identity store; propagating before the
	// local write means a failure to provision aborts the SCIM create
	// (the IdP retries) instead of leaving a local user with no
	// upstream identity.
	if s.bridge != nil {
		iamUserID, perr := s.bridge.provisionUpstream(ctx, tenantID, newUser, su)
		if perr != nil {
			return SCIMUser{}, fmt.Errorf("iam-core provisioning failed: %w", perr)
		}
		newUser.IDPSubject = iamUserID
	}
	u, err := s.users.Create(ctx, tenantID, newUser)
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
	// A PUT carries the full desired state, so active=false is an
	// explicit de-provision request: cut the user's live ZTNA sessions
	// before the (optional, failable) bridge sync so a bridge failure
	// can't strand them. Driving this off the requested state keeps it
	// retry-safe.
	if rerr := s.revokeOnDeactivation(ctx, tenantID, userID, !active, "scim_user_deactivated"); rerr != nil {
		return SCIMUser{}, rerr
	}
	if s.bridge != nil {
		if serr := s.bridge.syncProfile(ctx, tenantID, updated.IDPSubject, su, active); serr != nil {
			return SCIMUser{}, fmt.Errorf("iam-core sync failed: %w", serr)
		}
	}
	return userToSCIM(updated), nil
}

// PatchUser applies a SCIM PATCH operation (RFC 7644 §3.5.2).
func (s *SCIMService) PatchUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, ops []SCIMPatchOp) (SCIMUser, error) {
	u, err := s.users.Get(ctx, tenantID, userID)
	if err != nil {
		return SCIMUser{}, err
	}
	// A PATCH that asserts active=false is the canonical Okta/Entra
	// de-provision; detecting it from the ops (not the prior persisted
	// status) keeps the resulting revocation retry-safe.
	reqActive, activeSet := patchActiveIntent(ops)
	clearExternalID := false
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace":
			applyUserReplace(&u, op)
		case "add":
			applyUserReplace(&u, op) // add semantics = replace for single-valued
		case "remove":
			if canonicalAttr(op.Path) == "externalid" {
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
	// Cut live ZTNA sessions before the (optional, failable) bridge sync
	// so a bridge failure can't leave a de-provisioned user with active
	// sessions; revoking on the asserted state makes a retried PATCH
	// re-publish rather than silently skip.
	if rerr := s.revokeOnDeactivation(ctx, tenantID, userID, activeSet && !reqActive, "scim_user_deactivated"); rerr != nil {
		return SCIMUser{}, rerr
	}
	nowActive := updated.Status == repository.UserStatusActive
	if s.bridge != nil {
		if serr := s.bridge.syncProfile(ctx, tenantID, updated.IDPSubject, userToSCIM(updated), nowActive); serr != nil {
			return SCIMUser{}, fmt.Errorf("iam-core sync failed: %w", serr)
		}
	}
	return userToSCIM(updated), nil
}

// DeleteUser deactivates a SCIM user (SCIM DELETE = set active=false).
func (s *SCIMService) DeleteUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error {
	// Capture the upstream identity before the local soft-delete so we
	// can propagate the removal to iam-core.
	var iamUserID string
	if s.bridge != nil {
		if existing, gerr := s.users.Get(ctx, tenantID, userID); gerr == nil {
			iamUserID = existing.IDPSubject
		}
	}
	if _, err := s.users.Update(ctx, tenantID, repository.User{
		ID:     userID,
		Status: repository.UserStatusDeleted,
	}); err != nil {
		return err
	}
	// Cut the de-provisioned user's live ZTNA sessions before the
	// optional, failable iam-core bridge delete, mirroring UpdateUser /
	// PatchUser: a bridge failure must not strand a deleted user with
	// active sessions. Retry-safe — a retried DELETE re-publishes and the
	// downstream revocation is idempotent, so a duplicate is harmless.
	if rerr := s.revokeOnDeactivation(ctx, tenantID, userID, true, "scim_user_deleted"); rerr != nil {
		return rerr
	}
	if s.bridge != nil {
		if derr := s.bridge.deleteUpstream(ctx, tenantID, iamUserID); derr != nil {
			return fmt.Errorf("iam-core delete failed: %w", derr)
		}
	}
	return nil
}

// ListUsers returns a SCIM list response for users matching the filter.
func (s *SCIMService) ListUsers(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (SCIMListResponse, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = repository.DefaultPageLimit
	}
	// Cap the client-requested page size to the platform maximum so a
	// caller cannot request an unbounded page (RFC 7644 §3.4.2 permits
	// the server to constrain count); keeps SCIM consistent with the
	// rest of the API's MaxPageLimit ceiling.
	if count > repository.MaxPageLimit {
		count = repository.MaxPageLimit
	}

	var expr filterExpr
	if filter != "" {
		e, err := parseFilterExpr(filter)
		if err != nil {
			return SCIMListResponse{}, fmt.Errorf("invalid filter: %w: %w", err, repository.ErrInvalidArgument)
		}
		expr = e
	}

	// Pushdown fast path: a single eq/co/sw clause on a backed column
	// is resolved by the repository (indexed query + DB-side window +
	// total count), never an in-memory scan. This keeps the standard
	// IdP dedup lookup (`userName eq "x"`) O(1) and a 100K-user tenant
	// from materialising every row to filter+slice it.
	if expr != nil {
		if simple, ok := pushdown(expr); ok {
			return s.listUsersPushdown(ctx, tenantID, &simple, startIndex, count)
		}
	} else {
		return s.listUsersPushdown(ctx, tenantID, nil, startIndex, count)
	}

	// General path: compound / negated / richer-operator filters are
	// evaluated in memory over the tenant's user set. The scan is
	// tenant-scoped and batched through cursor pagination so it never
	// loads another tenant's rows; SME tenants hold a bounded user
	// count, so this stays cheap while remaining RFC 7644 §3.4.2
	// compliant for filters no SQL column can express.
	all, err := s.listAllUsers(ctx, tenantID)
	if err != nil {
		return SCIMListResponse{}, err
	}
	matching := make([]any, 0, len(all))
	for _, u := range all {
		su := userToSCIM(u)
		if expr.matchUser(su) {
			matching = append(matching, su)
		}
	}
	return paginateResources(matching, startIndex, count), nil
}

// listUsersPushdown serves an unfiltered list or a single pushdownable
// clause by delegating to the repository's indexed SearchUsers (and the
// GetByEmail shortcut for the userName-eq dedup lookup).
func (s *SCIMService) listUsersPushdown(ctx context.Context, tenantID uuid.UUID, parsed *SCIMFilter, startIndex, count int) (SCIMListResponse, error) {
	if parsed != nil && parsed.Op == SCIMFilterEq && canonicalAttr(parsed.Attribute) == "username" {
		u, err := s.users.GetByEmail(ctx, tenantID, parsed.Value)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return emptyList(startIndex), nil
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

	searchFilter, matchable := scimUserSearchFilter(parsed)
	if !matchable {
		return emptyList(startIndex), nil
	}
	users, totalResults, err := s.users.SearchUsers(ctx, tenantID, searchFilter, startIndex-1, count)
	if err != nil {
		return SCIMListResponse{}, err
	}
	resources := make([]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, userToSCIM(u))
	}
	return SCIMListResponse{
		Schemas:      []string{SCIMSchemaList},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

// listAllUsers pages the tenant's full user set through the cursor API.
func (s *SCIMService) listAllUsers(ctx context.Context, tenantID uuid.UUID) ([]repository.User, error) {
	var out []repository.User
	cursor := ""
	for {
		page, err := s.users.List(ctx, tenantID, repository.Page{
			After: cursor,
			Limit: repository.MaxPageLimit,
			Order: repository.SortDesc,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

// scimUserSearchFilter translates a parsed SCIM filter into a
// repository.UserSearchFilter for pushdown. The bool reports whether
// any row can match: a nil filter (unfiltered list) and filters on a
// backed attribute (userName/email, displayName, externalId) are always
// matchable. A filter on an unbacked attribute is matchable only when an
// empty field value would satisfy the operator (e.g. `foo eq ""`),
// reproducing the old in-memory matcher's all-or-nothing behaviour
// without scanning the table.
func scimUserSearchFilter(parsed *SCIMFilter) (repository.UserSearchFilter, bool) {
	if parsed == nil {
		return repository.UserSearchFilter{}, true
	}
	op, ok := scimOpToTextMatch(parsed.Op)
	if !ok {
		return repository.UserSearchFilter{}, false
	}
	field, known := scimAttrToUserField(parsed.Attribute)
	if !known {
		if matchOp(parsed.Op, "", parsed.Value) {
			// Degenerates to match-all; an empty Field matches everyone.
			return repository.UserSearchFilter{}, true
		}
		return repository.UserSearchFilter{}, false
	}
	return repository.UserSearchFilter{Field: field, Op: op, Value: parsed.Value}, true
}

// scimAttrToUserField maps a SCIM filter attribute to the user column
// that backs it. It mirrors SCIMFilter.MatchUser: userName and the
// e-mail attributes both resolve to the e-mail column (a user's primary
// e-mail is its userName), displayName to name, externalId to
// external_id. The bool is false for any other attribute.
func scimAttrToUserField(attr string) (repository.UserSearchField, bool) {
	switch canonicalAttr(attr) {
	case "username", "email", "emails.value":
		return repository.UserSearchFieldEmail, true
	case "displayname":
		return repository.UserSearchFieldName, true
	case "externalid":
		return repository.UserSearchFieldExternalID, true
	default:
		return "", false
	}
}

// scimOpToTextMatch maps the SCIM eq/co/sw operators to their repository
// equivalents. ParseSCIMFilter only ever produces these three, so the
// false case is defensive.
func scimOpToTextMatch(op SCIMFilterOp) (repository.TextMatchOp, bool) {
	switch op {
	case SCIMFilterEq:
		return repository.TextMatchEquals, true
	case SCIMFilterCo:
		return repository.TextMatchContains, true
	case SCIMFilterSw:
		return repository.TextMatchPrefix, true
	default:
		return "", false
	}
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
			switch canonicalAttr(op.Path) {
			case "members":
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
			case "displayname":
				// RFC 7644 §3.5.2.1: add on single-valued = set value.
				if val, ok := op.Value.(string); ok && val != "" {
					r, err = s.roles.Update(ctx, groupID, val, r.ExternalID)
					if err != nil {
						return SCIMGroup{}, err
					}
				}
			case "externalid":
				if val, ok := op.Value.(string); ok {
					r, err = s.roles.Update(ctx, groupID, r.Name, val)
					if err != nil {
						return SCIMGroup{}, err
					}
				}
			}
		case "remove":
			if canonicalAttr(op.Path) == "members" {
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
			if canonicalAttr(op.Path) == "displayname" {
				if val, ok := op.Value.(string); ok && val != "" {
					r, err = s.roles.Update(ctx, groupID, val, r.ExternalID)
					if err != nil {
						return SCIMGroup{}, err
					}
				}
			} else if canonicalAttr(op.Path) == "externalid" {
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

	var expr filterExpr
	if filter != "" {
		e, err := parseFilterExpr(filter)
		if err != nil {
			return SCIMListResponse{}, fmt.Errorf("invalid filter: %w: %w", err, repository.ErrInvalidArgument)
		}
		expr = e
	}

	allMatching := make([]any, 0, len(roles))
	for _, r := range roles {
		if r.TenantID == nil {
			continue
		}
		sg := roleToSCIMGroup(r)
		if expr != nil && !expr.matchGroup(sg) {
			continue
		}
		allMatching = append(allMatching, sg)
	}

	return paginateResources(allMatching, startIndex, count), nil
}

// emptyList returns a zero-result SCIM list response anchored at the
// requested start index.
func emptyList(startIndex int) SCIMListResponse {
	if startIndex < 1 {
		startIndex = 1
	}
	return SCIMListResponse{
		Schemas:      []string{SCIMSchemaList},
		TotalResults: 0,
		StartIndex:   startIndex,
		ItemsPerPage: 0,
		Resources:    []any{},
	}
}

// paginateResources applies the RFC 7644 §3.4.2 1-based startIndex /
// count window to an already-filtered resource slice, normalising the
// bounds the same way the list endpoints do.
func paginateResources(all []any, startIndex, count int) SCIMListResponse {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = repository.DefaultPageLimit
	}
	if count > repository.MaxPageLimit {
		count = repository.MaxPageLimit
	}
	totalResults := len(all)
	start := startIndex - 1
	if start > totalResults {
		start = totalResults
	}
	end := start + count
	if end > totalResults {
		end = totalResults
	}
	page := all[start:end]
	return SCIMListResponse{
		Schemas:      []string{SCIMSchemaList},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	}
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
			Version:      scimUserVersion(u),
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
			Version:      scimGroupVersion(r),
		},
	}
}

// applyUserReplace applies a "replace" (or "add") patch operation to
// a repository User. Supports path-less operations (Azure AD pattern)
// where op.Value is a map of attribute-value pairs.
func applyUserReplace(u *repository.User, op SCIMPatchOp) {
	path := canonicalAttr(op.Path)

	// Path-less patch: Azure AD sends {"op":"replace","value":{"active":false}}
	if path == "" {
		m, ok := op.Value.(map[string]any)
		if !ok {
			return
		}
		for k, v := range m {
			applyUserReplace(u, SCIMPatchOp{Op: op.Op, Path: k, Value: v})
		}
		return
	}

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

// applyUserRemove applies a "remove" patch op on a single-valued user
// attribute. externalId is deliberately NOT handled here: clearing it
// requires the dedicated UpdateAndClearExternalID DB path (a plain
// Update preserves the column via COALESCE/NULLIF, so zeroing it only
// in memory would be silently dropped), so PatchUser gates externalId
// removal separately and never routes it here. No other single-valued
// user attribute is removable today; this remains the extension point
// for ones that are clearable through a plain Update.
func applyUserRemove(_ *repository.User, _ SCIMPatchOp) {}

func extractMembers(val any) []SCIMGroupMember {
	v, ok := val.([]any)
	if !ok {
		return nil
	}
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

func extractEmails(val any) []SCIMEmail {
	v, ok := val.([]any)
	if !ok {
		return nil
	}
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
