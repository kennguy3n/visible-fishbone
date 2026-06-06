package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IAMCoreTenantResolver maps an iam-core `tenant_id` claim (an opaque
// upstream string) onto the local SNG tenant UUID, satisfying
// middleware.TenantResolver so the iam-core auth path can bind the
// Postgres RLS GUC `sng.tenant_id` to the native tenant model.
//
// Mapping convention (deterministic, no extra schema): the iam-core
// tenant_id is resolved against the SNG tenant by, in order,
//
//  1. its UUID — when the claim is the SNG tenant UUID verbatim; then
//  2. its slug — when iam-core is provisioned to emit the SNG tenant
//     slug as the tenant identifier (the recommended convention).
//
// A tenant that is not active (suspended / soft-deleted) is rejected
// fail-closed: an authenticated user must not operate under a tenant
// the platform has disabled. The middleware turns any returned error
// into a 403, so an unmappable or disabled tenant never falls through
// to an unscoped context.
type IAMCoreTenantResolver struct {
	tenants repository.TenantRepository
}

// compile-time check the resolver satisfies the middleware contract.
var _ middleware.TenantResolver = (*IAMCoreTenantResolver)(nil)

// NewIAMCoreTenantResolver constructs the resolver over the tenant
// repository.
func NewIAMCoreTenantResolver(tenants repository.TenantRepository) *IAMCoreTenantResolver {
	return &IAMCoreTenantResolver{tenants: tenants}
}

// ResolveTenant returns the SNG tenant UUID for an iam-core tenant_id.
func (r *IAMCoreTenantResolver) ResolveTenant(ctx context.Context, iamCoreTenantID string) (uuid.UUID, error) {
	id := strings.TrimSpace(iamCoreTenantID)
	if id == "" {
		return uuid.Nil, fmt.Errorf("iam-core tenant_id is empty: %w", repository.ErrInvalidArgument)
	}

	// 1. The claim is the SNG tenant UUID verbatim.
	if parsed, err := uuid.Parse(id); err == nil {
		tn, gerr := r.tenants.Get(ctx, parsed)
		if gerr == nil {
			return r.activeID(tn)
		}
		if !errors.Is(gerr, repository.ErrNotFound) {
			return uuid.Nil, gerr
		}
		// fall through: a well-formed UUID that is not a tenant id may
		// still be a slug (unlikely, but cheap to check).
	}

	// 2. The claim is the SNG tenant slug.
	tn, err := r.tenants.GetBySlug(ctx, id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("no SNG tenant for iam-core tenant_id %q: %w", id, err)
	}
	return r.activeID(tn)
}

// IAMCoreTenantID maps a local SNG tenant UUID back to the iam-core
// tenant identifier — the inverse of ResolveTenant. It returns the
// tenant slug, the canonical iam-core tenant_id under the mapping
// convention documented on the type. The SCIM bridge uses this to
// address the correct upstream tenant when propagating user lifecycle
// changes to the iam-core Management API.
func (r *IAMCoreTenantResolver) IAMCoreTenantID(ctx context.Context, sngTenant uuid.UUID) (string, error) {
	tn, err := r.tenants.Get(ctx, sngTenant)
	if err != nil {
		return "", fmt.Errorf("resolve iam-core tenant_id for SNG tenant %s: %w", sngTenant, err)
	}
	if tn.Slug == "" {
		return "", fmt.Errorf("SNG tenant %s has no slug to map to iam-core: %w", sngTenant, repository.ErrInvalidArgument)
	}
	return tn.Slug, nil
}

// activeID returns the tenant UUID only when the tenant is active,
// rejecting suspended / deleted tenants fail-closed.
func (r *IAMCoreTenantResolver) activeID(tn repository.Tenant) (uuid.UUID, error) {
	if tn.Status != repository.TenantStatusActive {
		return uuid.Nil, fmt.Errorf("SNG tenant %s is %s, not active: %w", tn.ID, tn.Status, repository.ErrForbidden)
	}
	return tn.ID, nil
}
