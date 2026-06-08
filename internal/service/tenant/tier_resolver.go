package tenant

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TierResolver looks up a tenant's billing tier so the per-tenant
// rate-limit middleware can pick the matching request budget. It
// satisfies middleware.TenantTierResolver.
//
// The middleware caches each tenant's tier on its token bucket and
// only re-resolves at its configured TierTTL, so this lookup runs once
// per tenant per TTL window rather than on every request — a single
// Get against the tenants table (the same lightweight read the
// iam-core tenant resolver already performs in the auth path).
type TierResolver struct {
	tenants repository.TenantRepository
}

// compile-time check the resolver satisfies the middleware contract.
var _ middleware.TenantTierResolver = (*TierResolver)(nil)

// NewTierResolver constructs the resolver over the tenant repository.
func NewTierResolver(tenants repository.TenantRepository) *TierResolver {
	return &TierResolver{tenants: tenants}
}

// ResolveTier returns the tenant's current tier. An error is returned
// verbatim; the middleware treats any error as "tier unknown" and
// falls back to the standard (lowest) budget, so a transient lookup
// failure can never grant a tenant a larger budget than it is owed.
func (r *TierResolver) ResolveTier(ctx context.Context, tenantID uuid.UUID) (repository.TenantTier, error) {
	tn, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return tn.Tier, nil
}
