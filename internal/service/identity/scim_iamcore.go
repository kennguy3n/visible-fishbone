package identity

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IdentityProvisioner propagates SCIM user lifecycle operations to the
// upstream iam-core identity store via its Management API. It is
// satisfied by *iamcore.Client; the interface keeps the SCIM bridge
// unit-testable with a fake provider.
//
// Every method takes the iam-core tenant_id (the Management API's
// X-Tenant-ID routing value), which the bridge derives from the SNG
// tenant via an IAMCoreTenantMapper.
type IdentityProvisioner interface {
	FindUserByEmail(ctx context.Context, iamTenantID, email string) (iamcore.ManagementUser, bool, error)
	CreateUser(ctx context.Context, iamTenantID string, in iamcore.CreateManagementUser) (iamcore.ManagementUser, error)
	UpdateUser(ctx context.Context, iamTenantID, userID string, in iamcore.UpdateManagementUser) (iamcore.ManagementUser, error)
	BlockUser(ctx context.Context, iamTenantID, userID string) error
	UnblockUser(ctx context.Context, iamTenantID, userID string) error
	DeleteUser(ctx context.Context, iamTenantID, userID string) error
}

// IAMCoreTenantMapper resolves the iam-core tenant_id for a SNG tenant
// UUID. The Management API is tenant-scoped, so every propagated call
// must carry the upstream tenant identifier.
type IAMCoreTenantMapper interface {
	IAMCoreTenantID(ctx context.Context, sngTenant uuid.UUID) (string, error)
}

// Compile-time guarantee that the real iam-core client satisfies the
// provisioner contract the SCIM bridge depends on.
var _ IdentityProvisioner = (*iamcore.Client)(nil)

// iamCoreBridge bundles the provisioner and tenant mapper.
type iamCoreBridge struct {
	prov   IdentityProvisioner
	tenant IAMCoreTenantMapper
}

// WithIAMCoreBridge wires SCIM user lifecycle propagation to iam-core.
// Omit it and the SCIM service behaves exactly as before (local only).
func WithIAMCoreBridge(prov IdentityProvisioner, tenant IAMCoreTenantMapper) SCIMOption {
	return func(s *SCIMService) {
		if prov == nil || tenant == nil {
			return
		}
		s.bridge = &iamCoreBridge{prov: prov, tenant: tenant}
	}
}

// provisionUpstream creates (or reuses) the iam-core identity for a
// freshly created SCIM user and returns the iam-core user_id to store
// on the local user. It is idempotent: an existing iam-core user with
// the same email is reused rather than duplicated (IdPs frequently
// retry create on transient errors).
func (b *iamCoreBridge) provisionUpstream(ctx context.Context, sngTenant uuid.UUID, u repository.User, su SCIMUser) (string, error) {
	iamTenant, err := b.tenant.IAMCoreTenantID(ctx, sngTenant)
	if err != nil {
		return "", fmt.Errorf("resolve iam-core tenant: %w", err)
	}
	existing, found, ferr := b.prov.FindUserByEmail(ctx, iamTenant, u.Email)
	if ferr != nil {
		// A transient lookup failure (network blip, iam-core 5xx) must
		// NOT fall through to CreateUser: if the identity already exists
		// upstream, creating again risks a duplicate iam-core user that
		// no longer round-trips with this email. Fail closed so the SCIM
		// operation can be retried idempotently once the lookup recovers.
		return "", fmt.Errorf("lookup iam-core user by email: %w", ferr)
	}
	if found {
		return existing.UserID, nil
	}
	created, err := b.prov.CreateUser(ctx, iamTenant, iamcore.CreateManagementUser{
		Email:      u.Email,
		Name:       u.Name,
		GivenName:  su.Name.GivenName,
		FamilyName: su.Name.FamilyName,
	})
	if err != nil {
		return "", fmt.Errorf("create iam-core user: %w", err)
	}
	return created.UserID, nil
}

// syncProfile propagates a profile/status change to iam-core. userID
// is the iam-core user_id (the local user's IDPSubject); when empty
// the user was never provisioned upstream and the call is a no-op.
func (b *iamCoreBridge) syncProfile(ctx context.Context, sngTenant uuid.UUID, userID string, su SCIMUser, active bool) error {
	if userID == "" {
		return nil
	}
	iamTenant, err := b.tenant.IAMCoreTenantID(ctx, sngTenant)
	if err != nil {
		return fmt.Errorf("resolve iam-core tenant: %w", err)
	}
	name := su.DisplayName
	given := su.Name.GivenName
	family := su.Name.FamilyName
	if _, err := b.prov.UpdateUser(ctx, iamTenant, userID, iamcore.UpdateManagementUser{
		Name:       strPtrOrNil(name),
		GivenName:  strPtrOrNil(given),
		FamilyName: strPtrOrNil(family),
	}); err != nil {
		return fmt.Errorf("update iam-core user: %w", err)
	}
	// Mirror the SCIM active flag onto iam-core's block state. This is
	// applied unconditionally (no "only if changed" guard) on purpose: it
	// is an idempotent reconciliation to the desired state, so it also
	// self-heals any drift where iam-core's block state diverged from SNG
	// (e.g. an out-of-band block in the iam-core console). The block /
	// unblock endpoints are idempotent, so the cost is at most one extra
	// Management call per SCIM update — cheaper and safer than trusting a
	// possibly-stale local mirror of iam-core's block state.
	if active {
		if err := b.prov.UnblockUser(ctx, iamTenant, userID); err != nil {
			return fmt.Errorf("unblock iam-core user: %w", err)
		}
	} else {
		if err := b.prov.BlockUser(ctx, iamTenant, userID); err != nil {
			return fmt.Errorf("block iam-core user: %w", err)
		}
	}
	return nil
}

// deleteUpstream removes the iam-core identity. A 404 is treated as
// success (the identity is already gone — idempotent delete).
func (b *iamCoreBridge) deleteUpstream(ctx context.Context, sngTenant uuid.UUID, userID string) error {
	if userID == "" {
		return nil
	}
	iamTenant, err := b.tenant.IAMCoreTenantID(ctx, sngTenant)
	if err != nil {
		return fmt.Errorf("resolve iam-core tenant: %w", err)
	}
	if err := b.prov.DeleteUser(ctx, iamTenant, userID); err != nil {
		if iamcore.StatusCode(err) == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("delete iam-core user: %w", err)
	}
	return nil
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
