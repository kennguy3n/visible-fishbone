package residency

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

// CMKResolver returns the key-encryption-key reference configured for a
// tenant. The production implementation reads the tenant record's CMK
// columns; a test supplies a static ref. A zero-Kind ref means the
// tenant has not opted into a customer-managed key, and the CMKService
// transparently falls back to the platform-managed KEK — CMK is opt-in,
// mirroring how data residency is opt-in.
type CMKResolver interface {
	TenantKeyRef(ctx context.Context, tenantID uuid.UUID) (TenantKeyRef, error)
}

// CMKResolverFunc adapts a function to CMKResolver.
type CMKResolverFunc func(ctx context.Context, tenantID uuid.UUID) (TenantKeyRef, error)

// TenantKeyRef implements CMKResolver.
func (f CMKResolverFunc) TenantKeyRef(ctx context.Context, tenantID uuid.UUID) (TenantKeyRef, error) {
	return f(ctx, tenantID)
}

// CMKService is the tier-independent envelope-encryption entry point.
// Every plane that persists regulated tenant data calls it to mint and
// unwrap data-encryption keys, so CMK enforcement is uniform across
// telemetry, policy bundles, cold storage, and RBI artifacts rather
// than special-cased per tier.
//
// On the write path it does three things the raw provider cannot:
//
//  1. Resolves the tenant's KEK ref, falling back to the platform KEK
//     when CMK is not configured.
//  2. Enforces the residency binding fail-closed: a customer-managed
//     key MUST live in the tenant's designated residency region, so
//     key material never leaves the jurisdiction the data is pinned to.
//  3. Binds the tenant id into the encryption context so a DEK wrapped
//     for one tenant can never be unwrapped for another, even on a
//     shared platform KEK.
type CMKService struct {
	refs     CMKResolver
	regions  RegionResolver
	registry *KeyProviderRegistry
	logger   *slog.Logger
}

// NewCMKService constructs a CMKService. refs, regions and registry are
// required; a nil logger defaults to slog.Default().
func NewCMKService(refs CMKResolver, regions RegionResolver, registry *KeyProviderRegistry, logger *slog.Logger) (*CMKService, error) {
	if refs == nil || regions == nil || registry == nil {
		return nil, errors.New("residency: NewCMKService requires refs, regions and registry")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &CMKService{refs: refs, regions: regions, registry: registry, logger: logger}, nil
}

// GenerateDataKey mints a fresh DEK for tenantID under its KEK, with
// the caller's encryption context (plus the enforced tenant binding)
// as AAD. The returned DataKey.Plaintext must be zeroized by the caller
// after use; DataKey.Wrapped is persisted alongside the ciphertext.
//
// Fail-closed throughout: a resolver error, an invalid ref, an
// unregistered provider, or a residency region-binding violation all
// return an error and a zero DataKey — never a usable key under the
// wrong KEK or in the wrong region.
func (s *CMKService) GenerateDataKey(ctx context.Context, tenantID uuid.UUID, ec EncryptionContext) (DataKey, error) {
	ref, provider, boundEC, err := s.resolveForWrite(ctx, tenantID, ec)
	if err != nil {
		return DataKey{}, err
	}
	dk, err := provider.GenerateDataKey(ctx, ref, boundEC)
	if err != nil {
		return DataKey{}, fmt.Errorf("residency: generate data key (tenant %s, %s): %w", tenantID, ref.Kind, err)
	}
	return dk, nil
}

// UnwrapDataKey decrypts a previously wrapped DEK for tenantID. It
// routes to the provider that produced the envelope (wrapped.Kind), not
// the tenant's current KEK, so a DEK stays decryptable after the tenant
// rotates to a different provider/key. The same caller encryption
// context supplied at wrap time must be supplied here.
//
// Region binding is intentionally NOT re-checked on the read path: the
// key already exists, and re-validating residency on read would break
// legitimate decryption of historical data after a residency change.
// Residency is enforced where data and keys are written.
func (s *CMKService) UnwrapDataKey(ctx context.Context, tenantID uuid.UUID, wrapped WrappedDataKey, ec EncryptionContext) ([]byte, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("%w: empty tenant id", ErrInvalidKeyRef)
	}
	provider, err := s.registry.For(wrapped.Kind)
	if err != nil {
		return nil, err
	}
	boundEC, err := s.bindTenant(ec, tenantID)
	if err != nil {
		return nil, err
	}
	// Region is intentionally the zero value here: the read path does
	// not re-bind residency (see the doc comment above), and WrappedDataKey
	// does not persist a region. Cloud KMS adapters must therefore derive
	// any region they need from wrapped.KeyURI (the ARN/resource name/vault
	// host already encodes it) rather than reading ref.Region on unwrap.
	ref := TenantKeyRef{TenantID: tenantID, Kind: wrapped.Kind, KeyURI: wrapped.KeyURI}
	dek, err := provider.UnwrapDataKey(ctx, ref, wrapped, boundEC)
	if err != nil {
		return nil, fmt.Errorf("residency: unwrap data key (tenant %s, %s): %w", tenantID, wrapped.Kind, err)
	}
	return dek, nil
}

// ReWrapDataKey re-seals an existing wrapped DEK for tenantID from
// whatever KEK currently protects it (wrapped.Kind / wrapped.KeyURI)
// onto the explicit target KEK, WITHOUT changing the DEK plaintext.
// This is the envelope primitive a cross-region tenant migration uses:
// the small DEK is re-wrapped under the target region's KEK while the
// (large) ciphertext the DEK protects is copied byte-for-byte, so no
// bulk re-encryption is needed and the data stays decryptable in the
// new region.
//
// The target ref is supplied explicitly by the caller rather than
// resolved, because during a migration the tenant's designated region
// (what the resolver returns) is deliberately still the SOURCE until
// the final region-column flip — so this method does NOT run
// enforceRegionBinding against the resolver. Instead it trusts the
// migration orchestrator to pass the correct target-region KEK and
// validates only that the ref is well-formed (a CMK target must name a
// concrete region+key URI; the platform KEK is region-global). The
// same caller encryption context supplied at wrap time must be supplied
// here so the tenant-bound AAD matches on both unwrap and re-wrap.
//
// Fail-closed: the plaintext DEK is zeroized before return on every
// path, and any unwrap/validate/wrap error returns a zero
// WrappedDataKey.
func (s *CMKService) ReWrapDataKey(ctx context.Context, tenantID uuid.UUID, wrapped WrappedDataKey, target TenantKeyRef, ec EncryptionContext) (WrappedDataKey, error) {
	if tenantID == uuid.Nil {
		return WrappedDataKey{}, fmt.Errorf("%w: empty tenant id", ErrInvalidKeyRef)
	}
	// Unwrap under the KEK that actually produced the envelope. This
	// binds the tenant id into the AAD itself, so a DEK wrapped for one
	// tenant cannot be re-wrapped for another.
	plaintext, err := s.UnwrapDataKey(ctx, tenantID, wrapped, ec)
	if err != nil {
		return WrappedDataKey{}, err
	}
	defer Zeroize(plaintext)

	// The requested tenant is authoritative for the target ref too.
	target.TenantID = tenantID
	if target.Kind == "" {
		target.Kind = ProviderPlatform
	}
	if err := target.Validate(); err != nil {
		return WrappedDataKey{}, err
	}
	target.Region = Normalize(target.Region)
	provider, err := s.registry.For(target.Kind)
	if err != nil {
		return WrappedDataKey{}, err
	}
	boundEC, err := s.bindTenant(ec, tenantID)
	if err != nil {
		return WrappedDataKey{}, err
	}
	rewrapped, err := provider.WrapDataKey(ctx, target, plaintext, boundEC)
	if err != nil {
		return WrappedDataKey{}, fmt.Errorf("residency: re-wrap data key (tenant %s, %s->%s): %w",
			tenantID, wrapped.Kind, target.Kind, err)
	}
	return rewrapped, nil
}

// resolveForWrite resolves the tenant's KEK, enforces the residency
// region binding, selects the provider, and binds the tenant id into
// the encryption context.
func (s *CMKService) resolveForWrite(ctx context.Context, tenantID uuid.UUID, ec EncryptionContext) (TenantKeyRef, TenantKeyProvider, EncryptionContext, error) {
	if tenantID == uuid.Nil {
		return TenantKeyRef{}, nil, nil, fmt.Errorf("%w: empty tenant id", ErrInvalidKeyRef)
	}
	ref, err := s.refs.TenantKeyRef(ctx, tenantID)
	if err != nil {
		// Fail-closed: if we cannot determine the tenant's KEK, we do
		// not silently fall back to plaintext or the platform key.
		return TenantKeyRef{}, nil, nil, fmt.Errorf("residency: resolve tenant key ref: %w", err)
	}
	// The requested tenant is authoritative — never trust a resolver
	// that returns a ref bound to a different tenant.
	ref.TenantID = tenantID
	if ref.Kind == "" {
		ref.Kind = ProviderPlatform
	}
	if err := ref.Validate(); err != nil {
		return TenantKeyRef{}, nil, nil, err
	}
	// Validate() only reads Region (it normalizes internally for its
	// regex check without mutating the value receiver). Canonicalize it
	// once here so the region the provider sees and the CMKService logs
	// is the same normalized form the binding check compares against,
	// rather than whatever case/whitespace the resolver returned.
	ref.Region = Normalize(ref.Region)
	if err := s.enforceRegionBinding(ctx, tenantID, ref); err != nil {
		return TenantKeyRef{}, nil, nil, err
	}
	provider, err := s.registry.For(ref.Kind)
	if err != nil {
		return TenantKeyRef{}, nil, nil, err
	}
	boundEC, err := s.bindTenant(ec, tenantID)
	if err != nil {
		return TenantKeyRef{}, nil, nil, err
	}
	return ref, provider, boundEC, nil
}

// enforceRegionBinding rejects a customer-managed key that does not
// live in the tenant's designated residency region. The platform KEK
// is exempt: it is a control-plane-global key, not tenant data pinned
// to a jurisdiction, so it is not residency-bound (the data it
// protects still is, via the data-plane residency Guard).
func (s *CMKService) enforceRegionBinding(ctx context.Context, tenantID uuid.UUID, ref TenantKeyRef) error {
	if !ref.IsCMK() {
		return nil
	}
	designated, err := s.regions.DesignatedRegion(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("residency: resolve designated region for key binding: %w", err)
	}
	if Normalize(designated) == "" {
		// Tenant has no residency designation: a CMK is allowed in any
		// region it is configured in (residency is opt-in). The data
		// is likewise unconstrained.
		return nil
	}
	if verr := EnforceWrite(designated, ref.Region, PlaneKeyManagement); verr != nil {
		s.logger.WarnContext(ctx, "residency: CMK region-binding rejected",
			"tenant_id", tenantID,
			"provider", ref.Kind,
			"designated_region", Normalize(designated),
			"key_region", Normalize(ref.Region),
			"error", verr)
		return verr
	}
	return nil
}

// bindTenant clones the caller's encryption context and stamps the
// authoritative tenant id into it. A caller that pre-set the reserved
// tenant_id key to a different value is rejected fail-closed — it is a
// programming error that, left unchecked, would let a wrap/unwrap cross
// a tenant boundary.
func (s *CMKService) bindTenant(ec EncryptionContext, tenantID uuid.UUID) (EncryptionContext, error) {
	out := ec.clone()
	if existing, ok := out[ContextTenantID]; ok && existing != tenantID.String() {
		return nil, fmt.Errorf("%w: encryption context %q=%q conflicts with tenant %s",
			ErrInvalidKeyRef, ContextTenantID, existing, tenantID)
	}
	out[ContextTenantID] = tenantID.String()
	return out, nil
}

// Compile-time assertion that LocalKeyProvider satisfies the provider
// interface.
var _ TenantKeyProvider = (*LocalKeyProvider)(nil)
