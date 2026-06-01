package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultBranding is the platform-wide branding fallback. Returned
// fields are intentionally generic — operators are expected to
// override at either the MSP or tenant level.
var DefaultBranding = repository.MSPBranding{
	LogoURL:         "/assets/sng-logo.svg",
	PrimaryColor:    "#0E1F3A",
	SecondaryColor:  "#1FB6FF",
	CustomDomain:    "",
	PortalSupportTo: "support@example.com",
}

// BrandingResolver computes the effective branding for a tenant
// by walking the resolution chain tenant override > MSP default >
// platform default. Per-field — not whole-record — overrides:
// a tenant that only sets PrimaryColor inherits LogoURL etc from
// the MSP layer.
//
// The resolver does NOT cache. Each Resolve call hits the tenant
// + msp repositories. Callers serving high-traffic UI surfaces
// should cache the resolved branding for the request lifetime.
type BrandingResolver struct {
	tenants repository.TenantRepository
	msps    repository.MSPRepository
}

// NewBrandingResolver returns a ready-to-use resolver.
func NewBrandingResolver(tenants repository.TenantRepository, msps repository.MSPRepository) *BrandingResolver {
	return &BrandingResolver{tenants: tenants, msps: msps}
}

// tenantBrandingSettings is the shape of the optional
// `branding` key inside tenants.settings JSONB. Tenants without
// any override leave the key absent; the resolver treats absence
// the same as an empty-fields struct (every field falls through
// to the next layer).
type tenantBrandingSettings struct {
	Branding *repository.MSPBranding `json:"branding,omitempty"`
}

// Resolve returns the effective branding for a tenant. The
// returned struct has every field populated — either from the
// tenant override, the MSP default, or DefaultBranding.
//
// Lookup order:
//  1. tenant.settings.branding (per-field override)
//  2. msp.branding (only consulted when the tenant has an
//     msp_id pointer — i.e. an MSP owner binding)
//  3. DefaultBranding (platform fallback)
//
// Returns ErrNotFound if the tenant does not exist.
func (r *BrandingResolver) Resolve(ctx context.Context, tenantID uuid.UUID) (repository.MSPBranding, error) {
	if tenantID == uuid.Nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: %w", repository.ErrInvalidArgument)
	}
	tn, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: get tenant: %w", err)
	}
	return r.ResolveForTenant(ctx, tn)
}

// ResolveForTenant computes the effective branding starting from
// an already-fetched tenant row. Callers that have just performed
// a tenant write (e.g. setBranding's SetTenantBranding) avoid the
// duplicate Get the all-in-one Resolve would otherwise issue.
//
// Layered identically to Resolve:
//  1. Tenant override (per-field) — already on the supplied tn.
//  2. MSP default — fetched only when tn.MSPID is non-nil.
//  3. Platform DefaultBranding fallback.
//
// ErrNotFound on the MSP fetch is tolerated (dangling MSPID) so a
// soft-deleted MSP cannot break branding resolution for tenants
// whose denormalised pointer was not cleared.
func (r *BrandingResolver) ResolveForTenant(ctx context.Context, tn repository.Tenant) (repository.MSPBranding, error) {
	out := DefaultBranding

	// Layer 2: MSP default, if the tenant has an owner MSP. A
	// nil MSPID means the tenant is unmanaged (direct platform
	// customer) — skip the layer.
	if tn.MSPID != nil {
		msp, err := r.msps.Get(ctx, *tn.MSPID)
		if err != nil {
			// A dangling MSPID (e.g. the MSP was soft-deleted
			// and the denormalised pointer was not cleared)
			// must not break branding resolution. Log via the
			// returned error path but allow the resolver to
			// fall through to the platform default.
			if !errors.Is(err, repository.ErrNotFound) {
				return repository.MSPBranding{}, fmt.Errorf("branding resolve: get msp: %w", err)
			}
		} else {
			out = mergeBranding(out, msp.Branding)
		}
	}

	// Layer 1: tenant.settings.branding (per-field override).
	override, err := extractTenantBranding(tn.Settings)
	if err != nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: decode tenant settings: %w", err)
	}
	if override != nil {
		out = mergeBranding(out, *override)
	}

	return out, nil
}

// extractTenantBranding pulls the optional `branding` key out of
// the tenants.settings JSONB. Returns nil if settings is empty,
// the key is absent, or settings is a JSON `null`.
//
// A separate decode (rather than promoting branding to a typed
// column) is intentional: settings is a free-form JSONB used by
// multiple subsystems, and migration 015 stops short of carving
// out a typed `tenants.branding` column. The per-tenant override
// only needs a thin marshal/unmarshal.
func extractTenantBranding(settings json.RawMessage) (*repository.MSPBranding, error) {
	if len(settings) == 0 || string(settings) == "null" {
		return nil, nil
	}
	var s tenantBrandingSettings
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	return s.Branding, nil
}

// mergeBranding overlays `override` onto `base` per field. Empty
// strings in `override` leave the corresponding `base` field
// untouched, which is what gives us the per-field semantics: a
// tenant override that only sets `primary_color` inherits the
// remaining fields from the lower layer (MSP or platform default).
func mergeBranding(base, override repository.MSPBranding) repository.MSPBranding {
	out := base
	if override.LogoURL != "" {
		out.LogoURL = override.LogoURL
	}
	if override.PrimaryColor != "" {
		out.PrimaryColor = override.PrimaryColor
	}
	if override.SecondaryColor != "" {
		out.SecondaryColor = override.SecondaryColor
	}
	if override.CustomDomain != "" {
		out.CustomDomain = override.CustomDomain
	}
	if override.PortalSupportTo != "" {
		out.PortalSupportTo = override.PortalSupportTo
	}
	return out
}

// SetTenantBranding writes the per-field branding override into
// tenants.settings.branding. Empty fields in `override` are kept
// in the persisted JSON exactly as supplied — they are NOT
// canonicalised to absent — so the round-trip preserves the
// caller's intent (e.g. an operator deliberately blanks the
// custom domain).
//
// The settings JSON is read-modify-written: any other keys (e.g.
// feature flags belonging to other subsystems) are preserved.
func (r *BrandingResolver) SetTenantBranding(
	ctx context.Context,
	tenantID uuid.UUID,
	override repository.MSPBranding,
) (repository.Tenant, error) {
	if tenantID == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: %w", repository.ErrInvalidArgument)
	}
	tn, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: get tenant: %w", err)
	}
	// RMW the settings JSON. Start from a generic map so unknown
	// keys (other subsystems) are preserved verbatim across the
	// update.
	var settings map[string]json.RawMessage
	if len(tn.Settings) > 0 && string(tn.Settings) != "null" {
		if err := json.Unmarshal(tn.Settings, &settings); err != nil {
			return repository.Tenant{}, fmt.Errorf("set tenant branding: decode existing settings: %w", err)
		}
	}
	if settings == nil {
		settings = map[string]json.RawMessage{}
	}
	encoded, err := json.Marshal(override)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: encode override: %w", err)
	}
	settings["branding"] = encoded
	newSettings, err := json.Marshal(settings)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: encode settings: %w", err)
	}
	updated, err := r.tenants.Update(ctx, tenantID, repository.TenantPatch{
		Settings: (*json.RawMessage)(&newSettings),
	})
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: update tenant: %w", err)
	}
	return updated, nil
}

// ClearTenantBranding removes the `branding` key from
// tenants.settings, restoring full inheritance from the MSP
// (or platform) default. Other settings keys are preserved.
func (r *BrandingResolver) ClearTenantBranding(ctx context.Context, tenantID uuid.UUID) (repository.Tenant, error) {
	if tenantID == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: %w", repository.ErrInvalidArgument)
	}
	tn, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: get tenant: %w", err)
	}
	if len(tn.Settings) == 0 || string(tn.Settings) == "null" {
		// No settings → nothing to clear; return the tenant
		// unchanged.
		return tn, nil
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(tn.Settings, &settings); err != nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: decode settings: %w", err)
	}
	if _, ok := settings["branding"]; !ok {
		return tn, nil
	}
	delete(settings, "branding")
	newSettings, err := json.Marshal(settings)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: encode settings: %w", err)
	}
	updated, err := r.tenants.Update(ctx, tenantID, repository.TenantPatch{
		Settings: (*json.RawMessage)(&newSettings),
	})
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: update tenant: %w", err)
	}
	return updated, nil
}
