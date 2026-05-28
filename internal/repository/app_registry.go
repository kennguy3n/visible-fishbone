package repository

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// TrafficClass enumerates the six per-flow steering tiers the
// classification engine emits. Mirrors the CHECK constraint on
// `app_registry.traffic_class` and
// `app_registry_overrides.traffic_class_override`.
//
// See `docs/TRAFFIC_CLASSIFICATION.md` for the full taxonomy.
type TrafficClass string

const (
	// TrafficClassTrustedDirect — DNS + cert-pin + IP-range
	// binding, no proxy, no TLS decrypt.
	TrafficClassTrustedDirect TrafficClass = "trusted_direct"
	// TrafficClassTrustedMediaBypass — same trust guarantees as
	// trusted_direct, telemetry sampled for cost control.
	TrafficClassTrustedMediaBypass TrafficClass = "trusted_media_bypass"
	// TrafficClassInspectLite — DNS verification + URL-category
	// lookup; no TLS decryption.
	TrafficClassInspectLite TrafficClass = "inspect_lite"
	// TrafficClassInspectFull — full SWG with TLS decrypt, AV,
	// IPS, DLP.
	TrafficClassInspectFull TrafficClass = "inspect_full"
	// TrafficClassTunnelPrivate — mTLS overlay to a tenant-private
	// destination (ZTNA, internal LOB).
	TrafficClassTunnelPrivate TrafficClass = "tunnel_private"
	// TrafficClassBlock — connection refused at the earliest
	// enforcement point.
	TrafficClassBlock TrafficClass = "block"
)

// AllTrafficClasses returns every valid traffic class in canonical
// enumeration order. Used by validators and by the per-class output
// shape of the steering compiler.
func AllTrafficClasses() []TrafficClass {
	return []TrafficClass{
		TrafficClassTrustedDirect,
		TrafficClassTrustedMediaBypass,
		TrafficClassInspectLite,
		TrafficClassInspectFull,
		TrafficClassTunnelPrivate,
		TrafficClassBlock,
	}
}

// IsValid reports whether c is a known traffic class.
func (c TrafficClass) IsValid() bool {
	switch c {
	case TrafficClassTrustedDirect,
		TrafficClassTrustedMediaBypass,
		TrafficClassInspectLite,
		TrafficClassInspectFull,
		TrafficClassTunnelPrivate,
		TrafficClassBlock:
		return true
	}
	return false
}

// AppRegistryScope distinguishes globally-applicable apps from
// region-pinned ones. Mirrors the CHECK constraint on
// `app_registry.scope`.
type AppRegistryScope string

const (
	AppRegistryScopeGlobal   AppRegistryScope = "global"
	AppRegistryScopeRegional AppRegistryScope = "regional"
)

// IsValid reports whether s is a known scope.
func (s AppRegistryScope) IsValid() bool {
	switch s {
	case AppRegistryScopeGlobal, AppRegistryScopeRegional:
		return true
	}
	return false
}

// AppRegistry is one row in the curated global app registry.
type AppRegistry struct {
	ID           uuid.UUID
	Name         string
	Vendor       string
	TrafficClass TrafficClass
	Scope        AppRegistryScope
	Regions      []string
	Domains      []string
	IPRanges     []netip.Prefix
	CertPins     []string
	MetadataURL  string
	Category     string
	IsSystem     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AppRegistryFilter narrows AppRegistryRepository.List results.
type AppRegistryFilter struct {
	TrafficClass TrafficClass
	Scope        AppRegistryScope
	Region       string
	Category     string
}

// AppRegistryOverride is one row in the tenant-scoped overrides
// table. Either AppID names a global registry entry, OR
// CustomDomains carries a tenant-local app definition — never both,
// never neither (enforced by a CHECK constraint).
type AppRegistryOverride struct {
	ID                   uuid.UUID
	TenantID             uuid.UUID
	AppID                *uuid.UUID
	CustomDomains        []string
	TrafficClassOverride TrafficClass
	ExpiresAt            *time.Time
	Reason               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// AppRegistryRepository is the persistence boundary for the global
// curated app database. NOT tenant-scoped — every tenant reads the
// same content. Writes are admin-gated at the service / handler
// layer; the repository itself does not enforce role checks.
type AppRegistryRepository interface {
	Create(ctx context.Context, app AppRegistry) (AppRegistry, error)
	Get(ctx context.Context, id uuid.UUID) (AppRegistry, error)
	GetByName(ctx context.Context, name string) (AppRegistry, error)
	Update(ctx context.Context, app AppRegistry) (AppRegistry, error)
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, filter AppRegistryFilter, page Page) (PageResult[AppRegistry], error)
	// ListAll returns every row. Used by the compiler hot path and
	// by tests; production callers must batch via List for large
	// catalogs.
	ListAll(ctx context.Context) ([]AppRegistry, error)
	// ListWithMetadataURL returns rows whose MetadataURL is
	// non-empty. The vendor-sync job iterates these to refresh
	// domain / IP lists from upstream.
	ListWithMetadataURL(ctx context.Context) ([]AppRegistry, error)
}

// AppRegistryOverrideRepository is the tenant-scoped overrides
// table. All operations run inside a transaction that sets the
// `sng.tenant_id` GUC so RLS isolation is enforced for every
// caller.
type AppRegistryOverrideRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, override AppRegistryOverride) (AppRegistryOverride, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (AppRegistryOverride, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[AppRegistryOverride], error)
	// ListAll returns every override for the tenant. Used by the
	// steering-rule compiler and by tests.
	ListAll(ctx context.Context, tenantID uuid.UUID) ([]AppRegistryOverride, error)
	// DeleteExpired removes overrides whose ExpiresAt has passed.
	// Used by the demotion-expiry sweeper; runs under the
	// system-role tx so it can touch every tenant in one pass.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
