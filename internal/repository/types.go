// Package repository defines the persistence interface for the
// ShieldNet Gateway control plane and the value types it returns.
//
// Two implementations live under sibling packages:
//
//   - `repository/postgres` — production driver backed by pgxpool.
//   - `repository/memory`   — thread-safe in-memory driver used for
//     unit tests of services that depend on the repositories.
//
// Both implementations satisfy the same interfaces declared in
// `interfaces.go`, so services can be unit-tested against the
// memory driver and integration-tested against Postgres without
// changing wiring beyond a constructor swap.
package repository

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TenantStatus enumerates the lifecycle stages of a tenant. Mirrors
// the CHECK constraint on `tenants.status`.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// TenantTier enumerates billing tiers. Mirrors the CHECK constraint
// on `tenants.tier`.
type TenantTier string

const (
	TenantTierStarter      TenantTier = "starter"
	TenantTierProfessional TenantTier = "professional"
	TenantTierEnterprise   TenantTier = "enterprise"
)

// Tenant is the top-level multi-tenancy entity.
type Tenant struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	Status    TenantStatus
	Region    string
	Tier      TenantTier
	Settings  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// SiteTemplate enumerates the supported site enforcement templates.
// Mirrors the CHECK constraint on `sites.template`.
type SiteTemplate string

const (
	SiteTemplateBranch     SiteTemplate = "branch"
	SiteTemplateHub        SiteTemplate = "hub"
	SiteTemplateCloudOnly  SiteTemplate = "cloud_only"
	SiteTemplateHomeOffice SiteTemplate = "home_office"
)

// Site is an enforcement scope owned by a tenant.
type Site struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Name      string
	Slug      string
	Template  SiteTemplate
	Config    json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserStatus enumerates lifecycle states for a user identity.
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

// User is an authenticatable identity inside a tenant.
type User struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Email      string
	Name       string
	ExternalID string
	IDPSubject string
	Status     UserStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// RoleScope enumerates the abstract scope a role can be granted at.
// `platform` and `msp` roles are system roles (tenant_id IS NULL)
// shared across tenants; `tenant` and `site` roles are tenant-owned.
type RoleScope string

const (
	RoleScopePlatform RoleScope = "platform"
	RoleScopeMSP      RoleScope = "msp"
	RoleScopeTenant   RoleScope = "tenant"
	RoleScopeSite     RoleScope = "site"
)

// Role represents a named permission set. Permissions are stored as
// a JSON array of strings (e.g. `["tenants:write", "devices:read"]`).
type Role struct {
	ID          uuid.UUID
	TenantID    *uuid.UUID // nil for system roles
	Name        string
	Permissions []string
	Scope       RoleScope
	CreatedAt   time.Time
}

// UserRole binds a user to a role, optionally narrowed to a scope_id
// (e.g. a site UUID for site-scoped roles).
type UserRole struct {
	UserID    uuid.UUID
	RoleID    uuid.UUID
	ScopeID   *uuid.UUID
	GrantedAt time.Time
	GrantedBy *uuid.UUID
}

// DevicePlatform enumerates the supported endpoint platforms.
// Mirrors the CHECK constraint on `devices.platform`.
type DevicePlatform string

const (
	DevicePlatformWindows DevicePlatform = "windows"
	DevicePlatformMacOS   DevicePlatform = "macos"
	DevicePlatformLinux   DevicePlatform = "linux"
	DevicePlatformIOS     DevicePlatform = "ios"
	DevicePlatformAndroid DevicePlatform = "android"
)

// IsMobile reports whether the platform is one of the mobile OSes
// (ios/android). The mobile platforms have different posture
// schemas and a separate compiled-policy bundle target type.
func (p DevicePlatform) IsMobile() bool {
	return p == DevicePlatformIOS || p == DevicePlatformAndroid
}

// DeviceStatus enumerates the lifecycle stages of a device.
type DeviceStatus string

const (
	DeviceStatusPending   DeviceStatus = "pending"
	DeviceStatusActive    DeviceStatus = "active"
	DeviceStatusSuspended DeviceStatus = "suspended"
	DeviceStatusDeleted   DeviceStatus = "deleted"
)

// Posture is a structured device-health snapshot covering both
// desktop and mobile signals. Stored as JSON on devices.posture.
// Fields are deliberately optional (`omitempty`) so older agents
// missing newer fields, and mobile agents missing desktop-only
// fields, still serialize cleanly.
type Posture struct {
	// Common.
	OSVersion    string     `json:"os_version,omitempty"`
	AgentVersion string     `json:"agent_version,omitempty"`
	CollectedAt  *time.Time `json:"collected_at,omitempty"`

	// Desktop / general signals.
	DiskEncrypted   *bool  `json:"disk_encrypted,omitempty"`
	FirewallEnabled *bool  `json:"firewall_enabled,omitempty"`
	ScreenLock      *bool  `json:"screen_lock,omitempty"`
	PatchLevel      string `json:"patch_level,omitempty"`

	// Mobile-specific signals (only meaningful on ios/android).
	PasscodeSet    *bool `json:"passcode_set,omitempty"`
	Jailbroken     *bool `json:"jailbroken,omitempty"`    // iOS
	RootDetected   *bool `json:"root_detected,omitempty"` // Android
	BiometricReady *bool `json:"biometric_ready,omitempty"`
	MDMEnrolled    *bool `json:"mdm_enrolled,omitempty"`

	// Free-form additional metadata for future signals. Kept
	// open so agents can report new posture facts without a
	// migration round-trip.
	Extra json.RawMessage `json:"extra,omitempty"`
}

// Device is an enrolled endpoint.
type Device struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	SiteID           *uuid.UUID
	Name             string
	Platform         DevicePlatform
	PublicKeyEd25519 string
	EnrolledAt       *time.Time
	LastSeenAt       *time.Time
	Status           DeviceStatus
	Posture          Posture
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ClaimToken is a short-lived one-time enrollment credential. Only
// the SHA-256 hash of the plaintext is persisted; callers receive
// the plaintext exactly once at create-time.
type ClaimToken struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	TokenHash  []byte
	ExpiresAt  time.Time
	RedeemedAt *time.Time
	CreatedBy  *uuid.UUID
	CreatedAt  time.Time
}

// AuditEntry is an append-only audit-log record.
type AuditEntry struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	ActorID      *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Details      json.RawMessage
	CreatedAt    time.Time
}

// PolicyGraph is a versioned tenant policy graph. The `Graph` blob
// is the JSON-serialized typed policy model (see internal/service/
// policy for the shape).
type PolicyGraph struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	Version         int
	Graph           json.RawMessage
	CompiledAt      *time.Time
	CompilerVersion string
	CreatedAt       time.Time
}

// PolicyBundleTarget enumerates the supported enforcement targets a
// compiled bundle can be emitted for. Mirrors the CHECK constraint
// on `policy_bundles.target_type`.
type PolicyBundleTarget string

const (
	PolicyBundleTargetEdge     PolicyBundleTarget = "edge"
	PolicyBundleTargetEndpoint PolicyBundleTarget = "endpoint"
	PolicyBundleTargetCloud    PolicyBundleTarget = "cloud"
	PolicyBundleTargetMobile   PolicyBundleTarget = "mobile"
)

// PolicyBundle is a compiled, signed bundle. The `Bundle` payload is
// MessagePack-encoded rules (see internal/service/policy). The
// `Signature` is an Ed25519 signature over the bundle bytes.
type PolicyBundle struct {
	ID            uuid.UUID
	PolicyGraphID uuid.UUID
	TargetType    PolicyBundleTarget
	Bundle        []byte
	Signature     []byte
	CreatedAt     time.Time
}
