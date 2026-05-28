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

// TenantPatch is the input to TenantRepository.Update. Each field
// is a pointer so the caller can distinguish three states per
// field:
//
//   - nil               — caller did not touch this field; the
//     stored value is preserved as-is.
//   - non-nil, zero     — caller wants the field cleared (Region
//     to empty string, Settings to empty JSON, etc.). This is
//     the case the previous "Update(Tenant)" signature could not
//     express: an empty `Tenant.Region` was ambiguous between
//     "absent" and "clear", and was always interpreted as
//     "absent", so once an operator set a Region they could only
//     ever change it, never remove it.
//   - non-nil, non-zero — caller wants the field set to that
//     value.
//
// Fields that are never legitimately empty (Name, Slug, Status,
// Tier) keep a string/enum payload because clearing them would
// move the row into an invalid state the service-layer Create
// validation already rejects. They use the historical
// "absent = nil pointer" sparse-PATCH convention for symmetry
// with the optional fields below.
type TenantPatch struct {
	Name     *string
	Slug     *string
	Status   *TenantStatus
	Region   *string
	Tier     *TenantTier
	Settings *json.RawMessage
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

// WebhookEndpointStatus enumerates the lifecycle states.
type WebhookEndpointStatus string

const (
	WebhookEndpointStatusActive   WebhookEndpointStatus = "active"
	WebhookEndpointStatusDisabled WebhookEndpointStatus = "disabled"
)

// WebhookEndpoint is a per-tenant webhook subscription.
type WebhookEndpoint struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	URL      string
	Events   []string
	// SigningSecret is the plaintext HMAC-SHA256 key used by the
	// delivery worker to sign outbound bodies. Receivers verify
	// signatures with this same value, which is emitted exactly
	// once on Create. At-rest protection is delegated to disk
	// encryption / TDE per the migration comment.
	SigningSecret []byte
	Status        WebhookEndpointStatus
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// WebhookDeliveryStatus enumerates delivery attempt states.
type WebhookDeliveryStatus string

const (
	WebhookDeliveryStatusPending WebhookDeliveryStatus = "pending"
	// WebhookDeliveryStatusProcessing is the exclusive-ownership
	// state a delivery transitions into when a worker claims it via
	// ListPending. While in this state no other worker will pick
	// the row up — both via the atomic-claim UPDATE in the postgres
	// repo and via the equivalent in-memory transition in the
	// memory repo. On worker crash the row stays in 'processing'
	// until ListPending's stuck-row reaper window elapses, at
	// which point it is re-claimed by another worker. See
	// migrations/003_webhook_processing.up.sql for the database
	// schema rationale.
	WebhookDeliveryStatusProcessing WebhookDeliveryStatus = "processing"
	WebhookDeliveryStatusDelivered  WebhookDeliveryStatus = "delivered"
	WebhookDeliveryStatusFailed     WebhookDeliveryStatus = "failed"
	WebhookDeliveryStatusExhausted  WebhookDeliveryStatus = "exhausted"
)

// WebhookDelivery is a single delivery attempt record.
type WebhookDelivery struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	EndpointID     uuid.UUID
	EventType      string
	Payload        json.RawMessage
	Status         WebhookDeliveryStatus
	Attempts       int
	LastAttemptAt  *time.Time
	LastError      string
	NextRetryAt    time.Time
	ResponseStatus int
	CreatedAt      time.Time
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
// `Signature` is an Ed25519 signature over the bundle bytes; `KeyID`
// names the tenant signing key whose public half verifies it.
type PolicyBundle struct {
	ID            uuid.UUID
	PolicyGraphID uuid.UUID
	TargetType    PolicyBundleTarget
	Bundle        []byte
	Signature     []byte
	KeyID         string
	CreatedAt     time.Time
}

// PolicySigningKeyStatus enumerates the lifecycle states of a
// tenant-scoped Ed25519 signing key. Mirrors the CHECK constraint on
// `policy_signing_keys.status`.
type PolicySigningKeyStatus string

const (
	// PolicySigningKeyStatusActive is the current signing key.
	// Exactly one key per tenant is in this state (enforced by a
	// partial unique index).
	PolicySigningKeyStatusActive PolicySigningKeyStatus = "active"
	// PolicySigningKeyStatusRotated is a previously-active key
	// retained so receivers can still verify bundles signed before
	// the rotation.
	PolicySigningKeyStatusRotated PolicySigningKeyStatus = "rotated"
	// PolicySigningKeyStatusRevoked is a compromised or
	// administratively-disabled key. Receivers MUST refuse
	// bundles signed by a revoked key even within their original
	// validity window.
	PolicySigningKeyStatusRevoked PolicySigningKeyStatus = "revoked"
)

// TenantAPIKeyStatus enumerates the lifecycle states of a
// tenant-scoped API key. Mirrors the CHECK constraint on
// `tenant_api_keys.status`.
type TenantAPIKeyStatus string

const (
	// TenantAPIKeyStatusActive is a key that may authenticate
	// requests (subject to ExpiresAt).
	TenantAPIKeyStatusActive TenantAPIKeyStatus = "active"
	// TenantAPIKeyStatusRevoked is a key the operator has
	// permanently disabled. Revocation is one-way; minting a new
	// key is the only way to restore access.
	TenantAPIKeyStatusRevoked TenantAPIKeyStatus = "revoked"
)

// TenantAPIKey is one row in the tenant_api_keys table.
//
// `Hash` is the SHA-256 digest of the secret the operator received
// at creation time. The plaintext is never persisted; presenting the
// secret again requires minting a fresh key. The lookup path is
// `Hash`-equality, so this is intentionally a deterministic digest
// rather than a slow KDF — the underlying secret has 256 bits of
// entropy and is uniformly random, putting it well outside the
// reach of any offline cracker even against SHA-256.
//
// `Hash` carries the `json:"-"` tag as a defence-in-depth guard
// against accidental serialisation — the same pattern applied to
// `PolicySigningKey.PrivateKey`. Every handler today projects via
// `toAPIKeyResponse` which omits the field, but tagging the struct
// itself means a future refactor that passes the raw `TenantAPIKey`
// through `json.Marshal` / `WriteJSON` cannot leak the hash onto
// the wire. Even though the hash is computationally infeasible to
// invert (256-bit-entropy preimage), leaking it would let an
// attacker with a suspected plaintext verify the match offline
// without hitting the API — a class of probe we cut off at the type
// level rather than relying on every handler to remember the rule.
//
// `Subject` is the human-readable actor name used in audit log
// entries (e.g. "ci-bot"). It is NOT a permission scope.
type TenantAPIKey struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Name       string
	Subject    string
	Hash       []byte `json:"-"`
	Status     TenantAPIKeyStatus
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedBy  *uuid.UUID
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// PolicySigningKey is one Ed25519 keypair in a tenant's rotation
// history. The private half is stored as the raw 32-byte seed; the
// public half is the 32-byte verification key. KeyID is a stable
// short identifier (e.g. a UUID truncated to 16 hex chars) so the
// bundle envelope can carry it without leaking the full database
// row id.
//
// PrivateKey carries the `json:"-"` tag as a defence-in-depth guard
// against accidental serialisation. Every handler today projects
// via `toPolicySigningKeyResponse` which omits the field, but
// tagging the struct itself means a future refactor that passes
// the raw `PolicySigningKey` through `json.Marshal` / `WriteJSON`
// cannot leak the seed onto the wire.
type PolicySigningKey struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	KeyID       string
	Algorithm   string
	PublicKey   []byte
	PrivateKey  []byte `json:"-"`
	Status      PolicySigningKeyStatus
	ActivatedAt time.Time
	RotatedAt   *time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
}
