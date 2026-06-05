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
	"fmt"
	"math"
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
	ID   uuid.UUID
	Name string
	Slug string
	// MSPID is the primary owner-binding MSP. Nil when the
	// tenant is unmanaged (direct platform customer). The denormalised
	// column is kept in sync with the `msp_tenants` row whose
	// relationship is 'owner' by the MSP service's AssignTenant /
	// UnassignTenant path. See migration 015 for the storage rationale.
	MSPID     *uuid.UUID
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

// SiteHAMode enumerates the high-availability posture of a site's
// edge appliance(s). Mirrors the CHECK constraint on
// `sites.ha_mode` added in migration 035.
//
//   - standalone:     a single edge VM, no failover (the default).
//   - active_passive: a VRRP-class active/passive pair; one edge
//     owns the VIP at a time and the other promotes on failure.
//     The peer device is recorded in `Site.HAPeerDeviceID`.
type SiteHAMode string

const (
	SiteHAModeStandalone    SiteHAMode = "standalone"
	SiteHAModeActivePassive SiteHAMode = "active_passive"
)

// Site is an enforcement scope owned by a tenant.
type Site struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Name     string
	Slug     string
	Template SiteTemplate
	Config   json.RawMessage
	// HAMode is the site's failover posture. Defaults to
	// standalone for every existing site (the migration
	// backfills the column with that value).
	HAMode SiteHAMode
	// HAPeerDeviceID is the partner edge device in an
	// active/passive pair. Nil when HAMode is standalone (a
	// nullable FK onto devices.id — see migration 035).
	HAPeerDeviceID *uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
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
	ExternalID  string // SCIM externalId for IdP reconciliation
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

	// IsDraft marks a candidate graph that has been persisted
	// (typically by the rollout API) but not yet promoted to
	// "live". GetCurrentGraph skips drafts; promotion flips
	// this back to false. See migration
	// 011_policy_graphs_is_draft for the schema rationale and
	// docs/policy-rollouts.md for the operator-facing
	// lifecycle. The zero value is false (live), which keeps
	// the direct PutGraph path backwards-compatible.
	IsDraft bool
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
// `Sha256` is the precomputed SHA-256 digest of `Bundle`, populated
// by the repository layer on insert and used by the agent-pull
// endpoint to serve HEAD / If-None-Match responses without
// transferring the full bundle bytes out of Postgres.
type PolicyBundle struct {
	ID            uuid.UUID
	PolicyGraphID uuid.UUID
	TargetType    PolicyBundleTarget
	Bundle        []byte
	Signature     []byte
	KeyID         string
	Sha256        []byte
	CreatedAt     time.Time
}

// PolicyBundleMetadata is the agent-pull metadata view of a
// PolicyBundle. It carries everything the HEAD / If-None-Match /
// If-Modified-Since paths need to respond to a polling agent
// (digest, signature, key_id, bundle byte length, timestamp)
// WITHOUT loading the bundle BYTEA into application memory. The
// downloadBundle handler resolves a metadata row first; only when
// the agent's conditional headers do not short-circuit does it
// reach for the full bundle bytes via GetLatestBundle.
//
// The split exists because polling agents fire HEAD / conditional
// GET an order of magnitude more often than full GET, and bundles
// can grow into the high-KB range as policy graphs scale. Avoiding
// the BYTEA load on the polling-hot path keeps Postgres bandwidth
// proportional to actual change rate, not poll rate.
type PolicyBundleMetadata struct {
	ID            uuid.UUID
	PolicyGraphID uuid.UUID
	TargetType    PolicyBundleTarget
	Signature     []byte
	KeyID         string
	Sha256        []byte
	BundleSize    int
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

// PolicyRolloutStage enumerates the stages of a progressive policy
// rollout, per ARCHITECTURE.md Block 2 (policy-change simulation).
// The rollout state-machine is monotone forward — Stage transitions
// can only advance (DryRun -> Canary -> Full) or terminate
// (-> RolledBack / -> Completed). A new rollout always begins at
// DryRun; operators cannot fast-path straight to Full without
// recording a dry-run pass first.
//
// `RolledBack` is a terminal state distinct from `Completed`. A
// rolled-back rollout exists in the audit trail so the operator
// can see "this proposed change was simulated, dry-run'd, and
// pulled back" — distinct from "never rolled out" (no record).
type PolicyRolloutStage string

const (
	// PolicyRolloutStageDryRun is the initial stage: the proposed
	// graph is compiled to a shadow bundle that agents log
	// verdicts against without enforcing. The operator inspects
	// the delta between shadow and live verdicts to decide
	// whether to promote.
	PolicyRolloutStageDryRun PolicyRolloutStage = "dry_run"
	// PolicyRolloutStageCanary is the partial-fleet stage: a
	// configurable percentage of devices receive the proposed
	// graph as the enforced bundle; the rest continue on the
	// previous graph. The operator watches per-cohort error
	// rates / verdict mix before advancing.
	PolicyRolloutStageCanary PolicyRolloutStage = "canary"
	// PolicyRolloutStageFull is the fleet-wide stage: every
	// device receives the proposed graph as the enforced bundle.
	// The rollout remains in this stage until either (a) the
	// operator marks it Completed (graph is now the tenant
	// canonical) or (b) the operator rolls it back.
	PolicyRolloutStageFull PolicyRolloutStage = "full"
	// PolicyRolloutStageCompleted is a terminal state: the
	// rollout reached fleet-wide enforcement and the operator
	// promoted the proposed graph to the tenant's canonical
	// PolicyGraph. Recorded for audit history.
	PolicyRolloutStageCompleted PolicyRolloutStage = "completed"
	// PolicyRolloutStageRolledBack is a terminal state: the
	// operator pulled the rollout at any non-completed stage,
	// restoring the previous graph as the enforced bundle.
	PolicyRolloutStageRolledBack PolicyRolloutStage = "rolled_back"
)

// IsTerminal reports whether the stage admits no further
// transitions. The handler layer uses this to reject
// advance/rollback calls on already-finished rollouts with
// ErrForbidden rather than silently no-op'ing.
func (s PolicyRolloutStage) IsTerminal() bool {
	return s == PolicyRolloutStageCompleted || s == PolicyRolloutStageRolledBack
}

// PolicyRollout is one row in the policy_rollouts table. Tracks the
// progressive deployment of a proposed PolicyGraph from dry-run
// shadow through canary cohort to fleet-wide enforcement, with
// rollback at any stage.
//
// `GraphID` is the proposed graph being rolled out. `PreviousGraphID`
// is the graph that was canonical immediately before this rollout
// started — populated even on the first rollout (in which case it
// references the empty-graph sentinel via uuid.Nil). On rollback,
// `PreviousGraphID` is the graph the agents return to.
//
// `CanaryPercent` is meaningful only when Stage == Canary (0-100
// inclusive); ignored in other stages. The cohort assignment is
// deterministic: device IDs hash into [0, 100) and devices whose
// hash < CanaryPercent receive the new bundle. This makes the
// cohort reproducible across server restarts and lets an operator
// deterministically tell a customer "your device is / is not in
// the cohort" given the rollout ID.
//
// `SimulationID` is the impact-report ID the operator reviewed
// before promoting. It's a UUID generated by the simulator and is
// not foreign-keyed (simulations aren't persisted in this PR —
// the operator records the ID out-of-band if they want a paper
// trail). Zero when the rollout was created without a pre-flight
// simulation (e.g. an emergency rollback re-promotion).
type PolicyRollout struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	GraphID         uuid.UUID
	PreviousGraphID uuid.UUID
	Stage           PolicyRolloutStage
	CanaryPercent   int
	SimulationID    uuid.UUID
	CreatedBy       *uuid.UUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
	// Notes is a free-form operator-facing label captured at the
	// most recent stage transition — useful for change-review
	// tooling ("rolling back due to elevated 5xx on
	// auth-svc"). Bounded to 1024 chars at the handler layer;
	// the column itself is unconstrained TEXT.
	Notes string
}

// -----------------------------------------------------------------------
// Baseline + alert types (Phase 3 Block 3, Tasks 11-15).
// -----------------------------------------------------------------------

// BaselineModel is one row in the baseline_models table. Tracks
// the running mean + variance (Welford) and EWMA estimators for
// a single (tenant, dimension, window_seconds) metric.
//
// The Welford pair (Mean, M2) is the numerically-stable online
// estimator from Knuth/Welford: given a new sample x, update
//
//	samples++  delta = x - mean
//	mean += delta / samples
//	m2   += delta * (x - mean)
//
// Sample variance is then m2 / max(samples - 1, 1); standard
// deviation is sqrt(variance). Samples < 2 means cold start —
// the anomaly detector skips scoring until enough samples
// accumulate to make the estimate meaningful (default 30).
//
// (EWMA, EWMVar) is the exponentially-weighted pair. On a new
// sample x with decay alpha, against the PRE-update ewma:
//
//	delta    = x - ewma           // residual vs. previous EWMA
//	ewma     = alpha*x + (1-alpha)*ewma
//	ewma_var = alpha*delta*delta + (1-alpha)*ewma_var
//
// This is the standard exponentially-smoothed squared residual
// (the "RiskMetrics-style" EWVar) used by baseline.Engine.Fold.
// It differs from West/Pelet's recursive variance estimator
// `(1-alpha)*(ewma_var + alpha*delta^2)` by a scaling factor of
// `(1-alpha)` on the squared-residual term — both are valid EW
// variance estimators, and we ship the simpler form. Tuning of
// ZThreshold should be done against the EWMA z-score this
// formula produces, not against the West/Pelet variant.
//
// The EWMA captures recent shifts much faster than the Welford
// estimator, which is important for catching sudden anomalies
// (e.g. a malware outbreak generating a 5x spike in DNS
// queries) that the long-run Welford mean would dilute.
//
// ZThreshold is the per-(tenant, dimension) alert threshold in
// units of standard deviation; the anomaly detector emits an
// alert when max(|z_welford|, |z_ewma|) >= ZThreshold. Default
// 3.0 captures the ~0.27% tail of a Gaussian, which empirically
// is the right knee for "novel enough to wake an operator".
//
// Version is an optimistic-lock counter incremented on every
// successful Update. The service layer uses it to detect lost
// updates when a fan-out goroutine observes two batches into the
// same model concurrently — see baseline.Engine.Observe.
type BaselineModel struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Dimension      string
	WindowSeconds  int
	Samples        int64
	Mean           float64
	M2             float64
	EWMA           float64
	EWMAVar        float64
	Alpha          float64
	ZThreshold     float64
	LastObservedAt time.Time
	LastUpdatedAt  time.Time
	CreatedAt      time.Time
	Version        int64
}

// StdDev returns the sample standard deviation of the Welford
// estimator. Returns 0 when samples < 2 (cold start, undefined).
func (b BaselineModel) StdDev() float64 {
	if b.Samples < 2 {
		return 0
	}
	v := b.M2 / float64(b.Samples-1)
	if v <= 0 {
		return 0
	}
	return math.Sqrt(v)
}

// EWMAStdDev returns the EW standard deviation. Like StdDev, the
// estimator is only meaningful after a warm-up window — callers
// should gate scoring on Samples >= a minimum-warmup threshold
// (the anomaly detector uses 30 by default).
func (b BaselineModel) EWMAStdDev() float64 {
	if b.Samples < 2 {
		return 0
	}
	if b.EWMAVar <= 0 {
		return 0
	}
	return math.Sqrt(b.EWMAVar)
}

// -----------------------------------------------------------------------
// Alert types
// -----------------------------------------------------------------------

// AlertSeverity enumerates the three-bucket severity scale.
// Matches the alerts.severity CHECK constraint.
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// IsValid reports whether s is a known severity.
func (s AlertSeverity) IsValid() bool {
	switch s {
	case AlertSeverityInfo, AlertSeverityWarning, AlertSeverityCritical:
		return true
	}
	return false
}

// AlertState enumerates the alert lifecycle states. Matches the
// alerts.state CHECK constraint.
type AlertState string

const (
	AlertStateOpen         AlertState = "open"
	AlertStateAcknowledged AlertState = "acknowledged"
	AlertStateResolved     AlertState = "resolved"
	AlertStateSuppressed   AlertState = "suppressed"
)

// IsValid reports whether s is a known state.
func (s AlertState) IsValid() bool {
	switch s {
	case AlertStateOpen, AlertStateAcknowledged,
		AlertStateResolved, AlertStateSuppressed:
		return true
	}
	return false
}

// IsTerminal reports whether the state admits no further
// transitions. Resolved and Suppressed are terminal; Open and
// Acknowledged are not.
func (s AlertState) IsTerminal() bool {
	return s == AlertStateResolved || s == AlertStateSuppressed
}

// Alert is one row in the alerts table. Created at emit time by
// alert.Router; the statistical context (Mean/StdDev/ZScore) is
// snapshot-copied at creation so the alert remains self-
// explaining even after the underlying baseline drifts.
type Alert struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Kind           string
	Severity       AlertSeverity
	Dimension      string
	ObservedValue  float64
	BaselineMean   float64
	BaselineStdDev float64
	ZScore         float64
	WindowStart    time.Time
	WindowEnd      time.Time
	// WindowSeconds is the bucket size of the underlying baseline
	// model. Snapshot-copied at emit time so the alert.Feedback
	// tuning loop can scope its FP-rate aggregation to the
	// matching (dimension, window_seconds) tuple. See PR #40
	// round-9 ANALYSIS_0002.
	WindowSeconds  int
	Summary        string
	Evidence       []byte // JSON; never persist non-JSON bytes here
	State          AlertState
	SuppressedBy   *uuid.UUID
	AcknowledgedBy *uuid.UUID
	AcknowledgedAt *time.Time
	ResolvedBy     *uuid.UUID
	ResolvedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AlertSuppression is one row in the alert_suppressions table.
// The (Kind, Dimension) pair are matchers: a nil pointer means
// "match any". The CHECK constraint requires at least one to be
// non-nil so a suppression rule always has a discriminating
// scope.
type AlertSuppression struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Kind      *string
	Dimension *string
	Reason    string
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// IsActive reports whether the suppression is currently in
// effect at the supplied wall-clock time. A nil ExpiresAt means
// the suppression never expires.
func (s AlertSuppression) IsActive(now time.Time) bool {
	if s.ExpiresAt == nil {
		return true
	}
	return now.Before(*s.ExpiresAt)
}

// Matches reports whether a suppression rule covers an alert
// with the supplied (kind, dimension). A nil matcher field on
// the rule is a wildcard.
func (s AlertSuppression) Matches(kind, dimension string) bool {
	if s.Kind != nil && *s.Kind != kind {
		return false
	}
	if s.Dimension != nil && *s.Dimension != dimension {
		return false
	}
	return true
}

// AlertFeedbackDecision enumerates the operator-visible feedback
// labels. Matches the alert_feedback.decision CHECK constraint.
type AlertFeedbackDecision string

const (
	AlertFeedbackTruePositive  AlertFeedbackDecision = "true_positive"
	AlertFeedbackFalsePositive AlertFeedbackDecision = "false_positive"
	AlertFeedbackNoise         AlertFeedbackDecision = "noise"
)

// IsValid reports whether d is a known feedback decision.
func (d AlertFeedbackDecision) IsValid() bool {
	switch d {
	case AlertFeedbackTruePositive, AlertFeedbackFalsePositive, AlertFeedbackNoise:
		return true
	}
	return false
}

// AlertFeedback is one row in the alert_feedback table. The
// UNIQUE constraint on alert_id enforces one feedback per alert
// — the API DELETEs and re-INSERTs rather than overwrites so
// the audit trail captures the revision.
type AlertFeedback struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	AlertID   uuid.UUID
	Decision  AlertFeedbackDecision
	Notes     string
	CreatedBy *uuid.UUID
	CreatedAt time.Time
}

// --- Integration connectors ----------------------------------------------

// IntegrationConnectorType enumerates the connector kinds supported
// by internal/service/integration. The Service uses this discriminator
// to route Validate/Test/Deliver calls to the right plugin in the
// connector registry; the database CHECK constraint pins the same
// set so a row with an unknown type cannot land in the table.
type IntegrationConnectorType string

const (
	// IntegrationConnectorSyslog forwards events as RFC 5424
	// syslog messages over TLS (RFC 5425) or plain TCP / UDP
	// where the operator explicitly opts out of TLS.
	IntegrationConnectorSyslog IntegrationConnectorType = "syslog"
	// IntegrationConnectorSIEMWebhook posts JSON-encoded events
	// to SIEM / XDR HTTP endpoints (Splunk HEC, Elastic, Sentinel,
	// generic webhook). Distinct from the tenant webhook service
	// — that one is operator-owned receivers; this one is a
	// purpose-built SIEM/XDR payload shape with HMAC + per-vendor
	// envelope normalisation.
	IntegrationConnectorSIEMWebhook IntegrationConnectorType = "siem_webhook"
	// IntegrationConnectorJira opens / updates Jira issues via the
	// Atlassian Cloud REST API (token + email auth in v1, OAuth 2.0
	// device flow planned). Bidirectional sync is best-effort: the
	// edge of trust is the cloud-issue ID embedded in the SNG
	// alert payload, returned by the connector on first Deliver.
	IntegrationConnectorJira IntegrationConnectorType = "jira"
	// IntegrationConnectorServiceNow opens / updates ServiceNow
	// incidents via the Table API (basic auth in v1, OAuth 2.0
	// client-credentials planned).
	IntegrationConnectorServiceNow IntegrationConnectorType = "servicenow"
)

// IsValid reports whether the connector type is one the registry
// knows how to dispatch. Returns false for the zero value.
func (t IntegrationConnectorType) IsValid() bool {
	switch t {
	case IntegrationConnectorSyslog,
		IntegrationConnectorSIEMWebhook,
		IntegrationConnectorJira,
		IntegrationConnectorServiceNow:
		return true
	}
	return false
}

// IntegrationConnectorStatus enumerates connector lifecycle states.
// Matches the CHECK constraint on integration_connectors.status.
type IntegrationConnectorStatus string

const (
	IntegrationConnectorStatusActive   IntegrationConnectorStatus = "active"
	IntegrationConnectorStatusDisabled IntegrationConnectorStatus = "disabled"
)

// IntegrationTestResult enumerates the outcome of the most recent
// Test() probe. NEVER means TestConnector has not been called since
// the row was created — operators are expected to test before
// enabling, but nothing in the data model forces that order.
type IntegrationTestResult string

const (
	IntegrationTestResultNever   IntegrationTestResult = "never"
	IntegrationTestResultSuccess IntegrationTestResult = "success"
	IntegrationTestResultFailure IntegrationTestResult = "failure"
)

// IntegrationConnector is one configured outbound destination for a
// tenant. The Config / Secret split mirrors the webhook endpoint
// shape: Config is operator-readable on List/Get; Secret is opaque
// and returned only as a presence flag on read (never the value).
//
// Secret encryption-at-rest is delegated to disk encryption / TDE
// in the same way as WebhookEndpoint.SigningSecret — the migration
// header comment calls this out. Per-row envelope encryption is a
// known follow-up for the FedRAMP-track deployment.
type IntegrationConnector struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	// Type is the connector plugin to dispatch to. See
	// IntegrationConnectorType.
	Type IntegrationConnectorType
	// Name is the operator-visible label (uniqueness scope is
	// (tenant, name) — enforced by the migration's UNIQUE index).
	Name string
	// Description is free-form operator notes. Optional.
	Description string
	// EventTypes is the inclusion filter: only events whose type
	// is in this slice fan out to this connector. Empty means
	// every event matches — the dispatcher treats nil and []string
	// identically (subscribe-to-all). Concrete event types are
	// owned by the producing services (alert.*, telemetry.* …).
	EventTypes []string
	// Config is the connector-type-specific configuration JSON.
	// The connector plugin owns the schema; the Service just
	// shuttles bytes. See internal/service/integration/{type}.go
	// Config struct for the per-connector contract.
	Config json.RawMessage
	// Secret is the connector-type-specific secret JSON. Same
	// shape contract as Config but never returned to clients.
	Secret json.RawMessage
	// Status governs whether the dispatcher fans out to this row
	// at all. Disabled rows are inert and Test()-only.
	Status IntegrationConnectorStatus
	// LastTestResult tracks the outcome of the last TestConnector
	// probe.
	LastTestResult IntegrationTestResult
	// LastTestAt is when the last probe ran. Nil when LastTestResult
	// is NEVER.
	LastTestAt *time.Time
	// LastTestError is the human-readable error from the last
	// failed probe. Cleared on success. Empty when LastTestResult
	// is NEVER or SUCCESS.
	LastTestError string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// IntegrationDeliveryStatus enumerates the delivery worker's state
// transitions for a single connector dispatch attempt. Identical
// shape to WebhookDeliveryStatus so operators using both pipes
// recognise the lifecycle.
type IntegrationDeliveryStatus string

const (
	IntegrationDeliveryStatusPending IntegrationDeliveryStatus = "pending"
	// IntegrationDeliveryStatusProcessing is the exclusive-ownership
	// state a delivery transitions into when a worker claims it.
	IntegrationDeliveryStatusProcessing IntegrationDeliveryStatus = "processing"
	IntegrationDeliveryStatusDelivered  IntegrationDeliveryStatus = "delivered"
	IntegrationDeliveryStatusFailed     IntegrationDeliveryStatus = "failed"
	IntegrationDeliveryStatusExhausted  IntegrationDeliveryStatus = "exhausted"
)

// IntegrationDelivery is one fan-out row produced by the dispatcher
// for a single connector. The Service.Enqueue path produces a row
// per matching connector; the DeliveryWorker (subsequent PR) walks
// IntegrationDeliveryRepository.ListPending to retry due rows.
type IntegrationDelivery struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	ConnectorID    uuid.UUID
	EventType      string
	Payload        json.RawMessage
	Status         IntegrationDeliveryStatus
	Attempts       int
	LastAttemptAt  *time.Time
	LastError      string
	NextRetryAt    time.Time
	ResponseStatus int
	// ExternalReference is the connector-issued identifier (Jira
	// issue key, ServiceNow sys_id, syslog has none). Populated by
	// the worker on first successful Deliver, then immutable —
	// follow-up Deliver()s for the same alert.* event update the
	// remote object referenced here.
	ExternalReference string
	CreatedAt         time.Time
}

// ---------------------------------------------------------------------
// MSP (Managed Service Provider) hierarchy
// ---------------------------------------------------------------------

// MSPStatus enumerates the lifecycle stages of an MSP. Mirrors the
// CHECK constraint on `msps.status`.
type MSPStatus string

const (
	MSPStatusActive    MSPStatus = "active"
	MSPStatusSuspended MSPStatus = "suspended"
	MSPStatusDeleted   MSPStatus = "deleted"
)

// MSPRelationship enumerates the kinds of MSP↔tenant bindings.
// Mirrors the CHECK constraint on `msp_tenants.relationship`.
//
//   - Owner       — the primary MSP for the tenant. A tenant has
//     at most one owner binding at any time (enforced by a
//     partial UNIQUE index in migration 015). The denormalised
//     `tenants.msp_id` always points at the owner.
//   - CoManager   — a secondary read-mostly binding, used for
//     temporary co-management or staged handoff.
type MSPRelationship string

const (
	MSPRelationshipOwner     MSPRelationship = "owner"
	MSPRelationshipCoManager MSPRelationship = "co_manager"
)

// IsValid reports whether r is a recognised MSPRelationship enum.
func (r MSPRelationship) IsValid() bool {
	switch r {
	case MSPRelationshipOwner, MSPRelationshipCoManager:
		return true
	}
	return false
}

// MSPBranding is the shared visual identity an MSP applies to its
// tenant cohort. Tenants inherit the MSP's branding unless they
// override individual fields via `tenants.settings.branding`. The
// resolution chain (tenant override → MSP default → platform
// default) lives in internal/service/tenant/branding.go.
//
// All fields are optional. Empty strings mean "not set" and the
// resolver falls through to the next layer.
type MSPBranding struct {
	LogoURL         string `json:"logo_url,omitempty"`
	PrimaryColor    string `json:"primary_color,omitempty"`
	SecondaryColor  string `json:"secondary_color,omitempty"`
	CustomDomain    string `json:"custom_domain,omitempty"`
	PortalSupportTo string `json:"portal_support_to,omitempty"`
}

// MSP is the top-level managed-service-provider entity. NOT
// RLS-scoped (mirrors Tenant) — application authorization gates
// who can read which rows.
type MSP struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	Status    MSPStatus
	Branding  MSPBranding
	Settings  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// MSPPatch is the input to MSPRepository.Update. Same sparse-PATCH
// semantics as TenantPatch (see its docstring): nil = leave
// untouched; non-nil = set (including zero value to clear).
type MSPPatch struct {
	Name     *string
	Slug     *string
	Status   *MSPStatus
	Branding *MSPBranding
	Settings *json.RawMessage
}

// MSPTenantBinding is one row of the msp_tenants join table. The
// Relationship field distinguishes the primary owner from
// co-managers.
type MSPTenantBinding struct {
	MSPID        uuid.UUID
	TenantID     uuid.UUID
	Relationship MSPRelationship
	CreatedAt    time.Time
	CreatedBy    *uuid.UUID
}

// ---------------------------------------------------------------------
// Browser Protection (Phase 4, Task 43)
// ---------------------------------------------------------------------

// BrowserRuleType enumerates the kinds of browser-level enforcement
// a BrowserRule can apply. Mirrors the CHECK constraint on
// browser_rules.type.
type BrowserRuleType string

const (
	BrowserRuleTypeDownload    BrowserRuleType = "download"
	BrowserRuleTypeUpload      BrowserRuleType = "upload"
	BrowserRuleTypeClipboard   BrowserRuleType = "clipboard"
	BrowserRuleTypePrint       BrowserRuleType = "print"
	BrowserRuleTypeScreenshot  BrowserRuleType = "screenshot"
	BrowserRuleTypeURLCategory BrowserRuleType = "url_category"
)

// IsValid reports whether t is a recognised BrowserRuleType.
func (t BrowserRuleType) IsValid() bool {
	switch t {
	case BrowserRuleTypeDownload, BrowserRuleTypeUpload,
		BrowserRuleTypeClipboard, BrowserRuleTypePrint,
		BrowserRuleTypeScreenshot, BrowserRuleTypeURLCategory:
		return true
	}
	return false
}

// BrowserPolicyAction enumerates the policy-level action applied
// when a rule matches.
type BrowserPolicyAction string

const (
	BrowserPolicyActionBlock BrowserPolicyAction = "block"
	BrowserPolicyActionAllow BrowserPolicyAction = "allow"
	BrowserPolicyActionWarn  BrowserPolicyAction = "warn"
	BrowserPolicyActionLog   BrowserPolicyAction = "log"
	// BrowserPolicyActionRBI redirects the user to the Remote Browser
	// Isolation proxy so the page renders in a disposable container
	// rather than the endpoint's local browser. Added by Gap #8.
	BrowserPolicyActionRBI BrowserPolicyAction = "rbi"
)

// IsValid reports whether a is a recognised BrowserPolicyAction.
func (a BrowserPolicyAction) IsValid() bool {
	switch a {
	case BrowserPolicyActionBlock, BrowserPolicyActionAllow,
		BrowserPolicyActionWarn, BrowserPolicyActionLog,
		BrowserPolicyActionRBI:
		return true
	}
	return false
}

// BrowserPolicyScope enumerates the targeting scope of a browser
// protection policy.
type BrowserPolicyScope string

const (
	BrowserPolicyScopeUser  BrowserPolicyScope = "user"
	BrowserPolicyScopeGroup BrowserPolicyScope = "group"
	BrowserPolicyScopeSite  BrowserPolicyScope = "site"
)

// IsValid reports whether s is a recognised BrowserPolicyScope.
func (s BrowserPolicyScope) IsValid() bool {
	switch s {
	case BrowserPolicyScopeUser, BrowserPolicyScopeGroup,
		BrowserPolicyScopeSite:
		return true
	}
	return false
}

// BrowserRule is a single enforcement rule inside a BrowserPolicy.
type BrowserRule struct {
	Type      BrowserRuleType     `json:"type"`
	Condition string              `json:"condition,omitempty"`
	Action    BrowserPolicyAction `json:"action"`
}

// BrowserPolicy is one row in the browser_policies table.
type BrowserPolicy struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Name      string
	Rules     []BrowserRule
	Action    BrowserPolicyAction
	Scope     BrowserPolicyScope
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// BrowserPolicyPatch is the sparse-PATCH input for updates.
type BrowserPolicyPatch struct {
	Name    *string
	Rules   []BrowserRule
	Action  *BrowserPolicyAction
	Scope   *BrowserPolicyScope
	Enabled *bool
}

// ---------------------------------------------------------------------
// Data Classification Taxonomy (Phase 4, Task 46)
// ---------------------------------------------------------------------

// ClassificationLevel enumerates the hierarchical data classification
// labels. Ordered from least to most sensitive.
type ClassificationLevel string

const (
	ClassificationLevelPublic       ClassificationLevel = "public"
	ClassificationLevelInternal     ClassificationLevel = "internal"
	ClassificationLevelConfidential ClassificationLevel = "confidential"
	ClassificationLevelRestricted   ClassificationLevel = "restricted"
	ClassificationLevelTopSecret    ClassificationLevel = "top_secret"
)

// IsValid reports whether l is a recognised ClassificationLevel.
func (l ClassificationLevel) IsValid() bool {
	switch l {
	case ClassificationLevelPublic, ClassificationLevelInternal,
		ClassificationLevelConfidential, ClassificationLevelRestricted,
		ClassificationLevelTopSecret:
		return true
	}
	return false
}

// ClassificationLevelRank returns a numeric rank (0-4) for sorting/
// comparison. Higher rank means more sensitive.
func (l ClassificationLevel) Rank() int {
	switch l {
	case ClassificationLevelPublic:
		return 0
	case ClassificationLevelInternal:
		return 1
	case ClassificationLevelConfidential:
		return 2
	case ClassificationLevelRestricted:
		return 3
	case ClassificationLevelTopSecret:
		return 4
	default:
		return -1
	}
}

// DataClassification is one row in the data_classifications table.
type DataClassification struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	Label         string
	Level         ClassificationLevel
	Description   string
	HandlingRules json.RawMessage
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DataClassificationPatch is the sparse-PATCH input for updates.
type DataClassificationPatch struct {
	Label         *string
	Level         *ClassificationLevel
	Description   *string
	HandlingRules *json.RawMessage
}

// --- CASB types -----------------------------------------------------------

// CASBConnectorType enumerates the CASB connector kinds.
type CASBConnectorType string

const (
	CASBConnectorM365       CASBConnectorType = "m365"
	CASBConnectorGoogle     CASBConnectorType = "google"
	CASBConnectorSlack      CASBConnectorType = "slack"
	CASBConnectorSalesforce CASBConnectorType = "salesforce"
)

// IsValid reports whether t is a known CASB connector type.
func (t CASBConnectorType) IsValid() bool {
	switch t {
	case CASBConnectorM365, CASBConnectorGoogle,
		CASBConnectorSlack, CASBConnectorSalesforce:
		return true
	}
	return false
}

// CASBConnectorStatus enumerates connector lifecycle states.
type CASBConnectorStatus string

const (
	CASBConnectorStatusActive      CASBConnectorStatus = "active"
	CASBConnectorStatusDisabled    CASBConnectorStatus = "disabled"
	CASBConnectorStatusError       CASBConnectorStatus = "error"
	CASBConnectorStatusConfiguring CASBConnectorStatus = "configuring"
)

// IsValid reports whether s is a known status.
func (s CASBConnectorStatus) IsValid() bool {
	switch s {
	case CASBConnectorStatusActive, CASBConnectorStatusDisabled,
		CASBConnectorStatusError, CASBConnectorStatusConfiguring:
		return true
	}
	return false
}

// CASBConnector is a per-tenant CASB SaaS API connector. Config
// holds non-sensitive settings (tenant_id, endpoints); Secret holds
// sensitive material (client_secret, service-account keys).
type CASBConnector struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Type       CASBConnectorType
	Name       string
	Status     CASBConnectorStatus
	Config     json.RawMessage
	Secret     []byte
	LastSyncAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CASBDiscoveredApp is a SaaS application discovered by a CASB
// connector sync.
type CASBDiscoveredApp struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Name       string
	Vendor     string
	Category   string
	RiskScore  *int
	UsersCount int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// CASBPostureCheckStatus enumerates posture check outcomes.
type CASBPostureCheckStatus string

const (
	CASBPosturePass CASBPostureCheckStatus = "pass"
	CASBPostureFail CASBPostureCheckStatus = "fail"
	CASBPostureWarn CASBPostureCheckStatus = "warn"
)

// CASBPostureCheck is a single posture assessment row.
type CASBPostureCheck struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	AppID      uuid.UUID
	CheckName  string
	Status     CASBPostureCheckStatus
	Details    string
	AssessedAt time.Time
}

// InlineCASBRule is a persisted inline-CASB rule row
// (inline_casb_rules, migration 037). The service-layer type with
// typed Action/Verdict/Conditions lives in internal/service/casb;
// this repository projection keeps Action and Verdict as plain
// strings and Conditions as the raw JSONB document so the
// repository layer stays decoupled from the service's enums.
type InlineCASBRule struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	AppID      string
	Action     string
	Verdict    string
	Conditions json.RawMessage
	Enabled    bool
	// Priority maps the INTEGER column; int32 matches the data
	// plane's i32 so a value that round-trips here cannot overflow
	// on bundle deserialisation.
	Priority  int32
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SandboxVerdict is a persisted zero-day file-analysis verdict row
// (sandbox_verdicts, migration 042). One row per (tenant, file
// SHA-256): the SWG malware stage looks a file up by digest and, on
// a miss, the control plane submits it to a detonation sandbox and
// upserts the result here so the file is detonated at most once.
// The service-layer type with typed Classification/Status lives in
// internal/service/sandbox; this projection keeps them as plain
// strings so the repository stays decoupled from the service enums.
type SandboxVerdict struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	SHA256         string
	Classification string
	// Confidence is the provider's confidence in [0,1].
	Confidence float64
	Provider   string
	// SandboxID is the provider-side analysis id (nullable until a
	// submission is made); kept as a plain string ("" means none).
	SandboxID string
	Summary   string
	// Status is the lifecycle state: pending | complete | error.
	Status string
	// AnalyzedAt is when the provider finished analysis; nil while a
	// submission is still pending.
	AnalyzedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// RBISession is a persisted Remote Browser Isolation session row
// (rbi_sessions, migration 043). The session is created when the
// SWG redirects a URL to the RBI proxy; it tracks the isolated
// browsing context so the operator can audit and the proxy can
// enforce tenant-scoped session limits.
type RBISession struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	UserID    uuid.UUID
	TargetURL string
	// Status: active | closed | expired.
	Status    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// --- DLP ------------------------------------------------------------------

// DLPAction enumerates the enforcement actions a DLP policy can take
// when content matches one of its rules.
type DLPAction string

const (
	DLPActionLog     DLPAction = "log"
	DLPActionBlock   DLPAction = "block"
	DLPActionEncrypt DLPAction = "encrypt"
	DLPActionRedact  DLPAction = "redact"
)

// DLPRuleType enumerates the detection mechanisms a single DLP rule
// can use.
type DLPRuleType string

const (
	DLPRuleTypeRegex       DLPRuleType = "regex"
	DLPRuleTypeMIPLabel    DLPRuleType = "mip_label"
	DLPRuleTypeFingerprint DLPRuleType = "fingerprint"
	DLPRuleTypeKeyword     DLPRuleType = "keyword"
)

// DLPRule is one detection rule inside a DLPPolicy.
type DLPRule struct {
	Type             DLPRuleType `json:"type"`
	Pattern          string      `json:"pattern"`
	SensitivityLevel string      `json:"sensitivity_level"`
}

// DLPPolicy is a tenant-scoped DLP policy with embedded rules.
type DLPPolicy struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description string
	Rules       []DLPRule
	Action      DLPAction
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DLPPolicyPatch is the sparse-PATCH input for
// DLPPolicyRepository.Update. Same nil=leave semantics as
// TenantPatch.
type DLPPolicyPatch struct {
	Name        *string
	Description *string
	Rules       *[]DLPRule
	Action      *DLPAction
	Enabled     *bool
}

// DLPFingerprint is a registered document fingerprint for
// near-duplicate detection.
type DLPFingerprint struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Name         string
	Hash         []byte
	ContentType  string
	RegisteredAt time.Time
}

// DLPMatch records one audit-trail row when a DLP policy fires.
type DLPMatch struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	PolicyID  uuid.UUID
	Source    string
	MatchedAt time.Time
	Details   json.RawMessage
}

// --- Device enrollment ----------------------------------------------------

// EnrollmentStatus enumerates the lifecycle stages of a device
// enrollment. Mirrors the CHECK constraint on
// `device_enrollments.status`.
type EnrollmentStatus string

const (
	EnrollmentStatusEnrolled EnrollmentStatus = "enrolled"
	EnrollmentStatusActive   EnrollmentStatus = "active"
	EnrollmentStatusRevoked  EnrollmentStatus = "revoked"
)

// DeviceEnrollment represents a row in the device_enrollments table.
type DeviceEnrollment struct {
	DeviceID         uuid.UUID
	TenantID         uuid.UUID
	PublicKey        []byte // Ed25519 32-byte public key
	Status           EnrollmentStatus
	EnrolledAt       time.Time
	LastCertIssuedAt *time.Time
	RevokedAt        *time.Time
}

// DeviceCertificate represents a row in the device_certificates table.
type DeviceCertificate struct {
	ID        uuid.UUID
	DeviceID  uuid.UUID
	TenantID  uuid.UUID
	Serial    string
	CertPEM   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// --- AI Correlations ------------------------------------------------------

// AICorrelation represents a row in the ai_alert_correlations table.
type AICorrelation struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	AlertIDs  []uuid.UUID
	Summary   string
	Severity  string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// --- Compliance -----------------------------------------------------------

// ComplianceReport represents a row in the compliance_reports table.
type ComplianceReport struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Framework    string
	Score        float64
	MaxScore     float64
	Controls     json.RawMessage
	EvidencePack json.RawMessage
	GeneratedAt  time.Time
	CreatedAt    time.Time
}

// ComplianceEvidence represents a row in the platform-level
// compliance_evidence table (migration 039). Unlike ComplianceReport
// it is NOT tenant-scoped: SOC2 Type II evidence attests to the SNG
// platform's own controls, so there is no TenantID and no RLS. Rows
// index the signed evidence bundles archived in S3.
type ComplianceEvidence struct {
	ID             uuid.UUID
	CollectionType string // weekly | monthly | manual
	CollectedAt    time.Time
	S3Key          string
	Signature      string // hex-encoded Ed25519 signature over the bundle bytes
	Status         string // collecting | collected | failed | aggregated
	CreatedAt      time.Time
}

// --- Playbooks ------------------------------------------------------------

// Playbook represents a row in the playbooks table.
type Playbook struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	Name             string
	Description      string
	TriggerCondition string
	Steps            json.RawMessage
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PlaybookPatch is the sparse-update input for PlaybookRepository.Update.
type PlaybookPatch struct {
	Name             *string
	Description      *string
	TriggerCondition *string
	Steps            *json.RawMessage
	Enabled          *bool
}

// PlaybookExecution represents a row in the playbook_executions table.
type PlaybookExecution struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	PlaybookID   uuid.UUID
	Status       string
	TriggerEvent json.RawMessage
	StartedAt    time.Time
	CompletedAt  *time.Time
	CreatedAt    time.Time
}

// StepResult represents a row in the playbook_step_results table.
type StepResult struct {
	ID          uuid.UUID
	ExecutionID uuid.UUID
	TenantID    uuid.UUID
	StepOrder   int
	Status      string
	Output      json.RawMessage
	Error       string
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// PlaybookApproval represents a row in the playbook_approvals table.
type PlaybookApproval struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	ExecutionID uuid.UUID
	ApproverID  *uuid.UUID
	Status      string
	ExpiresAt   time.Time
	DecidedAt   *time.Time
	CreatedAt   time.Time
}

// --- Operational Health ---------------------------------------------------

// PolicyReviewSchedule represents a row in the policy_review_schedules table.
type PolicyReviewSchedule struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	PolicyID           uuid.UUID
	LastReviewedAt     *time.Time
	NextReviewAt       *time.Time
	ReviewIntervalDays int
	CreatedAt          time.Time
}

// OpsHealthSnapshot represents a row in the ops_health_snapshots table.
type OpsHealthSnapshot struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	HealthScore     int
	ComponentScores json.RawMessage
	CreatedAt       time.Time
}

// --- AI Suggestions -------------------------------------------------------

// AISuggestionStatus tracks a suggestion through the review workflow.
type AISuggestionStatus string

const (
	AISuggestionStatusPending    AISuggestionStatus = "pending"
	AISuggestionStatusApproved   AISuggestionStatus = "approved"
	AISuggestionStatusRejected   AISuggestionStatus = "rejected"
	AISuggestionStatusApplied    AISuggestionStatus = "applied"
	AISuggestionStatusRolledBack AISuggestionStatus = "rolled_back"
)

// AISuggestion represents a row in the ai_policy_suggestions table.
type AISuggestion struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	RuleID         string
	Category       string
	SuggestionJSON json.RawMessage
	Confidence     float64
	Status         AISuggestionStatus
	CreatedAt      time.Time
	ReviewedAt     *time.Time
	ReviewerID     *uuid.UUID
	Feedback       *string
}

// --- Troubleshooting ------------------------------------------------------

// KBCategory enumerates the allowed categories for knowledge base entries.
type KBCategory string

const (
	KBCategoryConnectivity KBCategory = "connectivity"
	KBCategoryPolicy       KBCategory = "policy"
	KBCategoryIdentity     KBCategory = "identity"
	KBCategoryPerformance  KBCategory = "performance"
	KBCategoryIntegration  KBCategory = "integration"
)

// KBEntry is a knowledge base article for the troubleshooting assistant.
// TenantID nil means a global (system-wide) entry.
type KBEntry struct {
	ID        uuid.UUID
	TenantID  *uuid.UUID
	Category  KBCategory
	Title     string
	Content   string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// KBEntryPatch is the sparse-PATCH input for KBEntryRepository.Update.
type KBEntryPatch struct {
	Category *KBCategory
	Title    *string
	Content  *string
	Tags     *[]string
}

// TroubleshootSessionStatus enumerates session lifecycle states.
type TroubleshootSessionStatus string

const (
	TroubleshootSessionActive    TroubleshootSessionStatus = "active"
	TroubleshootSessionResolved  TroubleshootSessionStatus = "resolved"
	TroubleshootSessionEscalated TroubleshootSessionStatus = "escalated"
)

// TroubleshootSession is a conversational troubleshooting session.
type TroubleshootSession struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	OperatorID        uuid.UUID
	Issue             string
	Status            TroubleshootSessionStatus
	Messages          json.RawMessage // []SessionMessage as JSON
	DiagnosticResults json.RawMessage // []DiagnosticResult as JSON
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// IDPProviderType enumerates the OIDC identity-provider families a
// tenant can federate for mobile native SSO. Mirrors the CHECK
// constraint on idp_configs.provider_type and the OpenAPI enum.
type IDPProviderType string

const (
	IDPProviderGoogleWorkspace IDPProviderType = "google_workspace"
	IDPProviderMicrosoft365    IDPProviderType = "microsoft365"
	IDPProviderZoho            IDPProviderType = "zoho"
	IDPProviderOkta            IDPProviderType = "okta"
	IDPProviderCustomOIDC      IDPProviderType = "custom_oidc"
)

// IDPProviderTypes is the set of recognised provider families, used
// by both repository backends to reject invalid values before they
// reach the postgres CHECK constraint.
var IDPProviderTypes = map[IDPProviderType]bool{
	IDPProviderGoogleWorkspace: true,
	IDPProviderMicrosoft365:    true,
	IDPProviderZoho:            true,
	IDPProviderOkta:            true,
	IDPProviderCustomOIDC:      true,
}

// ValidateIDPProviderType returns ErrInvalidArgument when t is not a
// recognised provider family.
func ValidateIDPProviderType(t IDPProviderType) error {
	if !IDPProviderTypes[t] {
		return fmt.Errorf("%w: invalid idp provider_type %q", ErrInvalidArgument, t)
	}
	return nil
}

// IDPConfig is a per-tenant OIDC provider configuration. The control
// plane uses it to validate mobile-presented ID tokens: the token's
// `iss` must equal IssuerURL, its `aud` must contain ClientID, and —
// when AllowedDomains is non-empty — the verified email/hosted-domain
// must fall within the allow-list. Only validation material is
// persisted; OIDC tokens are never stored.
type IDPConfig struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	ProviderType IDPProviderType
	IssuerURL    string
	ClientID     string
	// AllowedDomains restricts which email / hosted domains may
	// federate. Empty means "any domain the provider asserts".
	AllowedDomains []string
	// GroupClaimPath is the dotted path to the groups/roles claim in
	// the ID token (e.g. "groups" or "https://acme.com/roles"). Empty
	// disables group mapping.
	GroupClaimPath string
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
