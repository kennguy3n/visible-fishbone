package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors. Postgres-driver and memory-driver both translate
// their backend-specific errors into these so callers can branch on
// behaviour without sniffing pgx errno values or panic strings.
var (
	// ErrNotFound is returned by Get-style methods when the row
	// (or composite key) does not exist (or is filtered out by
	// RLS). It is NOT used for soft-deleted rows that the call
	// path explicitly opts into reading.
	ErrNotFound = errors.New("repository: not found")

	// ErrConflict is returned when an INSERT or UPDATE collides
	// with a uniqueness constraint (unique slug, unique email,
	// unique tenant+slug, unique tenant+version, etc.).
	ErrConflict = errors.New("repository: conflict")

	// ErrForbidden is returned when an operation is denied for
	// policy reasons (e.g. attempting to revoke a system role,
	// double-redeeming a claim token, mutating audit log rows).
	ErrForbidden = errors.New("repository: forbidden")

	// ErrInvalidArgument is returned when an input fails
	// invariants the schema would otherwise enforce server-side
	// (e.g. a non-existent enum value). Callers can map this to
	// a 400 at the HTTP boundary.
	ErrInvalidArgument = errors.New("repository: invalid argument")

	// ErrResourceExhausted is returned when an operation would
	// exceed a per-tenant quota (e.g. the active-API-key cap).
	// Distinct from ErrConflict (which means uniqueness) and
	// ErrForbidden (which means policy denial) so the HTTP layer
	// can map it to 429 Too Many Requests; the same caller may
	// succeed later after revoking an existing resource.
	ErrResourceExhausted = errors.New("repository: resource exhausted")
)

// SortOrder controls cursor pagination direction.
type SortOrder string

const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)

// Page captures cursor pagination parameters. `After` is an opaque
// cursor returned by the previous page (callers MUST NOT decode it
// — drivers may change the format). `Limit` is clamped to
// [1, MaxPageLimit] by the implementation.
type Page struct {
	After string
	Limit int
	Order SortOrder
}

// MaxPageLimit caps the page size implementations will honour.
// Callers requesting more get this many rows.
const MaxPageLimit = 200

// DefaultPageLimit is the limit used when Page.Limit <= 0.
const DefaultPageLimit = 50

// Normalize clamps Limit to [1, MaxPageLimit] and fills Order if empty.
// Returned by value so callers don't have to mutate their input.
func (p Page) Normalize() Page {
	out := p
	switch {
	case out.Limit <= 0:
		out.Limit = DefaultPageLimit
	case out.Limit > MaxPageLimit:
		out.Limit = MaxPageLimit
	}
	if out.Order == "" {
		out.Order = SortDesc
	}
	return out
}

// PageResult wraps a slice and the cursor for the next page. An
// empty `NextCursor` signals there are no further rows.
type PageResult[T any] struct {
	Items      []T
	NextCursor string
}

// --- Tenant ---------------------------------------------------------------

// TenantRepository owns the tenants table.
type TenantRepository interface {
	Create(ctx context.Context, t Tenant) (Tenant, error)
	Get(ctx context.Context, id uuid.UUID) (Tenant, error)
	GetBySlug(ctx context.Context, slug string) (Tenant, error)
	List(ctx context.Context, page Page) (PageResult[Tenant], error)
	// Update applies a sparse, explicit-clear PATCH. See the
	// TenantPatch docstring for the per-field semantics: a nil
	// pointer leaves the column untouched; a non-nil pointer
	// applies the value (including the zero value, which is how
	// operators clear optional fields like Region).
	Update(ctx context.Context, id uuid.UUID, patch TenantPatch) (Tenant, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status TenantStatus) (Tenant, error)
	// TransitionStatus atomically changes the tenant status only if
	// the current status matches `from`. Returns ErrForbidden if the
	// precondition is not met, ErrNotFound if the tenant does not
	// exist. This is the race-free building block for state-machine
	// transitions like active->suspended or active->deleted; prefer
	// it over a Get+UpdateStatus pair.
	TransitionStatus(ctx context.Context, id uuid.UUID, from, to TenantStatus) (Tenant, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// --- Site -----------------------------------------------------------------

// SiteRepository owns the sites table. Every operation is implicitly
// scoped by tenantID — drivers set the RLS GUC for the duration of
// each call.
type SiteRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, s Site) (Site, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (Site, error)
	List(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[Site], error)
	Update(ctx context.Context, tenantID uuid.UUID, s Site) (Site, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// --- User -----------------------------------------------------------------

// UserRepository owns the users table.
type UserRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, u User) (User, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (User, error)
	List(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[User], error)
	Update(ctx context.Context, tenantID uuid.UUID, u User) (User, error)
}

// --- Device ---------------------------------------------------------------

// DeviceListFilter narrows a device list call. Empty fields are
// ignored.
type DeviceListFilter struct {
	Platform DevicePlatform
	Status   DeviceStatus
	SiteID   *uuid.UUID
}

// DeviceRepository owns the devices table.
type DeviceRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, d Device) (Device, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (Device, error)
	List(ctx context.Context, tenantID uuid.UUID, filter DeviceListFilter, page Page) (PageResult[Device], error)
	UpdateLastSeen(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error
	UpdatePosture(ctx context.Context, tenantID, id uuid.UUID, posture Posture) error
	UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status DeviceStatus) (Device, error)
}

// --- Role -----------------------------------------------------------------

// RoleRepository owns the roles + user_roles tables.
type RoleRepository interface {
	Create(ctx context.Context, r Role) (Role, error)
	Get(ctx context.Context, id uuid.UUID) (Role, error)
	List(ctx context.Context, tenantID *uuid.UUID) ([]Role, error)
	AssignRole(ctx context.Context, ur UserRole) error
	RevokeRole(ctx context.Context, userID, roleID uuid.UUID, scopeID *uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]UserRole, error)
	HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// --- Claim Token ----------------------------------------------------------

// ClaimTokenRepository owns the claim_tokens table.
type ClaimTokenRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, t ClaimToken) (ClaimToken, error)
	Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, now time.Time) (ClaimToken, error)
	// UnredeemByHash clears RedeemedAt on a token identified by
	// its hash. This is a compensating action: if the service
	// redeems a token but a subsequent step (e.g. device creation)
	// fails, the token can be restored so it is reusable on retry.
	// Returns ErrNotFound if no token with the hash exists.
	UnredeemByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) error
	GetByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) (ClaimToken, error)
}

// --- Audit log ------------------------------------------------------------

// AuditFilter narrows an audit-log list call. Empty fields are
// ignored.
type AuditFilter struct {
	ActorID      *uuid.UUID
	ResourceType string
	Action       string
	From         *time.Time
	To           *time.Time
}

// AuditLogRepository owns the audit_log table. Append-only —
// implementations enforce the no-update / no-delete invariant.
type AuditLogRepository interface {
	Append(ctx context.Context, tenantID uuid.UUID, e AuditEntry) (AuditEntry, error)
	List(ctx context.Context, tenantID uuid.UUID, filter AuditFilter, page Page) (PageResult[AuditEntry], error)
}

// --- Webhooks -------------------------------------------------------------

// WebhookEndpointRepository owns webhook_endpoints.
type WebhookEndpointRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, ep WebhookEndpoint) (WebhookEndpoint, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (WebhookEndpoint, error)
	List(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[WebhookEndpoint], error)
	Update(ctx context.Context, tenantID uuid.UUID, ep WebhookEndpoint) (WebhookEndpoint, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
	// ListActive returns all active endpoints that subscribe to at
	// least one of the given event types. Used by the delivery
	// worker to fan out events.
	ListActive(ctx context.Context, tenantID uuid.UUID, eventTypes []string) ([]WebhookEndpoint, error)
}

// WebhookDeliveryRepository owns webhook_deliveries.
type WebhookDeliveryRepository interface {
	Create(ctx context.Context, tenantID uuid.UUID, d WebhookDelivery) (WebhookDelivery, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (WebhookDelivery, error)
	List(ctx context.Context, tenantID uuid.UUID, endpointID *uuid.UUID, page Page) (PageResult[WebhookDelivery], error)
	// UpdateStatus transitions the delivery to a new status with
	// attempt metadata. Called by the delivery worker after each
	// attempt.
	UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status WebhookDeliveryStatus, attempt int, lastErr string, responseStatus int, nextRetry time.Time) error
	// ListPending atomically claims a batch of due-for-retry
	// deliveries. Each returned row is transitioned from 'pending'
	// to 'processing' inside the same statement that selects it,
	// so concurrent workers cannot double-claim the same row.
	//
	// processingTimeout is the recovery window for rows stuck in
	// 'processing' (i.e. a previous worker crashed before
	// transitioning out of the state). Rows whose last_attempt_at
	// is older than now-processingTimeout are also re-claimable;
	// the postgres implementation includes them in the WHERE clause
	// of the atomic UPDATE and the memory implementation does the
	// same in its critical section. Set to 0 to never re-claim
	// stuck rows (use only in tests where a crash mid-tick is
	// impossible).
	//
	// Limit caps the batch size; rows are ordered by next_retry_at
	// ASC so the oldest due delivery is dispatched first. Returned
	// rows carry the post-claim status ('processing'); callers must
	// transition them to delivered / pending / exhausted via
	// UpdateStatus, otherwise they remain in 'processing' until the
	// stuck-row window elapses.
	ListPending(ctx context.Context, limit int, processingTimeout time.Duration) ([]WebhookDelivery, error)
}

// --- Tenant API keys ------------------------------------------------------

// TenantAPIKeyRepository owns the tenant_api_keys table. All tenant-
// scoped reads/writes pass through `sng.tenant_id`; the cross-tenant
// `LookupByHash` path runs under `sng.system_role='true'` because
// the caller (the auth middleware) has not yet identified the
// tenant — the presented key IS the identification.
type TenantAPIKeyRepository interface {
	// Create inserts a new API key. The caller is responsible for
	// generating the random secret, computing its SHA-256 hash,
	// and populating Name/Subject. The returned row carries the
	// generated ID + CreatedAt; the secret itself is never stored.
	Create(ctx context.Context, tenantID uuid.UUID, k TenantAPIKey) (TenantAPIKey, error)
	// Get returns a single key by id, scoped to tenantID. Returns
	// ErrNotFound when the key does not exist or belongs to a
	// different tenant (filtered out by RLS).
	Get(ctx context.Context, tenantID, id uuid.UUID) (TenantAPIKey, error)
	// List returns all keys for the tenant ordered by created_at
	// DESC. The handler does not paginate this list; an operator
	// who hits the cap should rotate their key inventory rather
	// than introducing cursoring.
	List(ctx context.Context, tenantID uuid.UUID) ([]TenantAPIKey, error)
	// Revoke transitions a key to status='revoked' and stamps the
	// revoked_at column with `at`. Idempotent — revoking an
	// already-revoked key is a no-op (no error). Returns
	// ErrNotFound when the key does not exist.
	Revoke(ctx context.Context, tenantID, id uuid.UUID, at time.Time) (TenantAPIKey, error)
	// LookupByHash returns the API key whose SHA-256 hash matches
	// `hash`. The lookup runs cross-tenant under the system-role
	// RLS bypass; it is the only call path that does so. Returns
	// ErrNotFound when no key with that hash exists. Status,
	// expiry, and revocation checks are the caller's
	// responsibility — the repository returns the raw row.
	LookupByHash(ctx context.Context, hash []byte) (TenantAPIKey, error)
	// TouchLastUsed best-effort updates last_used_at to `at`. The
	// auth middleware calls this on every successful authentication
	// so operators can audit key activity; the call is fire-and-
	// forget and a failure must not block the request. Returns
	// ErrNotFound when the key does not exist.
	TouchLastUsed(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error
	// CountActive returns the number of active (non-revoked, non-
	// expired) keys for the tenant. The service layer uses this to
	// enforce a per-tenant cap on key inventory — without a cap an
	// authenticated caller (JWT or existing key) could mint
	// unbounded keys and DOS the List path (which intentionally
	// does not paginate; see the List comment above for why).
	// Expired keys are NOT counted because they are de-facto
	// unusable and operators commonly leave them in place for
	// audit-trail continuity rather than rotating-and-deleting.
	// Implementations evaluate expiry against `now`.
	CountActive(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error)
}

// --- Policy ---------------------------------------------------------------

// PolicyRepository owns policy_graphs + policy_bundles.
type PolicyRepository interface {
	CreateGraph(ctx context.Context, tenantID uuid.UUID, g PolicyGraph) (PolicyGraph, error)
	GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (PolicyGraph, error)
	ListGraphVersions(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[PolicyGraph], error)
	CreateBundle(ctx context.Context, tenantID uuid.UUID, b PolicyBundle) (PolicyBundle, error)
	GetBundle(ctx context.Context, tenantID, id uuid.UUID) (PolicyBundle, error)
	GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target PolicyBundleTarget) (PolicyBundle, error)
	// GetLatestBundleMetadata returns the row-level metadata for
	// the latest bundle of `target` without loading the bundle
	// BYTEA. The agent-pull endpoint uses this on the polling
	// hot path so a HEAD / 304 response never round-trips the
	// blob out of Postgres. Returns ErrNotFound when no bundle
	// has yet been compiled for the (tenant, target) pair.
	GetLatestBundleMetadata(ctx context.Context, tenantID uuid.UUID, target PolicyBundleTarget) (PolicyBundleMetadata, error)
}

// --- Policy signing keys --------------------------------------------------

// PolicySigningKeyRepository owns the policy_signing_keys table.
// The table is tenant-scoped and protected by RLS — drivers set the
// `sng.tenant_id` GUC for every call.
//
// Rotation is performed as a single transaction in the driver: the
// previous active key is updated to status='rotated' and the new key
// is inserted with status='active'. The partial unique index on
// (tenant_id) WHERE status='active' makes the operation race-safe;
// a concurrent rotation by another worker will be rejected by the
// constraint and surface as ErrConflict, letting the caller retry.
type PolicySigningKeyRepository interface {
	// Create inserts a new key. The caller is responsible for
	// computing the (public, private) Ed25519 pair and the stable
	// short KeyID. New keys are inserted with status='active'.
	// Returns ErrConflict if another active key already exists for
	// this tenant — use Rotate to atomically replace it.
	Create(ctx context.Context, tenantID uuid.UUID, k PolicySigningKey) (PolicySigningKey, error)
	// CreateIfNoHistory inserts a new active key only when the
	// tenant has no signing-key history at all. Used by the
	// brand-new-tenant bootstrap path in EnsureKey to enforce the
	// revocation-incident invariant atomically: once any key has
	// ever existed for a tenant (active, rotated, or revoked),
	// auto-provisioning is refused — an admin must explicitly
	// Create or Rotate to resume signing. The existence check and
	// the insert run inside a single transaction so a concurrent
	// "create then revoke" on another connection cannot slip a
	// fresh key past the guard. Returns ErrConflict when history
	// exists.
	CreateIfNoHistory(ctx context.Context, tenantID uuid.UUID, k PolicySigningKey) (PolicySigningKey, error)
	// GetActive returns the unique active key for the tenant.
	// Returns ErrNotFound if no key has ever been provisioned for
	// this tenant.
	GetActive(ctx context.Context, tenantID uuid.UUID) (PolicySigningKey, error)
	// GetByKeyID returns a key by its stable short KeyID,
	// independent of status. Receivers and the bundle distribution
	// endpoint use this to fetch the public key for any historical
	// bundle.
	GetByKeyID(ctx context.Context, tenantID uuid.UUID, keyID string) (PolicySigningKey, error)
	// List returns the full rotation history for a tenant, ordered
	// by activated_at DESC. Used by the public-key publication
	// endpoint and the rotation audit trail.
	List(ctx context.Context, tenantID uuid.UUID) ([]PolicySigningKey, error)
	// Rotate atomically transitions the current active key to
	// status='rotated' and inserts the new key with status='active'.
	// Returns ErrNotFound if no active key exists for the tenant —
	// callers should use Create for the first-ever key.
	Rotate(ctx context.Context, tenantID uuid.UUID, newKey PolicySigningKey, at time.Time) (PolicySigningKey, error)
	// Revoke transitions a key to status='revoked'. A key can be
	// revoked from either 'active' or 'rotated' state. If revoking
	// the currently active key, the tenant has no active key until
	// Create or Rotate provisions a new one — bundle compilation
	// will fail with a clear error in the meantime, which is the
	// intended behaviour for a compromised-key incident.
	Revoke(ctx context.Context, tenantID uuid.UUID, keyID string, at time.Time) (PolicySigningKey, error)
}
