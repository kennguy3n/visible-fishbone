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
	Update(ctx context.Context, t Tenant) (Tenant, error)
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

// --- Policy ---------------------------------------------------------------

// PolicyRepository owns policy_graphs + policy_bundles.
type PolicyRepository interface {
	CreateGraph(ctx context.Context, tenantID uuid.UUID, g PolicyGraph) (PolicyGraph, error)
	GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (PolicyGraph, error)
	ListGraphVersions(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[PolicyGraph], error)
	CreateBundle(ctx context.Context, tenantID uuid.UUID, b PolicyBundle) (PolicyBundle, error)
	GetBundle(ctx context.Context, tenantID, id uuid.UUID) (PolicyBundle, error)
	GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target PolicyBundleTarget) (PolicyBundle, error)
}
