package policytemplates

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates/ptmodel"
)

// Sentinel errors. They alias the shared repository errors so callers
// (and the HTTP layer) can errors.Is them uniformly regardless of
// whether the error originated here or in a repository implementation.
var (
	// ErrNotFound is returned when a tenant has no applied baseline.
	ErrNotFound = repository.ErrNotFound
	// errInvalidArgument is returned for an unknown industry/country
	// or other malformed input.
	errInvalidArgument = repository.ErrInvalidArgument
)

// CatalogRow and AppliedTemplate are the persistence DTOs. They live
// in the dependency-free ptmodel leaf package (so repository
// implementations can reference them without importing this service
// package and forming an import cycle); these aliases keep them
// ergonomically available as policytemplates.CatalogRow /
// policytemplates.AppliedTemplate throughout the service.
type (
	CatalogRow      = ptmodel.CatalogRow
	AppliedTemplate = ptmodel.AppliedTemplate
)

// Repository is the persistence boundary this package needs. It is
// declared here (rather than in internal/repository) so the package is
// self-contained; concrete implementations live in NEW files in the
// memory and postgres repository packages and satisfy this interface
// structurally via the ptmodel DTOs.
//
// The global catalog methods (UpsertCatalog/ListCatalog) operate on
// the shared policy_templates table and run in a system-role
// transaction. The per-tenant methods are RLS-scoped to tenantID.
type Repository interface {
	// UpsertCatalog idempotently writes the catalog definitions to the
	// global table. Rows whose ContentHash is unchanged are left
	// untouched (their UpdatedAt is preserved).
	UpsertCatalog(ctx context.Context, rows []CatalogRow) error
	// ListCatalog returns every persisted catalog row, sorted by id.
	ListCatalog(ctx context.Context) ([]CatalogRow, error)

	// GetApplied returns a tenant's current applied baseline, or
	// ErrNotFound when the tenant has not applied one.
	GetApplied(ctx context.Context, tenantID uuid.UUID) (AppliedTemplate, error)
	// UpsertApplied inserts or replaces a tenant's applied baseline
	// (keyed on tenant_id) and returns the stored row.
	UpsertApplied(ctx context.Context, applied AppliedTemplate) (AppliedTemplate, error)
}
