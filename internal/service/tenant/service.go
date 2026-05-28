// Package tenant implements the business logic for multi-tenant
// lifecycle management. It orchestrates the TenantRepository (CRUD)
// and the AuditLogRepository (every mutation is audit-logged).
//
// Slug derivation is delegated to the shared internal/slug package
// that mirrors sn360-security-platform's DeriveSlug convention.
package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/slug"
)

// Service implements tenant lifecycle operations.
type Service struct {
	tenants repository.TenantRepository
	audit   repository.AuditLogRepository
	logger  *slog.Logger
}

// New returns a ready-to-use tenant service.
func New(tenants repository.TenantRepository, audit repository.AuditLogRepository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{tenants: tenants, audit: audit, logger: logger}
}

// DeriveSlug projects a free-form name into a URL-safe slug.
// Thin wrapper around slug.Derive for backwards compatibility.
func DeriveSlug(name string) string { return slug.Derive(name) }

// IsValidSlug reports whether s is a well-formed slug.
// Thin wrapper around slug.IsValid for backwards compatibility.
func IsValidSlug(s string) bool { return slug.IsValid(s) }

// Create provisions a new tenant. If the caller omits a slug, one is
// derived from the name. Status is forced to "active" regardless of
// the input. An audit entry is appended on success.
func (svc *Service) Create(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if t.Name == "" {
		return repository.Tenant{}, fmt.Errorf("tenant name is required: %w", repository.ErrInvalidArgument)
	}
	if t.Tier == "" {
		t.Tier = repository.TenantTierStarter
	}
	if t.Slug == "" {
		t.Slug = slug.Derive(t.Name)
		if t.Slug == "" {
			t.Slug = "tenant-" + uuid.NewString()[:8]
		}
	}
	if !slug.IsValid(t.Slug) {
		return repository.Tenant{}, fmt.Errorf("invalid slug %q: %w", t.Slug, repository.ErrInvalidArgument)
	}
	t.Status = repository.TenantStatusActive

	created, err := svc.tenants.Create(ctx, t)
	if err != nil {
		return repository.Tenant{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, created.ID, nil, "tenant.created", "tenant", &created.ID, nil))
	return created, nil
}

// Get retrieves a tenant by primary key.
func (svc *Service) Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	return svc.tenants.Get(ctx, id)
}

// GetBySlug retrieves a tenant by its unique slug.
func (svc *Service) GetBySlug(ctx context.Context, slug string) (repository.Tenant, error) {
	return svc.tenants.GetBySlug(ctx, slug)
}

// List returns a cursor-paginated list of tenants.
func (svc *Service) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error) {
	return svc.tenants.List(ctx, page)
}

// Update applies a sparse patch to the tenant's mutable fields
// (name, region, tier, settings). See repository.TenantPatch for
// the per-field semantics — in short: nil pointer leaves the
// column untouched, non-nil pointer applies the value including
// the zero value, which is how operators clear optional fields
// like Region.
func (svc *Service) Update(ctx context.Context, id uuid.UUID, patch repository.TenantPatch) (repository.Tenant, error) {
	if id == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("tenant ID is required: %w", repository.ErrInvalidArgument)
	}
	updated, err := svc.tenants.Update(ctx, id, patch)
	if err != nil {
		return repository.Tenant{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, updated.ID, nil, "tenant.updated", "tenant", &updated.ID, nil))
	return updated, nil
}

// Suspend atomically transitions a tenant from active to suspended.
// Returns ErrForbidden (wrapped from the repository) if the tenant
// is not currently active. The state check and the status update
// happen in a single repository call to prevent TOCTOU races where
// a concurrent Suspend/Delete could change the status between a
// pre-flight Get and the UpdateStatus.
func (svc *Service) Suspend(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	updated, err := svc.tenants.TransitionStatus(ctx, id,
		repository.TenantStatusActive, repository.TenantStatusSuspended)
	if err != nil {
		return repository.Tenant{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, id, nil, "tenant.suspended", "tenant", &id, nil))
	return updated, nil
}

// Delete soft-deletes a tenant (status -> deleted, deleted_at set).
// The repository's Delete enforces atomically that the tenant is
// not already deleted, returning ErrForbidden otherwise. There is
// no TOCTOU window between a status read and the delete because the
// precondition lives inside the WHERE clause.
func (svc *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := svc.tenants.Delete(ctx, id); err != nil {
		return err
	}
	svc.logAuditErr(svc.appendAudit(ctx, id, nil, "tenant.deleted", "tenant", &id, nil))
	return nil
}

func (svc *Service) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	// Stamp the acting API-key ID into details when the request
	// was authenticated via API key. actor_id (a *user* UUID) is
	// NULL on API-key paths because keys are machine identities;
	// the enrichment preserves machine-actor attribution for
	// forensics without overloading actor_id's user-UUID
	// semantics.
	details = middleware.EnrichAuditDetails(ctx, details)
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

func (svc *Service) logAuditErr(err error) {
	if err != nil {
		svc.logger.Warn("tenant: audit append failed", slog.Any("error", err))
	}
}
