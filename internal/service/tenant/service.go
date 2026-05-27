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

// Update applies a partial update to the tenant's mutable fields
// (name, region, tier, settings). Empty strings in the input are
// treated as "no change" by the repository layer.
func (svc *Service) Update(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if t.ID == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("tenant ID is required: %w", repository.ErrInvalidArgument)
	}
	updated, err := svc.tenants.Update(ctx, t)
	if err != nil {
		return repository.Tenant{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, updated.ID, nil, "tenant.updated", "tenant", &updated.ID, nil))
	return updated, nil
}

// Suspend transitions a tenant from active to suspended. Only
// active tenants may be suspended; attempting to suspend a deleted
// or already-suspended tenant returns ErrForbidden.
func (svc *Service) Suspend(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	current, err := svc.tenants.Get(ctx, id)
	if err != nil {
		return repository.Tenant{}, err
	}
	if current.Status != repository.TenantStatusActive {
		return repository.Tenant{}, fmt.Errorf(
			"cannot suspend tenant with status %q (must be %q): %w",
			current.Status, repository.TenantStatusActive, repository.ErrForbidden,
		)
	}
	updated, err := svc.tenants.UpdateStatus(ctx, id, repository.TenantStatusSuspended)
	if err != nil {
		return repository.Tenant{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, id, nil, "tenant.suspended", "tenant", &id, nil))
	return updated, nil
}

// Delete soft-deletes a tenant (status -> deleted, deleted_at set).
// A tenant that is already deleted returns ErrForbidden to prevent
// re-deletion or un-deletion via status change.
func (svc *Service) Delete(ctx context.Context, id uuid.UUID) error {
	current, err := svc.tenants.Get(ctx, id)
	if err != nil {
		return err
	}
	if current.Status == repository.TenantStatusDeleted {
		return fmt.Errorf("tenant already deleted: %w", repository.ErrForbidden)
	}
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
