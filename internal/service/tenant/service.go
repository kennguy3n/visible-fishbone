// Package tenant implements the business logic for multi-tenant
// lifecycle management. It orchestrates the TenantRepository (CRUD)
// and the AuditLogRepository (every mutation is audit-logged).
//
// Slug derivation mirrors sn360-security-platform/services/
// tenant-controller's DeriveSlug: lowercase, collapse non-alnum
// runs into single hyphens, trim leading/trailing hyphens, cap at
// 63 bytes (DNS-label compat).
package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// slugAlnumRun matches runs of non-lowercase-alphanumeric chars.
var slugAlnumRun = regexp.MustCompile(`[^a-z0-9]+`)

// slugFormat validates a caller-supplied slug (DNS-label-safe).
var slugFormat = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

const slugMaxLen = 63

// Service implements tenant lifecycle operations.
type Service struct {
	tenants repository.TenantRepository
	audit   repository.AuditLogRepository
}

// New returns a ready-to-use tenant service.
func New(tenants repository.TenantRepository, audit repository.AuditLogRepository) *Service {
	return &Service{tenants: tenants, audit: audit}
}

// DeriveSlug projects a free-form name into a URL-safe slug.
// Mirrors sn360-security-platform DeriveSlug (lowercase, collapse
// non-alnum runs to hyphens, trim, cap at 63 bytes).
func DeriveSlug(name string) string {
	s := strings.Trim(slugAlnumRun.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > slugMaxLen {
		s = strings.TrimRight(s[:slugMaxLen], "-")
	}
	return s
}

// IsValidSlug reports whether s is a well-formed slug: 1–63 bytes,
// lowercase alphanumeric + hyphens, no leading/trailing/consecutive
// hyphens.
func IsValidSlug(s string) bool {
	if s == "" || len(s) > slugMaxLen || strings.Contains(s, "--") {
		return false
	}
	return slugFormat.MatchString(s)
}

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
		t.Slug = DeriveSlug(t.Name)
		if t.Slug == "" {
			t.Slug = "tenant-" + uuid.NewString()[:8]
		}
	}
	if !IsValidSlug(t.Slug) {
		return repository.Tenant{}, fmt.Errorf("invalid slug %q: %w", t.Slug, repository.ErrInvalidArgument)
	}
	t.Status = repository.TenantStatusActive

	created, err := svc.tenants.Create(ctx, t)
	if err != nil {
		return repository.Tenant{}, err
	}
	_ = svc.appendAudit(ctx, created.ID, nil, "tenant.created", "tenant", &created.ID, nil)
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
	_ = svc.appendAudit(ctx, updated.ID, nil, "tenant.updated", "tenant", &updated.ID, nil)
	return updated, nil
}

// Suspend transitions a tenant from active to suspended.
func (svc *Service) Suspend(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	updated, err := svc.tenants.UpdateStatus(ctx, id, repository.TenantStatusSuspended)
	if err != nil {
		return repository.Tenant{}, err
	}
	_ = svc.appendAudit(ctx, id, nil, "tenant.suspended", "tenant", &id, nil)
	return updated, nil
}

// Delete soft-deletes a tenant (status → deleted, deleted_at set).
func (svc *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := svc.tenants.Delete(ctx, id); err != nil {
		return err
	}
	_ = svc.appendAudit(ctx, id, nil, "tenant.deleted", "tenant", &id, nil)
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
