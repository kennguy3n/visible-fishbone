// Package audit implements the append-only audit log service.
// Only Append + List operations are exposed; the no-update /
// no-delete invariant is enforced at the service layer (the
// repository layer mirrors the same rule).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Service wraps the AuditLogRepository.
type Service struct {
	log repository.AuditLogRepository
}

// New returns a ready-to-use audit service.
func New(log repository.AuditLogRepository) *Service {
	return &Service{log: log}
}

// Entry mirrors repository.AuditEntry for callers that should not
// have to import the repository package directly.
type Entry struct {
	TenantID     uuid.UUID
	ActorID      *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Details      json.RawMessage
}

// Append appends an audit entry.
func (svc *Service) Append(ctx context.Context, e Entry) (repository.AuditEntry, error) {
	if e.TenantID == uuid.Nil {
		return repository.AuditEntry{}, fmt.Errorf("audit entry tenant_id is required: %w", repository.ErrInvalidArgument)
	}
	if e.Action == "" {
		return repository.AuditEntry{}, fmt.Errorf("audit entry action is required: %w", repository.ErrInvalidArgument)
	}
	if e.ResourceType == "" {
		return repository.AuditEntry{}, fmt.Errorf("audit entry resource_type is required: %w", repository.ErrInvalidArgument)
	}
	if len(e.Details) == 0 {
		e.Details = json.RawMessage(`{}`)
	}
	return svc.log.Append(ctx, e.TenantID, repository.AuditEntry{
		ActorID:      e.ActorID,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Details:      e.Details,
	})
}

// ListFilter is the service-layer surface of repository.AuditFilter.
type ListFilter struct {
	ActorID      *uuid.UUID
	ResourceType string
	Action       string
	From         *time.Time
	To           *time.Time
}

// List returns a cursor-paginated list of audit entries.
func (svc *Service) List(
	ctx context.Context,
	tenantID uuid.UUID,
	filter ListFilter,
	page repository.Page,
) (repository.PageResult[repository.AuditEntry], error) {
	return svc.log.List(ctx, tenantID, repository.AuditFilter{
		ActorID:      filter.ActorID,
		ResourceType: filter.ResourceType,
		Action:       filter.Action,
		From:         filter.From,
		To:           filter.To,
	}, page)
}
