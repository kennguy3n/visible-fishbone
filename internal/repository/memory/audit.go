package memory

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AuditLogRepository is the memory-backed AuditLogRepository
// implementation. Append-only; no Update / Delete methods.
type AuditLogRepository struct{ s *Store }

func NewAuditLogRepository(s *Store) *AuditLogRepository { return &AuditLogRepository{s: s} }

var _ repository.AuditLogRepository = (*AuditLogRepository)(nil)

func (r *AuditLogRepository) Append(ctx context.Context, tenantID uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AuditEntry{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.AuditEntry{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.AuditEntry{}, repository.ErrNotFound
	}
	if strings.TrimSpace(e.Action) == "" || strings.TrimSpace(e.ResourceType) == "" {
		return repository.AuditEntry{}, repository.ErrInvalidArgument
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	e.TenantID = tenantID
	if e.CreatedAt.IsZero() {
		e.CreatedAt = r.s.clock()
	}
	e.Details = cloneJSON(e.Details)
	r.s.auditEntries[e.ID] = e
	out := e
	out.Details = cloneJSON(e.Details)
	return out, nil
}

func (r *AuditLogRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.AuditFilter, page repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AuditEntry]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.AuditEntry, 0, len(r.s.auditEntries))
	for _, e := range r.s.auditEntries {
		if e.TenantID != tenantID {
			continue
		}
		if filter.ActorID != nil {
			if e.ActorID == nil || *e.ActorID != *filter.ActorID {
				continue
			}
		}
		if filter.ResourceType != "" && e.ResourceType != filter.ResourceType {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.From != nil && e.CreatedAt.Before(*filter.From) {
			continue
		}
		if filter.To != nil && e.CreatedAt.After(*filter.To) {
			continue
		}
		cp := e
		cp.Details = cloneJSON(e.Details)
		all = append(all, cp)
	}
	sorted := sortByCreatedAtDesc(all,
		func(e repository.AuditEntry) time.Time { return e.CreatedAt },
		func(e repository.AuditEntry) uuid.UUID { return e.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(e repository.AuditEntry) cursor {
		return cursor{CreatedAt: e.CreatedAt, ID: e.ID}
	}), nil
}
