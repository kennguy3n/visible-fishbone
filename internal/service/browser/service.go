// Package browser implements browser protection policy management
// for the ShieldNet Gateway control plane (Phase 4, Task 43).
//
// Policies control download restriction, upload restriction,
// clipboard control, print control, screenshot prevention, and
// URL category blocking. Each policy carries a set of typed rules,
// a default action, a targeting scope (user/group/site), and an
// enabled flag.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Service implements browser protection policy CRUD.
type Service struct {
	policies repository.BrowserPolicyRepository
	audit    repository.AuditLogRepository
	logger   *slog.Logger
}

// New returns a ready-to-use browser protection service.
func New(
	policies repository.BrowserPolicyRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{policies: policies, audit: audit, logger: logger}
}

// CreatePolicy provisions a new browser protection policy.
func (s *Service) CreatePolicy(
	ctx context.Context,
	tenantID uuid.UUID,
	p repository.BrowserPolicy,
) (repository.BrowserPolicy, error) {
	if p.Name == "" {
		return repository.BrowserPolicy{}, fmt.Errorf("name is required: %w", repository.ErrInvalidArgument)
	}
	if !p.Action.IsValid() {
		return repository.BrowserPolicy{}, fmt.Errorf("invalid action %q: %w", p.Action, repository.ErrInvalidArgument)
	}
	if !p.Scope.IsValid() {
		return repository.BrowserPolicy{}, fmt.Errorf("invalid scope %q: %w", p.Scope, repository.ErrInvalidArgument)
	}
	for i, r := range p.Rules {
		if !r.Type.IsValid() {
			return repository.BrowserPolicy{}, fmt.Errorf("rule[%d]: invalid type %q: %w", i, r.Type, repository.ErrInvalidArgument)
		}
		if !r.Action.IsValid() {
			return repository.BrowserPolicy{}, fmt.Errorf("rule[%d]: invalid action %q: %w", i, r.Action, repository.ErrInvalidArgument)
		}
	}
	created, err := s.policies.Create(ctx, tenantID, p)
	if err != nil {
		return repository.BrowserPolicy{}, err
	}
	s.logAudit(ctx, tenantID, "browser_policy.created", "browser_policy", &created.ID)
	return created, nil
}

// ListPolicies returns a paginated list of browser policies for the tenant.
func (s *Service) ListPolicies(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.BrowserPolicy], error) {
	return s.policies.List(ctx, tenantID, page)
}

// GetPolicy fetches a single browser policy.
func (s *Service) GetPolicy(ctx context.Context, tenantID, id uuid.UUID) (repository.BrowserPolicy, error) {
	return s.policies.Get(ctx, tenantID, id)
}

// UpdatePolicy applies a sparse patch to an existing browser policy.
func (s *Service) UpdatePolicy(
	ctx context.Context,
	tenantID, id uuid.UUID,
	patch repository.BrowserPolicyPatch,
) (repository.BrowserPolicy, error) {
	if patch.Action != nil && !patch.Action.IsValid() {
		return repository.BrowserPolicy{}, fmt.Errorf("invalid action %q: %w", *patch.Action, repository.ErrInvalidArgument)
	}
	if patch.Scope != nil && !patch.Scope.IsValid() {
		return repository.BrowserPolicy{}, fmt.Errorf("invalid scope %q: %w", *patch.Scope, repository.ErrInvalidArgument)
	}
	for i, r := range patch.Rules {
		if !r.Type.IsValid() {
			return repository.BrowserPolicy{}, fmt.Errorf("rule[%d]: invalid type %q: %w", i, r.Type, repository.ErrInvalidArgument)
		}
		if !r.Action.IsValid() {
			return repository.BrowserPolicy{}, fmt.Errorf("rule[%d]: invalid action %q: %w", i, r.Action, repository.ErrInvalidArgument)
		}
	}
	updated, err := s.policies.Update(ctx, tenantID, id, patch)
	if err != nil {
		return repository.BrowserPolicy{}, err
	}
	s.logAudit(ctx, tenantID, "browser_policy.updated", "browser_policy", &updated.ID)
	return updated, nil
}

// DeletePolicy removes a browser policy.
func (s *Service) DeletePolicy(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.policies.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, "browser_policy.deleted", "browser_policy", &id)
	return nil
}

func (s *Service) logAudit(ctx context.Context, tenantID uuid.UUID, action, resourceType string, resourceID *uuid.UUID) {
	if s.audit == nil {
		return
	}
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID:     tenantID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      json.RawMessage(`{}`),
	}); err != nil {
		s.logger.Error("audit log failed", "action", action, "err", err)
	}
}
