package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- PlaybookRepository ---------------------------------------------------

// PlaybookRepository is the memory-backed PlaybookRepository.
type PlaybookRepository struct{ s *Store }

// NewPlaybookRepository wires a fresh repo over the shared Store.
func NewPlaybookRepository(s *Store) *PlaybookRepository {
	return &PlaybookRepository{s: s}
}

var _ repository.PlaybookRepository = (*PlaybookRepository)(nil)

func clonePlaybook(p repository.Playbook) repository.Playbook {
	out := p
	out.Steps = cloneJSON(p.Steps)
	return out
}

func (r *PlaybookRepository) Create(ctx context.Context, tenantID uuid.UUID, p repository.Playbook) (repository.Playbook, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Playbook{}, err
	}
	if tenantID == uuid.Nil || p.Name == "" {
		return repository.Playbook{}, repository.ErrInvalidArgument
	}

	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	for _, existing := range r.s.playbooks {
		if existing.TenantID == tenantID && existing.Name == p.Name {
			return repository.Playbook{}, repository.ErrConflict
		}
	}

	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.TenantID = tenantID
	now := r.s.clock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if len(p.Steps) == 0 {
		p.Steps = []byte(`[]`)
	}
	p.Steps = cloneJSON(p.Steps)
	r.s.playbooks[p.ID] = p

	return clonePlaybook(p), nil
}

func (r *PlaybookRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Playbook, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Playbook{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	p, ok := r.s.playbooks[id]
	if !ok || p.TenantID != tenantID {
		return repository.Playbook{}, repository.ErrNotFound
	}
	return clonePlaybook(p), nil
}

func (r *PlaybookRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Playbook], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Playbook]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var all []repository.Playbook
	for _, p := range r.s.playbooks {
		if p.TenantID == tenantID {
			all = append(all, clonePlaybook(p))
		}
	}

	sorted := sortByCreatedAtDesc(all,
		func(p repository.Playbook) time.Time { return p.CreatedAt },
		func(p repository.Playbook) uuid.UUID { return p.ID },
		page.Normalize().Order,
	)

	return paginate(sorted, page, func(p repository.Playbook) cursor {
		return cursor{CreatedAt: p.CreatedAt, ID: p.ID}
	}), nil
}

func (r *PlaybookRepository) Update(ctx context.Context, tenantID, id uuid.UUID, patch repository.PlaybookPatch) (repository.Playbook, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Playbook{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	p, ok := r.s.playbooks[id]
	if !ok || p.TenantID != tenantID {
		return repository.Playbook{}, repository.ErrNotFound
	}

	if patch.Name != nil {
		if *patch.Name == "" {
			return repository.Playbook{}, repository.ErrInvalidArgument
		}
		for _, existing := range r.s.playbooks {
			if existing.TenantID == tenantID && existing.Name == *patch.Name && existing.ID != id {
				return repository.Playbook{}, repository.ErrConflict
			}
		}
		p.Name = *patch.Name
	}
	if patch.Description != nil {
		p.Description = *patch.Description
	}
	if patch.TriggerCondition != nil {
		p.TriggerCondition = *patch.TriggerCondition
	}
	if patch.Steps != nil {
		p.Steps = cloneJSON(*patch.Steps)
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	p.UpdatedAt = r.s.clock()
	r.s.playbooks[id] = p

	return clonePlaybook(p), nil
}

func (r *PlaybookRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	p, ok := r.s.playbooks[id]
	if !ok || p.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.playbooks, id)
	return nil
}

func (r *PlaybookRepository) ListByTrigger(ctx context.Context, tenantID uuid.UUID, triggerType string) ([]repository.Playbook, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var result []repository.Playbook
	for _, p := range r.s.playbooks {
		if p.TenantID == tenantID && p.Enabled && p.TriggerCondition == triggerType {
			result = append(result, clonePlaybook(p))
		}
	}
	return result, nil
}

// --- PlaybookExecutionRepository ------------------------------------------

// PlaybookExecutionRepository is the memory-backed PlaybookExecutionRepository.
type PlaybookExecutionRepository struct{ s *Store }

// NewPlaybookExecutionRepository wires a fresh repo over the shared Store.
func NewPlaybookExecutionRepository(s *Store) *PlaybookExecutionRepository {
	return &PlaybookExecutionRepository{s: s}
}

var _ repository.PlaybookExecutionRepository = (*PlaybookExecutionRepository)(nil)

func cloneExecution(e repository.PlaybookExecution) repository.PlaybookExecution {
	out := e
	out.TriggerEvent = cloneJSON(e.TriggerEvent)
	if e.CompletedAt != nil {
		v := *e.CompletedAt
		out.CompletedAt = &v
	}
	return out
}

func (r *PlaybookExecutionRepository) Create(ctx context.Context, tenantID uuid.UUID, e repository.PlaybookExecution) (repository.PlaybookExecution, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PlaybookExecution{}, err
	}
	if tenantID == uuid.Nil {
		return repository.PlaybookExecution{}, repository.ErrInvalidArgument
	}

	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	e.TenantID = tenantID
	now := r.s.clock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.StartedAt.IsZero() {
		e.StartedAt = now
	}
	if e.Status == "" {
		e.Status = "pending"
	}
	if len(e.TriggerEvent) == 0 {
		e.TriggerEvent = []byte(`{}`)
	}
	e.TriggerEvent = cloneJSON(e.TriggerEvent)
	r.s.playbookExecutions[e.ID] = e

	return cloneExecution(e), nil
}

func (r *PlaybookExecutionRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PlaybookExecution, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PlaybookExecution{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	e, ok := r.s.playbookExecutions[id]
	if !ok || e.TenantID != tenantID {
		return repository.PlaybookExecution{}, repository.ErrNotFound
	}
	return cloneExecution(e), nil
}

func (r *PlaybookExecutionRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PlaybookExecution], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.PlaybookExecution]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var all []repository.PlaybookExecution
	for _, e := range r.s.playbookExecutions {
		if e.TenantID == tenantID {
			all = append(all, cloneExecution(e))
		}
	}

	sorted := sortByCreatedAtDesc(all,
		func(e repository.PlaybookExecution) time.Time { return e.CreatedAt },
		func(e repository.PlaybookExecution) uuid.UUID { return e.ID },
		page.Normalize().Order,
	)

	return paginate(sorted, page, func(e repository.PlaybookExecution) cursor {
		return cursor{CreatedAt: e.CreatedAt, ID: e.ID}
	}), nil
}

func (r *PlaybookExecutionRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.playbookExecutions[id]
	if !ok || e.TenantID != tenantID {
		return repository.ErrNotFound
	}
	e.Status = status
	if status == "completed" || status == "failed" || status == "rolled_back" {
		now := r.s.clock()
		e.CompletedAt = &now
	}
	r.s.playbookExecutions[id] = e
	return nil
}

func (r *PlaybookExecutionRepository) AddStepResult(ctx context.Context, tenantID, executionID uuid.UUID, sr repository.StepResult) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.playbookExecutions[executionID]; !ok {
		return repository.ErrNotFound
	}
	if sr.ID == uuid.Nil {
		sr.ID = uuid.New()
	}
	sr.TenantID = tenantID
	sr.ExecutionID = executionID
	sr.Output = cloneJSON(sr.Output)
	r.s.playbookStepResults[sr.ID] = sr
	return nil
}

// --- PlaybookApprovalRepository -------------------------------------------

// PlaybookApprovalRepository is the memory-backed PlaybookApprovalRepository.
type PlaybookApprovalRepository struct{ s *Store }

// NewPlaybookApprovalRepository wires a fresh repo over the shared Store.
func NewPlaybookApprovalRepository(s *Store) *PlaybookApprovalRepository {
	return &PlaybookApprovalRepository{s: s}
}

var _ repository.PlaybookApprovalRepository = (*PlaybookApprovalRepository)(nil)

func cloneApproval(a repository.PlaybookApproval) repository.PlaybookApproval {
	out := a
	if a.ApproverID != nil {
		v := *a.ApproverID
		out.ApproverID = &v
	}
	if a.DecidedAt != nil {
		v := *a.DecidedAt
		out.DecidedAt = &v
	}
	return out
}

func (r *PlaybookApprovalRepository) Create(ctx context.Context, tenantID uuid.UUID, a repository.PlaybookApproval) (repository.PlaybookApproval, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PlaybookApproval{}, err
	}
	if tenantID == uuid.Nil {
		return repository.PlaybookApproval{}, repository.ErrInvalidArgument
	}

	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	a.TenantID = tenantID
	now := r.s.clock()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	if a.Status == "" {
		a.Status = "pending"
	}
	r.s.playbookApprovals[a.ID] = a

	return cloneApproval(a), nil
}

func (r *PlaybookApprovalRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PlaybookApproval, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PlaybookApproval{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	a, ok := r.s.playbookApprovals[id]
	if !ok || a.TenantID != tenantID {
		return repository.PlaybookApproval{}, repository.ErrNotFound
	}
	return cloneApproval(a), nil
}

func (r *PlaybookApprovalRepository) ListPending(ctx context.Context, tenantID uuid.UUID) ([]repository.PlaybookApproval, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var result []repository.PlaybookApproval
	for _, a := range r.s.playbookApprovals {
		if a.TenantID == tenantID && a.Status == "pending" {
			result = append(result, cloneApproval(a))
		}
	}
	return result, nil
}

func (r *PlaybookApprovalRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string, approverID *uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.playbookApprovals[id]
	if !ok || a.TenantID != tenantID {
		return repository.ErrNotFound
	}
	a.Status = status
	if approverID != nil {
		v := *approverID
		a.ApproverID = &v
	}
	now := r.s.clock()
	a.DecidedAt = &now
	r.s.playbookApprovals[id] = a
	return nil
}

func (r *PlaybookApprovalRepository) ExpireOld(ctx context.Context, before time.Time) (int, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return 0, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	count := 0
	for id, a := range r.s.playbookApprovals {
		if a.Status == "pending" && a.ExpiresAt.Before(before) {
			a.Status = "expired"
			now := r.s.clock()
			a.DecidedAt = &now
			r.s.playbookApprovals[id] = a
			count++
		}
	}
	return count, nil
}
