package memory

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IntegrationConnectorRepository is the memory-backed implementation
// of repository.IntegrationConnectorRepository. The shape deliberately
// mirrors WebhookEndpointRepository — same clone-on-read pattern,
// same (tenant_id, status, event-overlap) filter for ListActive —
// because the dispatcher semantics are identical modulo the
// connector_id foreign key.
type IntegrationConnectorRepository struct{ s *Store }

// NewIntegrationConnectorRepository binds a Store.
func NewIntegrationConnectorRepository(s *Store) *IntegrationConnectorRepository {
	return &IntegrationConnectorRepository{s: s}
}

var _ repository.IntegrationConnectorRepository = (*IntegrationConnectorRepository)(nil)

func (r *IntegrationConnectorRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IntegrationConnector,
) (repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationConnector{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.IntegrationConnector{}, repository.ErrNotFound
	}
	if !c.Type.IsValid() {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	if c.Name == "" {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	// (tenant_id, name) uniqueness — mirrors the migration's
	// UNIQUE index. Surfacing this here as ErrConflict gives the
	// service layer a deterministic 409 instead of an opaque
	// "did the insert happen?" race.
	for _, existing := range r.s.integrationConnectors {
		if existing.TenantID == tenantID && existing.Name == c.Name {
			return repository.IntegrationConnector{}, repository.ErrConflict
		}
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.TenantID = tenantID
	now := r.s.clock()
	c.CreatedAt = now
	c.UpdatedAt = now
	if c.Status == "" {
		c.Status = repository.IntegrationConnectorStatusActive
	}
	if c.LastTestResult == "" {
		c.LastTestResult = repository.IntegrationTestResultNever
	}
	c.EventTypes = cloneStrings(c.EventTypes)
	c.Config = cloneJSON(c.Config)
	c.Secret = cloneJSON(c.Secret)
	r.s.integrationConnectors[c.ID] = c
	return cloneConnector(c), nil
}

func (r *IntegrationConnectorRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationConnector{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.integrationConnectors[id]
	if !ok || c.TenantID != tenantID {
		return repository.IntegrationConnector{}, repository.ErrNotFound
	}
	return cloneConnector(c), nil
}

func (r *IntegrationConnectorRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationConnector], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.IntegrationConnector]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.IntegrationConnector, 0, len(r.s.integrationConnectors))
	for _, c := range r.s.integrationConnectors {
		if c.TenantID != tenantID {
			continue
		}
		all = append(all, cloneConnector(c))
	}
	sorted := sortByCreatedAtDesc(all,
		func(c repository.IntegrationConnector) time.Time { return c.CreatedAt },
		func(c repository.IntegrationConnector) uuid.UUID { return c.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(c repository.IntegrationConnector) cursor {
		return cursor{CreatedAt: c.CreatedAt, ID: c.ID}
	}), nil
}

func (r *IntegrationConnectorRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IntegrationConnector,
) (repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationConnector{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.integrationConnectors[c.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.IntegrationConnector{}, repository.ErrNotFound
	}
	if c.Name != "" && c.Name != existing.Name {
		// Re-check uniqueness on rename. Mirrors the postgres
		// UNIQUE(tenant_id, name) constraint.
		for _, other := range r.s.integrationConnectors {
			if other.ID == existing.ID {
				continue
			}
			if other.TenantID == tenantID && other.Name == c.Name {
				return repository.IntegrationConnector{}, repository.ErrConflict
			}
		}
		existing.Name = c.Name
	}
	if c.Description != "" {
		existing.Description = c.Description
	}
	if c.EventTypes != nil {
		existing.EventTypes = cloneStrings(c.EventTypes)
	}
	if len(c.Config) > 0 {
		existing.Config = cloneJSON(c.Config)
	}
	if len(c.Secret) > 0 {
		existing.Secret = cloneJSON(c.Secret)
	}
	if c.Status != "" {
		existing.Status = c.Status
	}
	existing.UpdatedAt = r.s.clock()
	r.s.integrationConnectors[existing.ID] = existing
	return cloneConnector(existing), nil
}

func (r *IntegrationConnectorRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.integrationConnectors[id]
	if !ok || existing.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.integrationConnectors, id)
	// Cascade matches the migration's ON DELETE CASCADE.
	for did, d := range r.s.integrationDeliveries {
		if d.ConnectorID == id {
			delete(r.s.integrationDeliveries, did)
		}
	}
	return nil
}

func (r *IntegrationConnectorRepository) SetStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.IntegrationConnectorStatus,
) (repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationConnector{}, err
	}
	if status != repository.IntegrationConnectorStatusActive &&
		status != repository.IntegrationConnectorStatusDisabled {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.integrationConnectors[id]
	if !ok || existing.TenantID != tenantID {
		return repository.IntegrationConnector{}, repository.ErrNotFound
	}
	existing.Status = status
	existing.UpdatedAt = r.s.clock()
	r.s.integrationConnectors[existing.ID] = existing
	return cloneConnector(existing), nil
}

func (r *IntegrationConnectorRepository) RecordTestResult(
	ctx context.Context,
	tenantID, id uuid.UUID,
	result repository.IntegrationTestResult,
	at time.Time,
	lastErr string,
) (repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationConnector{}, err
	}
	switch result {
	case repository.IntegrationTestResultSuccess,
		repository.IntegrationTestResultFailure,
		repository.IntegrationTestResultNever:
	default:
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.integrationConnectors[id]
	if !ok || existing.TenantID != tenantID {
		return repository.IntegrationConnector{}, repository.ErrNotFound
	}
	existing.LastTestResult = result
	if at.IsZero() {
		at = r.s.clock()
	}
	t := at
	existing.LastTestAt = &t
	if result == repository.IntegrationTestResultSuccess {
		existing.LastTestError = ""
	} else if result == repository.IntegrationTestResultFailure {
		existing.LastTestError = lastErr
	}
	existing.UpdatedAt = r.s.clock()
	r.s.integrationConnectors[existing.ID] = existing
	return cloneConnector(existing), nil
}

// ListActive returns every active connector for the tenant whose
// EventTypes is empty (subscribe-to-all) or overlaps the supplied
// eventTypes slice. Ordering is CreatedAt ASC, tie-broken by ID,
// matching the webhook dispatcher for determinism.
func (r *IntegrationConnectorRepository) ListActive(
	ctx context.Context,
	tenantID uuid.UUID,
	eventTypes []string,
) ([]repository.IntegrationConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(eventTypes))
	for _, e := range eventTypes {
		wanted[e] = struct{}{}
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.IntegrationConnector, 0)
	for _, c := range r.s.integrationConnectors {
		if c.TenantID != tenantID || c.Status != repository.IntegrationConnectorStatusActive {
			continue
		}
		if len(c.EventTypes) == 0 {
			// Subscribe-to-all.
			out = append(out, cloneConnector(c))
			continue
		}
		matched := false
		for _, e := range c.EventTypes {
			if _, ok := wanted[e]; ok {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, cloneConnector(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() < out[j].ID.String()
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// IntegrationDeliveryRepository is the memory-backed implementation.
type IntegrationDeliveryRepository struct{ s *Store }

// NewIntegrationDeliveryRepository binds a Store.
func NewIntegrationDeliveryRepository(s *Store) *IntegrationDeliveryRepository {
	return &IntegrationDeliveryRepository{s: s}
}

var _ repository.IntegrationDeliveryRepository = (*IntegrationDeliveryRepository)(nil)

func (r *IntegrationDeliveryRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	d repository.IntegrationDelivery,
) (repository.IntegrationDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationDelivery{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.IntegrationDelivery{}, repository.ErrInvalidArgument
	}
	if d.ConnectorID == uuid.Nil {
		return repository.IntegrationDelivery{}, repository.ErrInvalidArgument
	}
	c, ok := r.s.integrationConnectors[d.ConnectorID]
	if !ok || c.TenantID != tenantID {
		return repository.IntegrationDelivery{}, repository.ErrNotFound
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	d.TenantID = tenantID
	now := r.s.clock()
	d.CreatedAt = now
	if d.Status == "" {
		d.Status = repository.IntegrationDeliveryStatusPending
	}
	d.Payload = cloneJSON(d.Payload)
	if d.NextRetryAt.IsZero() {
		d.NextRetryAt = now
	}
	r.s.integrationDeliveries[d.ID] = d
	return cloneIntegrationDelivery(d), nil
}

func (r *IntegrationDeliveryRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IntegrationDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IntegrationDelivery{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	d, ok := r.s.integrationDeliveries[id]
	if !ok || d.TenantID != tenantID {
		return repository.IntegrationDelivery{}, repository.ErrNotFound
	}
	return cloneIntegrationDelivery(d), nil
}

func (r *IntegrationDeliveryRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	connectorID *uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationDelivery], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.IntegrationDelivery]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.IntegrationDelivery, 0, len(r.s.integrationDeliveries))
	for _, d := range r.s.integrationDeliveries {
		if d.TenantID != tenantID {
			continue
		}
		if connectorID != nil && d.ConnectorID != *connectorID {
			continue
		}
		all = append(all, cloneIntegrationDelivery(d))
	}
	sorted := sortByCreatedAtDesc(all,
		func(d repository.IntegrationDelivery) time.Time { return d.CreatedAt },
		func(d repository.IntegrationDelivery) uuid.UUID { return d.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(d repository.IntegrationDelivery) cursor {
		return cursor{CreatedAt: d.CreatedAt, ID: d.ID}
	}), nil
}

func (r *IntegrationDeliveryRepository) UpdateStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.IntegrationDeliveryStatus,
	attempt int,
	lastErr string,
	responseStatus int,
	nextRetry time.Time,
	externalRef string,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	d, ok := r.s.integrationDeliveries[id]
	if !ok || d.TenantID != tenantID {
		return repository.ErrNotFound
	}
	d.Status = status
	d.Attempts = attempt
	d.LastError = lastErr
	d.ResponseStatus = responseStatus
	d.NextRetryAt = nextRetry
	at := r.s.clock()
	d.LastAttemptAt = &at
	if externalRef != "" {
		d.ExternalReference = externalRef
	}
	r.s.integrationDeliveries[id] = d
	return nil
}

// ListPending atomically claims a batch of due-for-retry
// deliveries — the in-memory mirror of the postgres
// FOR UPDATE SKIP LOCKED atomic UPDATE. Two cases produce a
// claim, matching WebhookDeliveryRepository.ListPending:
//
//  1. status=pending AND next_retry_at <= now — the normal
//     due-row case.
//  2. status=processing AND processingTimeout > 0 AND
//     last_attempt_at < now - processingTimeout — the
//     stuck-row reaper.
//
// In both cases the source row is transitioned to 'processing'
// and last_attempt_at is stamped to `now` inside the critical
// section. The returned slice is cloned so the caller can mutate
// freely.
func (r *IntegrationDeliveryRepository) ListPending(
	ctx context.Context,
	limit int,
	processingTimeout time.Duration,
) ([]repository.IntegrationDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 32
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now := r.s.clock()
	candidates := make([]repository.IntegrationDelivery, 0)
	for _, d := range r.s.integrationDeliveries {
		switch d.Status {
		case repository.IntegrationDeliveryStatusPending:
			if d.NextRetryAt.After(now) {
				continue
			}
		case repository.IntegrationDeliveryStatusProcessing:
			if processingTimeout <= 0 {
				continue
			}
			if d.LastAttemptAt == nil {
				continue
			}
			if d.LastAttemptAt.After(now.Add(-processingTimeout)) {
				continue
			}
		default:
			continue
		}
		candidates = append(candidates, d)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].NextRetryAt.Equal(candidates[j].NextRetryAt) {
			return candidates[i].ID.String() < candidates[j].ID.String()
		}
		return candidates[i].NextRetryAt.Before(candidates[j].NextRetryAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]repository.IntegrationDelivery, 0, len(candidates))
	for _, src := range candidates {
		stored, ok := r.s.integrationDeliveries[src.ID]
		if !ok {
			continue
		}
		stored.Status = repository.IntegrationDeliveryStatusProcessing
		t := now
		stored.LastAttemptAt = &t
		r.s.integrationDeliveries[stored.ID] = stored
		out = append(out, cloneIntegrationDelivery(stored))
	}
	return out, nil
}

func cloneConnector(c repository.IntegrationConnector) repository.IntegrationConnector {
	out := c
	out.EventTypes = cloneStrings(c.EventTypes)
	if c.Config != nil {
		out.Config = make(json.RawMessage, len(c.Config))
		copy(out.Config, c.Config)
	}
	if c.Secret != nil {
		out.Secret = make(json.RawMessage, len(c.Secret))
		copy(out.Secret, c.Secret)
	}
	if c.LastTestAt != nil {
		t := *c.LastTestAt
		out.LastTestAt = &t
	}
	return out
}

func cloneIntegrationDelivery(d repository.IntegrationDelivery) repository.IntegrationDelivery {
	out := d
	if d.Payload != nil {
		out.Payload = make(json.RawMessage, len(d.Payload))
		copy(out.Payload, d.Payload)
	}
	if d.LastAttemptAt != nil {
		t := *d.LastAttemptAt
		out.LastAttemptAt = &t
	}
	return out
}
