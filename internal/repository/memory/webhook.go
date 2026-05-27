package memory

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// WebhookEndpointRepository is the memory-backed implementation.
type WebhookEndpointRepository struct{ s *Store }

// NewWebhookEndpointRepository binds a Store.
func NewWebhookEndpointRepository(s *Store) *WebhookEndpointRepository {
	return &WebhookEndpointRepository{s: s}
}

var _ repository.WebhookEndpointRepository = (*WebhookEndpointRepository)(nil)

func (r *WebhookEndpointRepository) Create(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.WebhookEndpoint{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.WebhookEndpoint{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.WebhookEndpoint{}, repository.ErrNotFound
	}
	if ep.URL == "" {
		return repository.WebhookEndpoint{}, repository.ErrInvalidArgument
	}
	if len(ep.SigningSecret) == 0 {
		return repository.WebhookEndpoint{}, repository.ErrInvalidArgument
	}
	if ep.ID == uuid.Nil {
		ep.ID = uuid.New()
	}
	ep.TenantID = tenantID
	now := r.s.clock()
	ep.CreatedAt = now
	ep.UpdatedAt = now
	if ep.Status == "" {
		ep.Status = repository.WebhookEndpointStatusActive
	}
	ep.Events = cloneStrings(ep.Events)
	ep.SigningSecret = cloneBytes(ep.SigningSecret)
	r.s.webhookEndpoints[ep.ID] = ep
	return cloneEndpoint(ep), nil
}

func (r *WebhookEndpointRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookEndpoint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.WebhookEndpoint{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	ep, ok := r.s.webhookEndpoints[id]
	if !ok || ep.TenantID != tenantID {
		return repository.WebhookEndpoint{}, repository.ErrNotFound
	}
	return cloneEndpoint(ep), nil
}

func (r *WebhookEndpointRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookEndpoint], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.WebhookEndpoint]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.WebhookEndpoint, 0, len(r.s.webhookEndpoints))
	for _, ep := range r.s.webhookEndpoints {
		if ep.TenantID != tenantID {
			continue
		}
		all = append(all, cloneEndpoint(ep))
	}
	sorted := sortByCreatedAtDesc(all,
		func(e repository.WebhookEndpoint) time.Time { return e.CreatedAt },
		func(e repository.WebhookEndpoint) uuid.UUID { return e.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(e repository.WebhookEndpoint) cursor {
		return cursor{CreatedAt: e.CreatedAt, ID: e.ID}
	}), nil
}

func (r *WebhookEndpointRepository) Update(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.WebhookEndpoint{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.webhookEndpoints[ep.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.WebhookEndpoint{}, repository.ErrNotFound
	}
	if ep.URL != "" {
		existing.URL = ep.URL
	}
	if ep.Events != nil {
		existing.Events = cloneStrings(ep.Events)
	}
	if ep.Status != "" {
		existing.Status = ep.Status
	}
	if len(ep.SigningSecret) > 0 {
		existing.SigningSecret = cloneBytes(ep.SigningSecret)
	}
	existing.UpdatedAt = r.s.clock()
	r.s.webhookEndpoints[existing.ID] = existing
	return cloneEndpoint(existing), nil
}

func (r *WebhookEndpointRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.webhookEndpoints[id]
	if !ok || existing.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.webhookEndpoints, id)
	return nil
}

// ListActive returns all active endpoints subscribed to at least
// one of the given event types. Ordering is by CreatedAt ASC so
// fan-out is deterministic for tests.
func (r *WebhookEndpointRepository) ListActive(ctx context.Context, tenantID uuid.UUID, eventTypes []string) ([]repository.WebhookEndpoint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(eventTypes))
	for _, e := range eventTypes {
		wanted[e] = struct{}{}
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.WebhookEndpoint, 0)
	for _, ep := range r.s.webhookEndpoints {
		if ep.TenantID != tenantID || ep.Status != repository.WebhookEndpointStatusActive {
			continue
		}
		for _, ev := range ep.Events {
			if _, ok := wanted[ev]; ok {
				out = append(out, cloneEndpoint(ep))
				break
			}
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

// WebhookDeliveryRepository is the memory-backed implementation.
type WebhookDeliveryRepository struct{ s *Store }

// NewWebhookDeliveryRepository binds a Store.
func NewWebhookDeliveryRepository(s *Store) *WebhookDeliveryRepository {
	return &WebhookDeliveryRepository{s: s}
}

var _ repository.WebhookDeliveryRepository = (*WebhookDeliveryRepository)(nil)

func (r *WebhookDeliveryRepository) Create(ctx context.Context, tenantID uuid.UUID, d repository.WebhookDelivery) (repository.WebhookDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.WebhookDelivery{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.WebhookDelivery{}, repository.ErrInvalidArgument
	}
	if d.EndpointID == uuid.Nil {
		return repository.WebhookDelivery{}, repository.ErrInvalidArgument
	}
	ep, ok := r.s.webhookEndpoints[d.EndpointID]
	if !ok || ep.TenantID != tenantID {
		return repository.WebhookDelivery{}, repository.ErrNotFound
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	d.TenantID = tenantID
	now := r.s.clock()
	d.CreatedAt = now
	if d.Status == "" {
		d.Status = repository.WebhookDeliveryStatusPending
	}
	d.Payload = cloneJSON(d.Payload)
	if d.NextRetryAt.IsZero() {
		d.NextRetryAt = now
	}
	r.s.webhookDeliveries[d.ID] = d
	return cloneDelivery(d), nil
}

func (r *WebhookDeliveryRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.WebhookDelivery{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	d, ok := r.s.webhookDeliveries[id]
	if !ok || d.TenantID != tenantID {
		return repository.WebhookDelivery{}, repository.ErrNotFound
	}
	return cloneDelivery(d), nil
}

func (r *WebhookDeliveryRepository) List(ctx context.Context, tenantID uuid.UUID, endpointID *uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookDelivery], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.WebhookDelivery]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.WebhookDelivery, 0, len(r.s.webhookDeliveries))
	for _, d := range r.s.webhookDeliveries {
		if d.TenantID != tenantID {
			continue
		}
		if endpointID != nil && d.EndpointID != *endpointID {
			continue
		}
		all = append(all, cloneDelivery(d))
	}
	sorted := sortByCreatedAtDesc(all,
		func(d repository.WebhookDelivery) time.Time { return d.CreatedAt },
		func(d repository.WebhookDelivery) uuid.UUID { return d.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(d repository.WebhookDelivery) cursor {
		return cursor{CreatedAt: d.CreatedAt, ID: d.ID}
	}), nil
}

func (r *WebhookDeliveryRepository) UpdateStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.WebhookDeliveryStatus,
	attempt int,
	lastErr string,
	responseStatus int,
	nextRetry time.Time,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	d, ok := r.s.webhookDeliveries[id]
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
	r.s.webhookDeliveries[id] = d
	return nil
}

// ListPending returns deliveries due for retry (status=pending and
// next_retry_at <= now). Limit caps the batch size. Ordering is
// NextRetryAt ASC, ID ASC for tie-break.
func (r *WebhookDeliveryRepository) ListPending(ctx context.Context, limit int) ([]repository.WebhookDelivery, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 32
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	now := r.s.clock()
	out := make([]repository.WebhookDelivery, 0)
	for _, d := range r.s.webhookDeliveries {
		if d.Status != repository.WebhookDeliveryStatusPending {
			continue
		}
		if d.NextRetryAt.After(now) {
			continue
		}
		out = append(out, cloneDelivery(d))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NextRetryAt.Equal(out[j].NextRetryAt) {
			return out[i].ID.String() < out[j].ID.String()
		}
		return out[i].NextRetryAt.Before(out[j].NextRetryAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func cloneEndpoint(ep repository.WebhookEndpoint) repository.WebhookEndpoint {
	out := ep
	out.Events = cloneStrings(ep.Events)
	out.SigningSecret = cloneBytes(ep.SigningSecret)
	return out
}

func cloneDelivery(d repository.WebhookDelivery) repository.WebhookDelivery {
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

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
