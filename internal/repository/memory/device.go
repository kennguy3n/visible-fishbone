package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceRepository is the memory-backed DeviceRepository implementation.
type DeviceRepository struct{ s *Store }

func NewDeviceRepository(s *Store) *DeviceRepository { return &DeviceRepository{s: s} }

var _ repository.DeviceRepository = (*DeviceRepository)(nil)

func (r *DeviceRepository) Create(ctx context.Context, tenantID uuid.UUID, d repository.Device) (repository.Device, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Device{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.Device{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.Device{}, repository.ErrNotFound
	}
	if d.Platform == "" {
		return repository.Device{}, repository.ErrInvalidArgument
	}
	if d.SiteID != nil {
		s, ok := r.s.sites[*d.SiteID]
		if !ok || s.TenantID != tenantID {
			return repository.Device{}, repository.ErrInvalidArgument
		}
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	d.TenantID = tenantID
	if d.Status == "" {
		d.Status = repository.DeviceStatusPending
	}
	now := r.s.clock()
	d.CreatedAt = now
	d.UpdatedAt = now
	r.s.devices[d.ID] = d
	return d, nil
}

func (r *DeviceRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Device, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Device{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	d, ok := r.s.devices[id]
	if !ok || d.TenantID != tenantID {
		return repository.Device{}, repository.ErrNotFound
	}
	return d, nil
}

func (r *DeviceRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.DeviceListFilter, page repository.Page) (repository.PageResult[repository.Device], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Device]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.Device, 0, len(r.s.devices))
	for _, d := range r.s.devices {
		if d.TenantID != tenantID {
			continue
		}
		if filter.Platform != "" && d.Platform != filter.Platform {
			continue
		}
		if filter.Status != "" && d.Status != filter.Status {
			continue
		}
		if filter.SiteID != nil {
			if d.SiteID == nil || *d.SiteID != *filter.SiteID {
				continue
			}
		}
		all = append(all, d)
	}
	sorted := sortByCreatedAtDesc(all,
		func(d repository.Device) time.Time { return d.CreatedAt },
		func(d repository.Device) uuid.UUID { return d.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(d repository.Device) cursor {
		return cursor{CreatedAt: d.CreatedAt, ID: d.ID}
	}), nil
}

func (r *DeviceRepository) UpdateLastSeen(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.devices[id]
	if !ok || existing.TenantID != tenantID {
		return repository.ErrNotFound
	}
	at = at.UTC()
	existing.LastSeenAt = &at
	existing.UpdatedAt = r.s.clock()
	r.s.devices[id] = existing
	return nil
}

func (r *DeviceRepository) UpdatePosture(ctx context.Context, tenantID, id uuid.UUID, posture repository.Posture) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.devices[id]
	if !ok || existing.TenantID != tenantID {
		return repository.ErrNotFound
	}
	existing.Posture = posture
	existing.UpdatedAt = r.s.clock()
	r.s.devices[id] = existing
	return nil
}

func (r *DeviceRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status repository.DeviceStatus) (repository.Device, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Device{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.devices[id]
	if !ok || existing.TenantID != tenantID {
		return repository.Device{}, repository.ErrNotFound
	}
	switch status {
	case repository.DeviceStatusPending, repository.DeviceStatusActive,
		repository.DeviceStatusSuspended, repository.DeviceStatusDeleted:
	default:
		return repository.Device{}, repository.ErrInvalidArgument
	}
	existing.Status = status
	if status == repository.DeviceStatusActive && existing.EnrolledAt == nil {
		t := r.s.clock()
		existing.EnrolledAt = &t
	}
	existing.UpdatedAt = r.s.clock()
	r.s.devices[id] = existing
	return existing, nil
}
