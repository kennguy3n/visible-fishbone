package memory

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceCARepository is the memory-backed implementation of the
// per-tenant device certificate authority store.
type DeviceCARepository struct{ s *Store }

func NewDeviceCARepository(s *Store) *DeviceCARepository {
	return &DeviceCARepository{s: s}
}

var _ repository.DeviceCARepository = (*DeviceCARepository)(nil)

func (r *DeviceCARepository) GetCA(ctx context.Context, tenantID uuid.UUID) (repository.DeviceCA, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceCA{}, err
	}
	if tenantID == uuid.Nil {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	ca, ok := r.s.deviceCAs[tenantID]
	if !ok {
		return repository.DeviceCA{}, repository.ErrNotFound
	}
	return ca, nil
}

func (r *DeviceCARepository) CreateCA(ctx context.Context, tenantID uuid.UUID, ca repository.DeviceCA) (repository.DeviceCA, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceCA{}, err
	}
	if tenantID == uuid.Nil {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	if ca.CertPEM == "" || len(ca.PrivateKeySealed) == 0 {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.deviceCAs[tenantID]; ok {
		return repository.DeviceCA{}, repository.ErrConflict
	}
	ca.TenantID = tenantID
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = r.s.clock()
	}
	r.s.deviceCAs[tenantID] = ca
	return ca, nil
}
