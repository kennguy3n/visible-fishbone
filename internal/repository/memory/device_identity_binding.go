package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceIdentityBindingRepository is the memory-backed implementation
// of repository.DeviceIdentityBindingRepository. Tenant isolation is
// enforced by keying on (tenant_id, device_id), mirroring the Postgres
// RLS + unique index.
type DeviceIdentityBindingRepository struct{ s *Store }

// NewDeviceIdentityBindingRepository binds the Store to the interface.
func NewDeviceIdentityBindingRepository(s *Store) *DeviceIdentityBindingRepository {
	return &DeviceIdentityBindingRepository{s: s}
}

var _ repository.DeviceIdentityBindingRepository = (*DeviceIdentityBindingRepository)(nil)

func (r *DeviceIdentityBindingRepository) Upsert(ctx context.Context, tenantID uuid.UUID, b repository.DeviceIdentityBinding) (repository.DeviceIdentityBinding, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceIdentityBinding{}, err
	}
	if tenantID == uuid.Nil || b.DeviceID == uuid.Nil || b.IAMCoreUserID == "" || b.Ed25519PublicKey == "" {
		return repository.DeviceIdentityBinding{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := deviceBindingKey{TenantID: tenantID, DeviceID: b.DeviceID}
	now := r.s.clock()
	b.TenantID = tenantID
	if existing, ok := r.s.deviceIdentityBindings[key]; ok {
		b.ID = existing.ID
		b.CreatedAt = existing.CreatedAt
	} else {
		if b.ID == uuid.Nil {
			b.ID = uuid.New()
		}
		b.CreatedAt = now
	}
	b.UpdatedAt = now
	r.s.deviceIdentityBindings[key] = b
	return b, nil
}

func (r *DeviceIdentityBindingRepository) GetByDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (repository.DeviceIdentityBinding, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceIdentityBinding{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	b, ok := r.s.deviceIdentityBindings[deviceBindingKey{TenantID: tenantID, DeviceID: deviceID}]
	if !ok {
		return repository.DeviceIdentityBinding{}, repository.ErrNotFound
	}
	return b, nil
}

func (r *DeviceIdentityBindingRepository) ListByIAMCoreUser(ctx context.Context, tenantID uuid.UUID, iamCoreUserID string) ([]repository.DeviceIdentityBinding, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []repository.DeviceIdentityBinding
	for key, b := range r.s.deviceIdentityBindings {
		if key.TenantID == tenantID && b.IAMCoreUserID == iamCoreUserID {
			out = append(out, b)
		}
	}
	// Stable order for deterministic tests.
	sort.Slice(out, func(i, j int) bool {
		return out[i].DeviceID.String() < out[j].DeviceID.String()
	})
	return out, nil
}

func (r *DeviceIdentityBindingRepository) DeleteByDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	delete(r.s.deviceIdentityBindings, deviceBindingKey{TenantID: tenantID, DeviceID: deviceID})
	return nil
}
