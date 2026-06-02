package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// deviceEnrollmentKey is the composite key for device_enrollments.
type deviceEnrollmentKey struct {
	DeviceID uuid.UUID
	TenantID uuid.UUID
}

// DeviceEnrollmentRepository is the memory-backed implementation.
type DeviceEnrollmentRepository struct{ s *Store }

func NewDeviceEnrollmentRepository(s *Store) *DeviceEnrollmentRepository {
	return &DeviceEnrollmentRepository{s: s}
}

var _ repository.DeviceEnrollmentRepository = (*DeviceEnrollmentRepository)(nil)

func (r *DeviceEnrollmentRepository) CreateEnrollment(ctx context.Context, tenantID uuid.UUID, e repository.DeviceEnrollment) (repository.DeviceEnrollment, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceEnrollment{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.DeviceEnrollment{}, repository.ErrInvalidArgument
	}
	key := deviceEnrollmentKey{DeviceID: e.DeviceID, TenantID: tenantID}
	if existing, ok := r.s.deviceEnrollments[key]; ok {
		if existing.Status != repository.EnrollmentStatusRevoked {
			return repository.DeviceEnrollment{}, repository.ErrConflict
		}
	}
	e.TenantID = tenantID
	if e.EnrolledAt.IsZero() {
		e.EnrolledAt = r.s.clock()
	}
	r.s.deviceEnrollments[key] = e
	return e, nil
}

func (r *DeviceEnrollmentRepository) GetEnrollment(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID) (repository.DeviceEnrollment, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceEnrollment{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	key := deviceEnrollmentKey{DeviceID: deviceID, TenantID: tenantID}
	e, ok := r.s.deviceEnrollments[key]
	if !ok {
		return repository.DeviceEnrollment{}, repository.ErrNotFound
	}
	return e, nil
}

func (r *DeviceEnrollmentRepository) UpdateEnrollmentStatus(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, status repository.EnrollmentStatus) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := deviceEnrollmentKey{DeviceID: deviceID, TenantID: tenantID}
	e, ok := r.s.deviceEnrollments[key]
	if !ok {
		return repository.ErrNotFound
	}
	e.Status = status
	if status == repository.EnrollmentStatusRevoked {
		now := r.s.clock()
		e.RevokedAt = &now
	}
	r.s.deviceEnrollments[key] = e
	return nil
}

func (r *DeviceEnrollmentRepository) UpdateLastCertIssuedAt(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, at time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := deviceEnrollmentKey{DeviceID: deviceID, TenantID: tenantID}
	e, ok := r.s.deviceEnrollments[key]
	if !ok {
		return repository.ErrNotFound
	}
	at = at.UTC()
	e.LastCertIssuedAt = &at
	r.s.deviceEnrollments[key] = e
	return nil
}

func (r *DeviceEnrollmentRepository) CreateCertificate(ctx context.Context, tenantID uuid.UUID, c repository.DeviceCertificate) (repository.DeviceCertificate, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DeviceCertificate{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.TenantID = tenantID
	r.s.deviceCertificates[c.ID] = c
	return c, nil
}

func (r *DeviceEnrollmentRepository) RevokeAllCertificates(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, at time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	at = at.UTC()
	for id, c := range r.s.deviceCertificates {
		if c.TenantID == tenantID && c.DeviceID == deviceID && c.RevokedAt == nil {
			c.RevokedAt = &at
			r.s.deviceCertificates[id] = c
		}
	}
	return nil
}
