package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// countingResolver is a programmable middleware.MobileDeviceStatusResolver
// that records how many times it was consulted, so a test can assert a
// cache hit avoided the underlying lookup.
type countingResolver struct {
	err   error
	calls int
}

func (c *countingResolver) MobileSessionAllowed(_ context.Context, _ uuid.UUID, _ string) error {
	c.calls++
	return c.err
}

func TestMobileDeviceStatusCache_HitAvoidsUnderlyingLookup(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: nil}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)
	tid, key := uuid.New(), "a2V5"

	for i := 0; i < 5; i++ {
		if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
			t.Fatalf("call %d: unexpected err %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1 (subsequent calls should hit cache)", inner.calls)
	}
}

func TestMobileDeviceStatusCache_CachesRevokedDecision(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: middleware.ErrMobileDeviceRevoked}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)
	tid, key := uuid.New(), "a2V5"

	for i := 0; i < 3; i++ {
		if err := r.MobileSessionAllowed(context.Background(), tid, key); !errors.Is(err, middleware.ErrMobileDeviceRevoked) {
			t.Fatalf("call %d: err = %v, want ErrMobileDeviceRevoked", i, err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1 (revoked decision must be cached)", inner.calls)
	}
}

func TestMobileDeviceStatusCache_ExpiryReResolves(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: nil}
	now := time.Unix(0, 0)
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return now })
	r := cache.Resolver(inner)
	tid, key := uuid.New(), "a2V5"

	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Within TTL: cache hit.
	now = now.Add(4 * time.Second)
	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("within-ttl call: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1 before expiry", inner.calls)
	}
	// Past TTL: miss, re-resolve.
	now = now.Add(2 * time.Second)
	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("post-ttl call: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("inner calls = %d, want 2 after expiry", inner.calls)
	}
}

func TestMobileDeviceStatusCache_InvalidateDropsEntry(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: nil}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)
	tid, key := uuid.New(), "a2V5"

	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("first call: %v", err)
	}
	cache.Invalidate(tid, key)
	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("post-invalidate call: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("inner calls = %d, want 2 (invalidate must force re-resolve)", inner.calls)
	}
}

func TestMobileDeviceStatusCache_InfraErrorNotCached(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: errors.New("db unavailable")}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)
	tid, key := uuid.New(), "a2V5"

	for i := 0; i < 3; i++ {
		if err := r.MobileSessionAllowed(context.Background(), tid, key); err == nil {
			t.Fatalf("call %d: expected infra error", i)
		}
	}
	if inner.calls != 3 {
		t.Fatalf("inner calls = %d, want 3 (infra errors must not be cached)", inner.calls)
	}
}

func TestMobileDeviceStatusCache_PartialIdentityBypassesCache(t *testing.T) {
	t.Parallel()
	inner := &countingResolver{err: nil}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)

	// Missing tenant or key: pass through every time, never cached.
	for i := 0; i < 2; i++ {
		_ = r.MobileSessionAllowed(context.Background(), uuid.Nil, "a2V5")
		_ = r.MobileSessionAllowed(context.Background(), uuid.New(), "")
	}
	if inner.calls != 4 {
		t.Fatalf("inner calls = %d, want 4 (partial identity must bypass cache)", inner.calls)
	}
}

// statusWriteRepo is a minimal DeviceRepository that returns a fixed
// device from status mutations; all other methods are unused.
type statusWriteRepo struct {
	repository.DeviceRepository
	dev repository.Device
	err error
}

func (s statusWriteRepo) UpdateStatus(_ context.Context, _, _ uuid.UUID, status repository.DeviceStatus) (repository.Device, error) {
	d := s.dev
	d.Status = status
	return d, s.err
}

func (s statusWriteRepo) TransitionStatus(_ context.Context, _, _ uuid.UUID, _, to repository.DeviceStatus) (repository.Device, error) {
	d := s.dev
	d.Status = to
	return d, s.err
}

func TestInstrumentRepository_StatusWritesInvalidate(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	const key = "ZGV2aWNlLWtleQ=="
	dev := repository.Device{ID: uuid.New(), TenantID: tid, PublicKeyEd25519: key}

	for _, tc := range []struct {
		name  string
		write func(repo repository.DeviceRepository)
	}{
		{"UpdateStatus", func(repo repository.DeviceRepository) {
			_, _ = repo.UpdateStatus(context.Background(), tid, dev.ID, repository.DeviceStatusSuspended)
		}},
		{"TransitionStatus", func(repo repository.DeviceRepository) {
			_, _ = repo.TransitionStatus(context.Background(), tid, dev.ID, repository.DeviceStatusActive, repository.DeviceStatusSuspended)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inner := &countingResolver{err: nil}
			cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
			r := cache.Resolver(inner)
			repo := cache.InstrumentRepository(statusWriteRepo{dev: dev})

			// Warm the cache.
			if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
				t.Fatalf("warm: %v", err)
			}
			// Admin status change must purge the entry.
			tc.write(repo)
			if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
				t.Fatalf("post-write: %v", err)
			}
			if inner.calls != 2 {
				t.Fatalf("inner calls = %d, want 2 (status write must invalidate cache)", inner.calls)
			}
		})
	}
}

// TestInstrumentRepository_FailedWriteKeepsEntry verifies a status write
// that errors does NOT invalidate (the live status is unchanged, so the
// cached decision is still valid).
func TestInstrumentRepository_FailedWriteKeepsEntry(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	const key = "ZGV2aWNlLWtleQ=="
	dev := repository.Device{ID: uuid.New(), TenantID: tid, PublicKeyEd25519: key}

	inner := &countingResolver{err: nil}
	cache := newMobileDeviceStatusCache(5*time.Second, func() time.Time { return time.Unix(0, 0) })
	r := cache.Resolver(inner)
	repo := cache.InstrumentRepository(statusWriteRepo{dev: dev, err: errors.New("boom")})

	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if _, err := repo.UpdateStatus(context.Background(), tid, dev.ID, repository.DeviceStatusSuspended); err == nil {
		t.Fatal("expected write error")
	}
	if err := r.MobileSessionAllowed(context.Background(), tid, key); err != nil {
		t.Fatalf("post-failed-write: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1 (failed write must not invalidate)", inner.calls)
	}
}
