package handler

// mobile_device_cache.go adds a short-TTL cache in front of the
// per-request mobile device-status lookup that the auth middleware
// performs (middleware.Auth → MobileDeviceStatusResolver). Without it
// every mobile-authenticated request costs one GetByPublicKey round
// trip; at fleet scale (many devices × frequent posture reports) that
// is a meaningful, repetitive DB load. The cache keeps the kill-switch
// effectively immediate by invalidating an entry the moment a device's
// status changes through the repository (suspend / delete / reactivate),
// so a just-suspended device is refused on its very next request rather
// than after the TTL.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultMobileDeviceStatusTTL is the cache lifetime applied to a
// mobile device-status decision. It is deliberately short so that, even
// absent an explicit invalidation, a stale "allowed" decision cannot
// outlive the window by more than this much.
const DefaultMobileDeviceStatusTTL = 5 * time.Second

// mobileDeviceStatusSweepThreshold bounds memory: once the map grows
// past this many entries a store opportunistically drops expired ones,
// so devices that appear once and never again do not accumulate.
const mobileDeviceStatusSweepThreshold = 1024

// deviceStatusKey identifies a cached decision. The device key is unique
// within a tenant, so the (tenant, key) tuple is the natural identity.
type deviceStatusKey struct {
	tenantID  uuid.UUID
	deviceKey string
}

// deviceStatusEntry is a cached revocation decision with its expiry. A
// nil resolver error caches as revoked=false; ErrMobileDeviceRevoked
// caches as revoked=true. Infrastructure errors are never cached (the
// middleware fails open on them and must re-evaluate next time).
type deviceStatusEntry struct {
	revoked   bool
	expiresAt time.Time
}

// MobileDeviceStatusCache holds short-lived mobile device-status
// decisions shared between the caching resolver (read path) and the
// repository decorator (invalidation path). It is safe for concurrent
// use.
type MobileDeviceStatusCache struct {
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	data map[deviceStatusKey]deviceStatusEntry
}

// NewMobileDeviceStatusCache builds a cache with the given TTL, using
// the wall clock. A non-positive TTL falls back to the default.
func NewMobileDeviceStatusCache(ttl time.Duration) *MobileDeviceStatusCache {
	return newMobileDeviceStatusCache(ttl, time.Now)
}

func newMobileDeviceStatusCache(ttl time.Duration, now func() time.Time) *MobileDeviceStatusCache {
	if ttl <= 0 {
		ttl = DefaultMobileDeviceStatusTTL
	}
	if now == nil {
		now = time.Now
	}
	return &MobileDeviceStatusCache{
		ttl:  ttl,
		now:  now,
		data: make(map[deviceStatusKey]deviceStatusEntry),
	}
}

// lookup returns the cached revocation decision when a fresh entry
// exists. An expired entry is treated as a miss (and dropped).
func (c *MobileDeviceStatusCache) lookup(k deviceStatusKey) (revoked, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.data[k]
	if !found {
		return false, false
	}
	if !c.now().Before(e.expiresAt) {
		delete(c.data, k)
		return false, false
	}
	return e.revoked, true
}

// store records a definitive revocation decision with a fresh TTL.
func (c *MobileDeviceStatusCache) store(k deviceStatusKey, revoked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= mobileDeviceStatusSweepThreshold {
		c.sweepLocked()
	}
	c.data[k] = deviceStatusEntry{revoked: revoked, expiresAt: c.now().Add(c.ttl)}
}

// sweepLocked drops expired entries. The caller must hold c.mu.
func (c *MobileDeviceStatusCache) sweepLocked() {
	now := c.now()
	for k, e := range c.data {
		if !now.Before(e.expiresAt) {
			delete(c.data, k)
		}
	}
}

// Invalidate drops any cached decision for (tenantID, deviceKey) so the
// next request re-resolves the live status. Called whenever a device's
// status changes, keeping the kill-switch immediate.
func (c *MobileDeviceStatusCache) Invalidate(tenantID uuid.UUID, deviceKey string) {
	if tenantID == uuid.Nil || deviceKey == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, deviceStatusKey{tenantID: tenantID, deviceKey: deviceKey})
}

// Resolver wraps an underlying MobileDeviceStatusResolver with this
// cache, returning a resolver suitable for middleware.WithMobileDeviceStatus.
func (c *MobileDeviceStatusCache) Resolver(inner middleware.MobileDeviceStatusResolver) middleware.MobileDeviceStatusResolver {
	return cachingMobileDeviceStatusResolver{inner: inner, cache: c}
}

// InstrumentRepository wraps a DeviceRepository so that every status
// mutation (UpdateStatus / TransitionStatus) invalidates the matching
// cache entry. Decorating the repository — rather than each caller —
// guarantees that any present or future status-change path keeps the
// kill-switch immediate without coupling those callers to the cache.
func (c *MobileDeviceStatusCache) InstrumentRepository(inner repository.DeviceRepository) repository.DeviceRepository {
	return cacheInvalidatingDeviceRepo{DeviceRepository: inner, cache: c}
}

// cachingMobileDeviceStatusResolver short-circuits the per-request
// device-status lookup with a cached decision when one is fresh.
type cachingMobileDeviceStatusResolver struct {
	inner middleware.MobileDeviceStatusResolver
	cache *MobileDeviceStatusCache
}

// MobileSessionAllowed serves a fresh cached decision when available,
// otherwise consults the underlying resolver and caches only its
// definitive outcomes. Infrastructure errors are passed through
// uncached so the middleware's fail-open re-evaluates next time.
func (r cachingMobileDeviceStatusResolver) MobileSessionAllowed(ctx context.Context, tenantID uuid.UUID, deviceKey string) error {
	if tenantID == uuid.Nil || deviceKey == "" {
		return r.inner.MobileSessionAllowed(ctx, tenantID, deviceKey)
	}
	k := deviceStatusKey{tenantID: tenantID, deviceKey: deviceKey}
	if revoked, ok := r.cache.lookup(k); ok {
		if revoked {
			return middleware.ErrMobileDeviceRevoked
		}
		return nil
	}
	err := r.inner.MobileSessionAllowed(ctx, tenantID, deviceKey)
	switch {
	case err == nil:
		r.cache.store(k, false)
		return nil
	case errors.Is(err, middleware.ErrMobileDeviceRevoked):
		r.cache.store(k, true)
		return middleware.ErrMobileDeviceRevoked
	default:
		return err
	}
}

// cacheInvalidatingDeviceRepo decorates a DeviceRepository, invalidating
// the status cache after a successful status mutation. All other methods
// pass straight through via the embedded interface — notably
// GetByPublicKey stays uncached, so the service-layer enroll/posture
// paths always read the live row and keep their fail-closed guarantees.
type cacheInvalidatingDeviceRepo struct {
	repository.DeviceRepository
	cache *MobileDeviceStatusCache
}

func (r cacheInvalidatingDeviceRepo) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status repository.DeviceStatus) (repository.Device, error) {
	d, err := r.DeviceRepository.UpdateStatus(ctx, tenantID, id, status)
	if err == nil {
		r.cache.Invalidate(tenantID, d.PublicKeyEd25519)
	}
	return d, err
}

func (r cacheInvalidatingDeviceRepo) TransitionStatus(ctx context.Context, tenantID, id uuid.UUID, from, to repository.DeviceStatus) (repository.Device, error) {
	d, err := r.DeviceRepository.TransitionStatus(ctx, tenantID, id, from, to)
	if err == nil {
		r.cache.Invalidate(tenantID, d.PublicKeyEd25519)
	}
	return d, err
}
