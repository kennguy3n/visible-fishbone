// Package telemetry — normalize.go takes raw MessagePack
// envelopes off the wire, validates the schema version, and
// enriches them with the tenant + site + identity context the
// hot-path (ClickHouse) and cold-path (S3) writers expect.
//
// Why a separate normalisation pass:
//
//   - The wire envelope is intentionally minimal (UUIDs only) to
//     keep MessagePack overhead low across millions of events
//     per second.
//   - The downstream consumers (ClickHouse columns, the operator
//     portal, the AI summariser) need the resolved
//     human-readable identifiers — tenant name, site name,
//     device name — alongside the wire envelope. Doing the
//     lookup once at the consumer boundary saves N redundant
//     joins downstream.
//   - The lookup itself has a bounded working set (tenants count
//     in the low thousands, devices in the low millions) so we
//     cache aggressively with a TTL. A miss falls back to the
//     repository, which is the source of truth.
//
// The Normalizer is stateless once constructed; safe for
// concurrent use.

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// MaxSchemaVersion is the highest schema version this normaliser
// understands. Producers emitting a higher version are an
// upgrade-skew indication and the envelope is rejected with
// ErrUnsupportedSchema so the operator can deploy the matching
// control-plane release. Bumped in lock-step with
// schema.SchemaVersion.
const MaxSchemaVersion uint8 = schema.SchemaVersion

// MinSchemaVersion is the lowest schema version still accepted.
// Drop in tandem with whatever release retires schema-version-1
// producers (currently no producers below 1 exist).
const MinSchemaVersion uint8 = 1

// DefaultCacheTTL is the entry lifetime of the per-tenant /
// per-site / per-device enrichment cache. Picked so an operator
// rename propagates to telemetry within at most one TTL window;
// in the common case the steady-state lookup is cache-hit.
const DefaultCacheTTL = 30 * time.Second

// DefaultCacheCapacity is the maximum number of entries the
// enrichment cache retains per dimension (tenant, site, device).
// 16k devices keeps the working-set well inside L2; the
// repositories are the source of truth on cache miss.
const DefaultCacheCapacity = 16_384

// Sentinel errors returned by Normalize.
var (
	// ErrUnsupportedSchema is returned when the envelope's
	// SchemaVersion is outside [MinSchemaVersion, MaxSchemaVersion].
	ErrUnsupportedSchema = errors.New("telemetry: unsupported schema version")

	// ErrTenantUnknown is returned when the envelope's TenantID
	// does not resolve via the TenantLookup. The envelope is
	// usually routed to the DLQ for forensics.
	ErrTenantUnknown = errors.New("telemetry: unknown tenant")

	// ErrTenantSuspended is returned when the resolved tenant is
	// in a non-active lifecycle state. Suspended tenants emit
	// telemetry from devices still online during the suspension
	// — the normaliser rejects the envelope so it lands in the
	// DLQ rather than billing them for archive bytes.
	ErrTenantSuspended = errors.New("telemetry: tenant suspended")

	// ErrDeviceUnknown is returned when the envelope's DeviceID
	// is not present in the tenant's device repository. This is
	// the canonical "rogue device" signal — a producer with a
	// valid mTLS identity but no current enrollment record.
	ErrDeviceUnknown = errors.New("telemetry: unknown device")

	// ErrSiteUnknown is returned when the envelope carries a
	// SiteID that does not resolve. Logged but NOT a hard
	// reject: the writer falls through to "site unknown" so the
	// event still lands in ClickHouse (the data is still useful
	// to the tenant even when site metadata is briefly stale,
	// e.g. just after a site rename).
	ErrSiteUnknown = errors.New("telemetry: unknown site")
)

// TenantLookup is the minimum interface Normalize needs out of
// the tenant service. The production type is *tenant.Service;
// tests pass a fake.
type TenantLookup interface {
	Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error)
}

// SiteLookup is the minimum interface for site resolution.
type SiteLookup interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Site, error)
}

// DeviceLookup is the minimum interface for device resolution.
type DeviceLookup interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Device, error)
}

// NormalizedEvent is the enriched event handed to the writers.
// Carries the wire envelope alongside the resolved metadata so
// the writers can promote stable identifiers to ClickHouse
// columns and embed human-readable context in S3 archive
// objects.
type NormalizedEvent struct {
	// Envelope is the original wire envelope, validated.
	Envelope schema.Envelope

	// TenantName / TenantTier are denormalised from the tenant
	// record. The writers promote TenantName to a low-cardinality
	// ClickHouse column so per-tenant rollups can JOIN-free.
	TenantName string
	TenantTier repository.TenantTier

	// SiteName is empty when the envelope has no SiteID or the
	// lookup failed (ErrSiteUnknown). Promoting site to a
	// dedicated column lets per-site dashboards aggregate
	// without a JOIN.
	SiteName string

	// DeviceName is populated from the device repository.
	// Empty when the device was deleted between event emission
	// and consumer dispatch.
	DeviceName string
	// DevicePlatform mirrors the wire envelope's Platform after
	// validation against the repository record. A drift between
	// the wire-claimed platform and the enrolled platform is
	// surfaced as PlatformMismatch — the writer logs but does
	// not reject (a renamed device may have its enrolled
	// platform mid-update).
	DevicePlatform repository.DevicePlatform
	// PlatformMismatch is true when the wire envelope's
	// Platform disagrees with the enrolled device's platform.
	// Used by the alert engine as a low-grade integrity signal.
	PlatformMismatch bool

	// NormalizedAt is the time the consumer finished
	// enrichment, distinct from envelope.Timestamp (which is
	// producer wall-clock). The skew between the two is an
	// operator-facing metric.
	NormalizedAt time.Time
}

// Normalizer is the validator + enricher.
type Normalizer struct {
	tenantLookup TenantLookup
	siteLookup   SiteLookup
	deviceLookup DeviceLookup

	tenantCache *normCache[uuid.UUID, repository.Tenant]
	siteCache   *normCache[siteCacheKey, repository.Site]
	deviceCache *normCache[deviceCacheKey, repository.Device]

	nowFunc func() time.Time
}

type siteCacheKey struct {
	tenant, site uuid.UUID
}

type deviceCacheKey struct {
	tenant, device uuid.UUID
}

// NormalizerConfig configures the Normalizer.
type NormalizerConfig struct {
	// CacheTTL bounds the staleness of cached tenant / site /
	// device lookups. Defaults to DefaultCacheTTL when zero.
	CacheTTL time.Duration
	// CacheCapacity bounds the size of each per-dimension cache.
	// Defaults to DefaultCacheCapacity when zero.
	CacheCapacity int
	// NowFunc returns the current time. Injected so tests can
	// pin the clock; production passes time.Now.
	NowFunc func() time.Time
}

// NewNormalizer constructs a Normalizer. All three lookups are
// required.
func NewNormalizer(
	tenantLookup TenantLookup,
	siteLookup SiteLookup,
	deviceLookup DeviceLookup,
	cfg NormalizerConfig,
) (*Normalizer, error) {
	if tenantLookup == nil {
		return nil, errors.New("telemetry: tenant lookup is required")
	}
	if siteLookup == nil {
		return nil, errors.New("telemetry: site lookup is required")
	}
	if deviceLookup == nil {
		return nil, errors.New("telemetry: device lookup is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.CacheCapacity <= 0 {
		cfg.CacheCapacity = DefaultCacheCapacity
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}
	return &Normalizer{
		tenantLookup: tenantLookup,
		siteLookup:   siteLookup,
		deviceLookup: deviceLookup,
		tenantCache:  newNormCache[uuid.UUID, repository.Tenant](cfg.CacheCapacity, cfg.CacheTTL, cfg.NowFunc),
		siteCache:    newNormCache[siteCacheKey, repository.Site](cfg.CacheCapacity, cfg.CacheTTL, cfg.NowFunc),
		deviceCache:  newNormCache[deviceCacheKey, repository.Device](cfg.CacheCapacity, cfg.CacheTTL, cfg.NowFunc),
		nowFunc:      cfg.NowFunc,
	}, nil
}

// Normalize validates and enriches a single envelope.
//
// Validation order:
//
//  1. Envelope.Validate (schema-level invariants: required IDs,
//     known event class / platform / traffic class).
//  2. SchemaVersion ∈ [MinSchemaVersion, MaxSchemaVersion].
//  3. TenantID resolves to an active tenant.
//  4. DeviceID resolves; platform drift recorded.
//  5. SiteID, when present, resolves (soft failure).
//
// On any hard failure the returned error is one of the sentinels
// above so the caller can branch (e.g. ErrTenantSuspended →
// drop; ErrTenantUnknown → DLQ + alert).
func (n *Normalizer) Normalize(ctx context.Context, env schema.Envelope) (NormalizedEvent, error) {
	if err := env.Validate(); err != nil {
		return NormalizedEvent{}, err
	}
	if env.SchemaVersion < MinSchemaVersion || env.SchemaVersion > MaxSchemaVersion {
		return NormalizedEvent{}, fmt.Errorf("schema_version=%d outside [%d, %d]: %w",
			env.SchemaVersion, MinSchemaVersion, MaxSchemaVersion, ErrUnsupportedSchema)
	}

	tenant, err := n.lookupTenant(ctx, env.TenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return NormalizedEvent{}, fmt.Errorf("tenant %s: %w", env.TenantID, ErrTenantUnknown)
		}
		return NormalizedEvent{}, fmt.Errorf("tenant lookup: %w", err)
	}
	if tenant.Status != repository.TenantStatusActive {
		return NormalizedEvent{}, fmt.Errorf("tenant %s status=%s: %w",
			env.TenantID, tenant.Status, ErrTenantSuspended)
	}

	device, err := n.lookupDevice(ctx, env.TenantID, env.DeviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return NormalizedEvent{}, fmt.Errorf("device %s: %w", env.DeviceID, ErrDeviceUnknown)
		}
		return NormalizedEvent{}, fmt.Errorf("device lookup: %w", err)
	}

	var siteName string
	if env.SiteID != nil && *env.SiteID != uuid.Nil {
		site, err := n.lookupSite(ctx, env.TenantID, *env.SiteID)
		if err != nil {
			if !errors.Is(err, repository.ErrNotFound) {
				return NormalizedEvent{}, fmt.Errorf("site lookup: %w", err)
			}
			// Soft failure: keep going with an empty site
			// name. The writer logs a warning so the operator
			// can investigate the dangling reference.
		} else {
			siteName = site.Name
		}
	}

	enrolled := repository.DevicePlatform(env.Platform)
	mismatch := device.Platform != "" && enrolled != "" && device.Platform != enrolled

	return NormalizedEvent{
		Envelope:         env,
		TenantName:       tenant.Name,
		TenantTier:       tenant.Tier,
		SiteName:         siteName,
		DeviceName:       device.Name,
		DevicePlatform:   device.Platform,
		PlatformMismatch: mismatch,
		NormalizedAt:     n.nowFunc(),
	}, nil
}

// Invalidate drops any cached entry for the given tenant /
// site / device. The site / device invalidation requires the
// tenant ID; pass uuid.Nil for the ID you do not want to touch.
func (n *Normalizer) Invalidate(tenantID, siteID, deviceID uuid.UUID) {
	if tenantID != uuid.Nil {
		n.tenantCache.Invalidate(tenantID)
	}
	if tenantID != uuid.Nil && siteID != uuid.Nil {
		n.siteCache.Invalidate(siteCacheKey{tenant: tenantID, site: siteID})
	}
	if tenantID != uuid.Nil && deviceID != uuid.Nil {
		n.deviceCache.Invalidate(deviceCacheKey{tenant: tenantID, device: deviceID})
	}
}

func (n *Normalizer) lookupTenant(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	if t, ok := n.tenantCache.Get(id); ok {
		return t, nil
	}
	t, err := n.tenantLookup.Get(ctx, id)
	if err != nil {
		return repository.Tenant{}, err
	}
	n.tenantCache.Put(id, t)
	return t, nil
}

func (n *Normalizer) lookupSite(ctx context.Context, tenantID, id uuid.UUID) (repository.Site, error) {
	key := siteCacheKey{tenant: tenantID, site: id}
	if s, ok := n.siteCache.Get(key); ok {
		return s, nil
	}
	s, err := n.siteLookup.Get(ctx, tenantID, id)
	if err != nil {
		return repository.Site{}, err
	}
	n.siteCache.Put(key, s)
	return s, nil
}

func (n *Normalizer) lookupDevice(ctx context.Context, tenantID, id uuid.UUID) (repository.Device, error) {
	key := deviceCacheKey{tenant: tenantID, device: id}
	if d, ok := n.deviceCache.Get(key); ok {
		return d, nil
	}
	d, err := n.deviceLookup.Get(ctx, tenantID, id)
	if err != nil {
		return repository.Device{}, err
	}
	n.deviceCache.Put(key, d)
	return d, nil
}

// --- normCache ---------------------------------------------------------

// normCache is a thread-safe TTL+LRU cache for the per-tenant /
// per-site / per-device lookups. Implementation kept private to
// this file so the public API of Normalizer stays narrow.
type normCache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	nowFunc  func() time.Time
	entries  map[K]normCacheEntry[V]
}

type normCacheEntry[V any] struct {
	value     V
	expiresAt time.Time
}

func newNormCache[K comparable, V any](capacity int, ttl time.Duration, nowFunc func() time.Time) *normCache[K, V] {
	return &normCache[K, V]{
		capacity: capacity,
		ttl:      ttl,
		nowFunc:  nowFunc,
		entries:  make(map[K]normCacheEntry[V], capacity),
	}
}

func (c *normCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if c.nowFunc().After(e.expiresAt) {
		delete(c.entries, key)
		var zero V
		return zero, false
	}
	return e.value, true
}

func (c *normCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		// Bounded random eviction — keeps the cache small
		// without the overhead of full LRU bookkeeping. The
		// access pattern is "most events touch the same
		// handful of tenants per second" so random eviction
		// is a reasonable approximation of LRU at this size.
		// Skip eviction when the key already exists — a
		// TTL-refresh is an in-place update, not a net new
		// insertion, so evicting a peer entry would silently
		// kick out another hot tenant for no capacity gain
		// and degrade the steady-state hit rate.
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = normCacheEntry[V]{
		value:     value,
		expiresAt: c.nowFunc().Add(c.ttl),
	}
}

func (c *normCache[K, V]) Invalidate(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *normCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
