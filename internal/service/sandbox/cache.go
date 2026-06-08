package sandbox

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Cache is a small, concurrency-safe in-memory verdict cache keyed
// by (tenant, SHA-256). It sits in front of the persistent
// repository so the SWG malware stage's hot-path "do we have a
// verdict for this digest?" lookup is answered without a database
// round-trip for recently-seen files.
//
// Only resolved verdicts (clean/suspicious/malicious/timeout) are
// cached; a pending submission is never cached so a poll that later
// resolves is not shadowed by a stale "pending". Entries expire
// after a TTL, and the map is bounded: when it would exceed maxEntries
// the oldest-inserted entry is evicted. This is deliberately a
// simple bounded TTL map, not a true LRU — verdicts are immutable
// once resolved, so the worst case of evicting a still-hot entry is
// just one extra DB read.
type Cache struct {
	mu         sync.Mutex
	entries    map[string]cacheEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	// providerTTL overrides the default ttl per producing provider
	// (verdict.Provider). A reputation provider whose intel ages
	// quickly (e.g. VirusTotal, where engines re-score) can be given
	// a shorter TTL than a deterministic detonation backend. A
	// provider absent from the map uses the default ttl.
	providerTTL map[string]time.Duration
}

type cacheEntry struct {
	verdict   Verdict
	expiresAt time.Time
	inserted  time.Time
}

// CacheOption configures the cache.
type CacheOption func(*Cache)

// WithCacheTTL sets how long a resolved verdict stays cached.
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *Cache) {
		if ttl > 0 {
			c.ttl = ttl
		}
	}
}

// WithCacheCapacity bounds the number of cached entries.
func WithCacheCapacity(n int) CacheOption {
	return func(c *Cache) {
		if n > 0 {
			c.maxEntries = n
		}
	}
}

// WithCacheProviderTTL sets per-provider TTL overrides keyed by
// provider id (the verdict's Provider field). Entries with a
// non-positive duration are ignored; providers not listed fall back
// to the default TTL.
func WithCacheProviderTTL(ttls map[string]time.Duration) CacheOption {
	return func(c *Cache) {
		for id, d := range ttls {
			if d > 0 {
				c.providerTTL[id] = d
			}
		}
	}
}

// withCacheClock injects a clock for deterministic tests.
func withCacheClock(now func() time.Time) CacheOption {
	return func(c *Cache) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCache builds a verdict cache. Defaults: 1h TTL, 4096 entries.
func NewCache(opts ...CacheOption) *Cache {
	c := &Cache{
		entries:     make(map[string]cacheEntry),
		ttl:         time.Hour,
		maxEntries:  4096,
		now:         func() time.Time { return time.Now().UTC() },
		providerTTL: make(map[string]time.Duration),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func cacheKey(tenantID uuid.UUID, sha256 string) string {
	return tenantID.String() + "/" + sha256
}

// Get returns the cached verdict for (tenant, sha256) if present and
// not expired.
func (c *Cache) Get(tenantID uuid.UUID, sha256 string) (Verdict, bool) {
	if c == nil {
		return Verdict{}, false
	}
	key := cacheKey(tenantID, sha256)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Verdict{}, false
	}
	if c.now().After(e.expiresAt) {
		delete(c.entries, key)
		return Verdict{}, false
	}
	return e.verdict, true
}

// Put caches a resolved verdict. Pending/unknown verdicts are
// ignored so they never shadow a later resolution.
func (c *Cache) Put(tenantID uuid.UUID, v Verdict) {
	if c == nil {
		return
	}
	if v.Classification == ClassUnknown || !v.Classification.Valid() {
		return
	}
	now := c.now()
	ttl := c.ttl
	if d, ok := c.providerTTL[v.Provider]; ok && d > 0 {
		ttl = d
	}
	key := cacheKey(tenantID, v.SHA256)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Only evict when inserting a genuinely new key would push the map
	// over capacity. Overwriting an existing digest's verdict doesn't
	// grow the map, so evicting another (still-valid) entry there would
	// be a spurious eviction and an avoidable later DB read.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = cacheEntry{
		verdict:   v,
		expiresAt: now.Add(ttl),
		inserted:  now,
	}
}

// Invalidate drops any cached verdict for (tenant, sha256).
func (c *Cache) Invalidate(tenantID uuid.UUID, sha256 string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, cacheKey(tenantID, sha256))
}

// evictOldestLocked removes the oldest-inserted entry. Caller holds
// the lock.
func (c *Cache) evictOldestLocked() {
	var oldestKey string
	var oldestAt time.Time
	first := true
	for k, e := range c.entries {
		if first || e.inserted.Before(oldestAt) {
			oldestKey = k
			oldestAt = e.inserted
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
