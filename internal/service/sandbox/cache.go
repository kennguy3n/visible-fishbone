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
		entries:    make(map[string]cacheEntry),
		ttl:        time.Hour,
		maxEntries: 4096,
		now:        func() time.Time { return time.Now().UTC() },
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.entries[cacheKey(tenantID, v.SHA256)] = cacheEntry{
		verdict:   v,
		expiresAt: now.Add(c.ttl),
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
