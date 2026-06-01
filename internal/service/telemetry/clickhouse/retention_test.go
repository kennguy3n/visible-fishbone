package clickhouse

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestStaticRetentionResolver_ReturnsConfigured ensures the
// simplest resolver always returns the configured value
// regardless of the tenant.
func TestStaticRetentionResolver_ReturnsConfigured(t *testing.T) {
	t.Parallel()
	r := StaticRetentionResolver{Days: 45}
	if got := r.RetentionDays(context.Background(), uuid.New()); got != 45 {
		t.Fatalf("static resolver: got %d want 45", got)
	}
}

// TestMapRetentionResolver_FallbackAndOverride confirms the map
// resolver returns per-tenant overrides where present and the
// default otherwise.
func TestMapRetentionResolver_FallbackAndOverride(t *testing.T) {
	t.Parallel()
	special := uuid.New()
	r := MapRetentionResolver{
		Default:   60,
		PerTenant: map[uuid.UUID]int{special: 90},
	}
	if got := r.RetentionDays(context.Background(), special); got != 90 {
		t.Fatalf("override: got %d want 90", got)
	}
	if got := r.RetentionDays(context.Background(), uuid.New()); got != 60 {
		t.Fatalf("fallback: got %d want 60", got)
	}
}

// trackingResolver counts how many times RetentionDays is
// called so the cache test can prove memoisation.
type trackingResolver struct {
	mu    sync.Mutex
	calls int
	days  int
}

func (r *trackingResolver) RetentionDays(_ context.Context, _ uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.days
}

func (r *trackingResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestResolveRetention_Cached confirms the in-process cache
// hides redundant lookups for the same tenant within the cache
// TTL. A flush of N rows from one tenant must call the resolver
// at most once.
func TestResolveRetention_Cached(t *testing.T) {
	t.Parallel()
	resolver := &trackingResolver{days: 75}
	w := &Writer{
		cfg: Config{
			Retention:            resolver,
			DefaultRetentionDays: DefaultRetentionDays,
		},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	tenant := uuid.New()
	for i := 0; i < 32; i++ {
		got := w.resolveRetention(tenant)
		if got != 75 {
			t.Fatalf("days at iter %d: got %d want 75", i, got)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("resolver calls: got %d want 1 (cache miss)", got)
	}
}

// TestResolveRetention_Clamped pins the [Min, Max] clamp at the
// writer boundary. A resolver returning out-of-range values is
// clamped — never propagated to ClickHouse.
func TestResolveRetention_Clamped(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		input  int
		expect int
	}{
		{"below floor", 5, MinRetentionDays},
		{"at floor", MinRetentionDays, MinRetentionDays},
		{"in band", 60, 60},
		{"at ceiling", MaxRetentionDays, MaxRetentionDays},
		{"above ceiling", 365, MaxRetentionDays},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &trackingResolver{days: tc.input}
			w := &Writer{
				cfg: Config{
					Retention:            r,
					DefaultRetentionDays: DefaultRetentionDays,
				},
				retentionCache: make(map[uuid.UUID]retentionCacheEntry),
			}
			if got := w.resolveRetention(uuid.New()); got != tc.expect {
				t.Fatalf("clamp: got %d want %d", got, tc.expect)
			}
		})
	}
}

// TestResolveRetention_DefaultUsedWhenResolverZero ensures the
// writer falls back to DefaultRetentionDays when the resolver
// returns 0 (the "defer to default" sentinel).
func TestResolveRetention_DefaultUsedWhenResolverZero(t *testing.T) {
	t.Parallel()
	w := &Writer{
		cfg: Config{
			Retention:            &trackingResolver{days: 0},
			DefaultRetentionDays: 65,
		},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	if got := w.resolveRetention(uuid.New()); got != 65 {
		t.Fatalf("default fallback: got %d want 65", got)
	}
}

// TestResolveRetention_NilResolverUsesDefault confirms a Writer
// without a Retention resolver falls back to
// DefaultRetentionDays cleanly (no nil-deref).
func TestResolveRetention_NilResolverUsesDefault(t *testing.T) {
	t.Parallel()
	w := &Writer{
		cfg:            Config{DefaultRetentionDays: 60},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	if got := w.resolveRetention(uuid.New()); got != 60 {
		t.Fatalf("nil resolver: got %d want 60", got)
	}
}

// TestResolveRetention_PerTenantIsolation confirms each tenant
// gets its own cached entry and the resolver is called once
// per distinct tenant.
func TestResolveRetention_PerTenantIsolation(t *testing.T) {
	t.Parallel()
	resolver := &trackingResolver{days: 90}
	w := &Writer{
		cfg: Config{
			Retention:            resolver,
			DefaultRetentionDays: DefaultRetentionDays,
		},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for i := 0; i < 16; i++ {
		w.resolveRetention(tenants[i%len(tenants)])
	}
	if got := resolver.callCount(); got != len(tenants) {
		t.Fatalf("resolver calls: got %d want %d", got, len(tenants))
	}
}

// TestResolveRetention_Concurrent stresses concurrent access
// across many goroutines under -race to confirm the mu coverage
// is correct.
func TestResolveRetention_Concurrent(t *testing.T) {
	t.Parallel()
	resolver := &trackingResolver{days: 60}
	w := &Writer{
		cfg: Config{
			Retention:            resolver,
			DefaultRetentionDays: DefaultRetentionDays,
		},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				w.resolveRetention(tenants[(seed+j)%len(tenants)])
			}
		}(i)
	}
	wg.Wait()
	// Resolver should have been called at most one time per
	// distinct tenant — concurrent first-touch is OK because
	// we don't take the lock across the resolver call by
	// design (avoiding lock-on-IO).
	if got := resolver.callCount(); got > len(tenants)*32 {
		t.Fatalf("resolver call count unreasonably high: %d", got)
	}
}

// TestResolveRetention_CacheExpiry pins the cache TTL by
// driving the cache entry to expiry and verifying the resolver
// is re-consulted.
func TestResolveRetention_CacheExpiry(t *testing.T) {
	t.Parallel()
	resolver := &trackingResolver{days: 60}
	w := &Writer{
		cfg: Config{
			Retention:            resolver,
			DefaultRetentionDays: DefaultRetentionDays,
		},
		retentionCache: make(map[uuid.UUID]retentionCacheEntry),
	}
	tenant := uuid.New()
	w.resolveRetention(tenant)
	if resolver.callCount() != 1 {
		t.Fatalf("first call: got %d want 1", resolver.callCount())
	}
	// Force the cache entry into the past by hand-poking the
	// retentionCache. We don't expose a time injection because
	// the resolver path is fast and the production path is
	// driven by wall-clock; the test mutates the cache
	// directly to simulate expiry.
	w.mu.Lock()
	entry := w.retentionCache[tenant]
	entry.expiresAt = time.Now().Add(-1 * time.Minute)
	w.retentionCache[tenant] = entry
	w.mu.Unlock()
	w.resolveRetention(tenant)
	if resolver.callCount() != 2 {
		t.Fatalf("post-expiry: got %d want 2", resolver.callCount())
	}
}

// TestMigrationFileMatchesEnsureSchemaIntent is a contract
// check: the SQL migration file must reference the same
// table name, the per-tenant retention column, and the TTL
// clause that EnsureSchema applies. The check is intentionally
// loose (substring) so reformatting the SQL does not break it
// — the precise DDL parity is exercised by the integration
// tests against a real ClickHouse instance.
func TestMigrationFileMatchesEnsureSchemaIntent(t *testing.T) {
	t.Parallel()
	bytes, err := os.ReadFile("../../../../migrations/clickhouse/001_telemetry_events.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(bytes)
	mustContain := []string{
		"CREATE TABLE IF NOT EXISTS telemetry_events",
		"retain_until",
		"TTL toDateTime(retain_until)",
		"ORDER BY (tenant_id, event_class, traffic_class, timestamp, event_id)",
		"PARTITION BY toYYYYMMDD(timestamp)",
		"LowCardinality(String)",
		"ALTER TABLE telemetry_events",
	}
	for _, sub := range mustContain {
		if !strings.Contains(sql, sub) {
			t.Errorf("migration file missing required clause: %q", sub)
		}
	}
}
