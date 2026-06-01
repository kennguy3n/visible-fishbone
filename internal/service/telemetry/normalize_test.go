package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- test doubles -------------------------------------------------------

type fakeTenantLookup struct {
	mu      sync.Mutex
	rows    map[uuid.UUID]repository.Tenant
	notFound map[uuid.UUID]bool
	calls   int
}

func newFakeTenantLookup() *fakeTenantLookup {
	return &fakeTenantLookup{
		rows:     map[uuid.UUID]repository.Tenant{},
		notFound: map[uuid.UUID]bool{},
	}
}

func (f *fakeTenantLookup) Get(_ context.Context, id uuid.UUID) (repository.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.notFound[id] {
		return repository.Tenant{}, repository.ErrNotFound
	}
	t, ok := f.rows[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	return t, nil
}

func (f *fakeTenantLookup) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeSiteLookup struct {
	mu    sync.Mutex
	rows  map[siteCacheKey]repository.Site
	calls int
}

func newFakeSiteLookup() *fakeSiteLookup {
	return &fakeSiteLookup{rows: map[siteCacheKey]repository.Site{}}
}

func (f *fakeSiteLookup) Get(_ context.Context, tenantID, id uuid.UUID) (repository.Site, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	s, ok := f.rows[siteCacheKey{tenant: tenantID, site: id}]
	if !ok {
		return repository.Site{}, repository.ErrNotFound
	}
	return s, nil
}

func (f *fakeSiteLookup) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeDeviceLookup struct {
	mu      sync.Mutex
	rows    map[deviceCacheKey]repository.Device
	failNxt error
	calls   int
}

func newFakeDeviceLookup() *fakeDeviceLookup {
	return &fakeDeviceLookup{rows: map[deviceCacheKey]repository.Device{}}
}

func (f *fakeDeviceLookup) Get(_ context.Context, tenantID, id uuid.UUID) (repository.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNxt != nil {
		err := f.failNxt
		f.failNxt = nil
		return repository.Device{}, err
	}
	d, ok := f.rows[deviceCacheKey{tenant: tenantID, device: id}]
	if !ok {
		return repository.Device{}, repository.ErrNotFound
	}
	return d, nil
}

func (f *fakeDeviceLookup) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --- helpers ------------------------------------------------------------

// envelopeFor builds a valid signed-off envelope for a flow event.
// Done via schema.WrapFlowEvent so the payload is real MessagePack
// and Envelope.Validate passes.
func envelopeFor(t *testing.T, tenant, device uuid.UUID, opts ...func(*schema.Envelope)) schema.Envelope {
	t.Helper()
	env, err := schema.WrapFlowEvent(schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       uuid.New(),
		TenantID:      tenant,
		DeviceID:      device,
		Timestamp:     time.Now().UTC(),
		Platform:      schema.PlatformLinux,
	},
		"trusted_direct",
		schema.FlowEvent{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1024, DstPort: 443,
			Protocol: "tcp", Verdict: schema.VerdictAllow,
			BytesIn: 1, BytesOut: 1, DurationMs: 1,
		})
	if err != nil {
		t.Fatalf("wrap envelope: %v", err)
	}
	for _, opt := range opts {
		opt(&env)
	}
	return env
}

func newNormalizerWithLookups(
	t *testing.T,
	tenants *fakeTenantLookup,
	sites *fakeSiteLookup,
	devices *fakeDeviceLookup,
) *Normalizer {
	t.Helper()
	n, err := NewNormalizer(tenants, sites, devices, NormalizerConfig{
		CacheTTL:      100 * time.Millisecond,
		CacheCapacity: 8,
		NowFunc:       time.Now,
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	return n
}

// --- tests --------------------------------------------------------------

func TestNormalize_HappyPath(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	siteID := uuid.New()

	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{
		ID: tenantID, Name: "Acme", Slug: "acme",
		Status: repository.TenantStatusActive, Tier: repository.TenantTier("pro"),
	}
	sites := newFakeSiteLookup()
	sites.rows[siteCacheKey{tenantID, siteID}] = repository.Site{
		ID: siteID, TenantID: tenantID, Name: "HQ",
	}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{
		ID: deviceID, TenantID: tenantID, Name: "laptop-7",
		Platform: repository.DevicePlatform("linux"),
	}

	n := newNormalizerWithLookups(t, tenants, sites, devices)
	env := envelopeFor(t, tenantID, deviceID, func(e *schema.Envelope) { e.SiteID = &siteID })

	got, err := n.Normalize(context.Background(), env)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.TenantName != "Acme" {
		t.Fatalf("TenantName: got %q", got.TenantName)
	}
	if got.SiteName != "HQ" {
		t.Fatalf("SiteName: got %q", got.SiteName)
	}
	if got.DeviceName != "laptop-7" {
		t.Fatalf("DeviceName: got %q", got.DeviceName)
	}
	if got.PlatformMismatch {
		t.Fatalf("PlatformMismatch should be false (linux == linux)")
	}
}

func TestNormalize_SchemaVersionRejected(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{
		ID: tenantID, Status: repository.TenantStatusActive,
	}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), newFakeDeviceLookup())
	env := envelopeFor(t, tenantID, deviceID, func(e *schema.Envelope) { e.SchemaVersion = MaxSchemaVersion + 1 })
	_, err := n.Normalize(context.Background(), env)
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("expected ErrUnsupportedSchema, got %v", err)
	}
}

func TestNormalize_TenantUnknown(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.notFound[tenantID] = true
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), newFakeDeviceLookup())
	env := envelopeFor(t, tenantID, deviceID)
	_, err := n.Normalize(context.Background(), env)
	if !errors.Is(err, ErrTenantUnknown) {
		t.Fatalf("expected ErrTenantUnknown, got %v", err)
	}
}

func TestNormalize_TenantSuspended(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{
		ID: tenantID, Status: repository.TenantStatusSuspended,
	}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), devices)
	_, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID))
	if !errors.Is(err, ErrTenantSuspended) {
		t.Fatalf("expected ErrTenantSuspended, got %v", err)
	}
}

func TestNormalize_DeviceUnknown(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), newFakeDeviceLookup())
	_, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID))
	if !errors.Is(err, ErrDeviceUnknown) {
		t.Fatalf("expected ErrDeviceUnknown, got %v", err)
	}
}

func TestNormalize_SiteSoftFailure(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	siteID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Name: "T", Status: repository.TenantStatusActive}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID, Name: "d"}
	// Site lookup is empty — will return ErrNotFound which the
	// normalizer must absorb as a soft failure.
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), devices)
	got, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID, func(e *schema.Envelope) { e.SiteID = &siteID }))
	if err != nil {
		t.Fatalf("site miss should not fail Normalize, got %v", err)
	}
	if got.SiteName != "" {
		t.Fatalf("SiteName: got %q want empty (soft fail)", got.SiteName)
	}
}

func TestNormalize_PlatformMismatch(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{
		ID: deviceID, TenantID: tenantID, Name: "x",
		Platform: repository.DevicePlatform("macos"), // enrolled as macOS
	}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), devices)
	// Envelope says linux; enrolled says macos.
	env := envelopeFor(t, tenantID, deviceID) // PlatformLinux
	got, err := n.Normalize(context.Background(), env)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !got.PlatformMismatch {
		t.Fatalf("PlatformMismatch should be true (envelope=linux, enrolled=macos)")
	}
}

func TestNormalize_TenantCacheHit(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive, Name: "C"}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID, Name: "d"}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), devices)
	for i := 0; i < 5; i++ {
		if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
			t.Fatalf("normalize[%d]: %v", i, err)
		}
	}
	if got := tenants.callCount(); got != 1 {
		t.Fatalf("expected 1 tenant lookup (cached), got %d", got)
	}
}

func TestNormalize_CacheTTLExpiry(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive, Name: "Z"}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID, Name: "d"}

	now := time.Now()
	clock := &now
	n, err := NewNormalizer(tenants, newFakeSiteLookup(), devices, NormalizerConfig{
		CacheTTL:      10 * time.Millisecond,
		CacheCapacity: 4,
		NowFunc:       func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("first normalize: %v", err)
	}
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("second normalize: %v", err)
	}
	if got := tenants.callCount(); got != 1 {
		t.Fatalf("expected 1 lookup, got %d", got)
	}
	// Advance the clock past the TTL.
	*clock = now.Add(time.Second)
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("post-expiry normalize: %v", err)
	}
	if got := tenants.callCount(); got != 2 {
		t.Fatalf("post-expiry lookup not refreshed: got %d calls", got)
	}
}

func TestNormalize_Invalidate(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive, Name: "Z"}
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID, Name: "d"}
	n := newNormalizerWithLookups(t, tenants, newFakeSiteLookup(), devices)
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if tenants.callCount() != 1 {
		t.Fatalf("call count: %d", tenants.callCount())
	}
	n.Invalidate(tenantID, uuid.Nil, deviceID)
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("post-invalidate: %v", err)
	}
	if tenants.callCount() != 2 {
		t.Fatalf("post-invalidate call count: %d", tenants.callCount())
	}
}

func TestNewNormalizer_ValidatesInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewNormalizer(nil, newFakeSiteLookup(), newFakeDeviceLookup(), NormalizerConfig{}); err == nil {
		t.Fatalf("nil tenant lookup should error")
	}
	if _, err := NewNormalizer(newFakeTenantLookup(), nil, newFakeDeviceLookup(), NormalizerConfig{}); err == nil {
		t.Fatalf("nil site lookup should error")
	}
	if _, err := NewNormalizer(newFakeTenantLookup(), newFakeSiteLookup(), nil, NormalizerConfig{}); err == nil {
		t.Fatalf("nil device lookup should error")
	}
}

func TestNormalize_RejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()
	n := newNormalizerWithLookups(t, newFakeTenantLookup(), newFakeSiteLookup(), newFakeDeviceLookup())
	env := schema.Envelope{} // all zero — fails Validate
	_, err := n.Normalize(context.Background(), env)
	if err == nil {
		t.Fatalf("expected error on invalid envelope")
	}
}

// TestNormalize_NegativeTenantCache asserts that a flood of
// envelopes for an unknown tenant only hits the tenant lookup
// once within the NegativeCacheTTL window. Prior to PR #38
// round-7 ANALYSIS_0004, every envelope re-issued the repo
// call.
func TestNormalize_NegativeTenantCache(t *testing.T) {
	t.Parallel()
	unknownTenant := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	sites := newFakeSiteLookup()
	devices := newFakeDeviceLookup()
	n, err := NewNormalizer(tenants, sites, devices, NormalizerConfig{
		CacheTTL:         time.Second,
		CacheCapacity:    8,
		NegativeCacheTTL: time.Second,
		NowFunc:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	for i := 0; i < 50; i++ {
		_, err := n.Normalize(context.Background(), envelopeFor(t, unknownTenant, deviceID))
		if !errors.Is(err, ErrTenantUnknown) {
			t.Fatalf("envelope %d: want ErrTenantUnknown, got %v", i, err)
		}
	}
	if got := tenants.callCount(); got != 1 {
		t.Fatalf("negative cache leaked: want 1 tenant lookup, got %d", got)
	}
}

// TestNormalize_NegativeDeviceCache mirrors the tenant variant
// for an unknown device under a known-good tenant. The negative
// cache must absorb the device lookups; the tenant lookup is
// satisfied from the positive cache after the first hit.
func TestNormalize_NegativeDeviceCache(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	unknownDevice := uuid.New()
	tenants := newFakeTenantLookup()
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive, Name: "T"}
	sites := newFakeSiteLookup()
	devices := newFakeDeviceLookup()
	n, err := NewNormalizer(tenants, sites, devices, NormalizerConfig{
		CacheTTL:         time.Second,
		CacheCapacity:    8,
		NegativeCacheTTL: time.Second,
		NowFunc:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	for i := 0; i < 50; i++ {
		_, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, unknownDevice))
		if !errors.Is(err, ErrDeviceUnknown) {
			t.Fatalf("envelope %d: want ErrDeviceUnknown, got %v", i, err)
		}
	}
	if got := devices.callCount(); got != 1 {
		t.Fatalf("negative cache leaked: want 1 device lookup, got %d", got)
	}
}

// TestNormalize_NegativeCacheDisabled confirms callers can pin
// the legacy behaviour (every miss touches the repo) by passing
// NegativeCacheTTL < 0.
func TestNormalize_NegativeCacheDisabled(t *testing.T) {
	t.Parallel()
	unknownTenant := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	n, err := NewNormalizer(tenants, newFakeSiteLookup(), newFakeDeviceLookup(), NormalizerConfig{
		CacheTTL:         time.Second,
		CacheCapacity:    8,
		NegativeCacheTTL: -1, // disabled
		NowFunc:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, _ = n.Normalize(context.Background(), envelopeFor(t, unknownTenant, deviceID))
	}
	if got := tenants.callCount(); got != 5 {
		t.Fatalf("disabled negative cache: want 5 tenant lookups, got %d", got)
	}
}

// TestNormalize_InvalidateClearsNegativeCache pins the
// "freshly-created tenant accepted within seconds" semantics:
// after a negative cache hit, calling Invalidate must clear the
// memo so a subsequent Normalize for the same tenant re-issues
// the lookup and sees the new row.
func TestNormalize_InvalidateClearsNegativeCache(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	deviceID := uuid.New()
	tenants := newFakeTenantLookup()
	devices := newFakeDeviceLookup()
	devices.rows[deviceCacheKey{tenantID, deviceID}] = repository.Device{ID: deviceID, TenantID: tenantID, Name: "d"}
	n, err := NewNormalizer(tenants, newFakeSiteLookup(), devices, NormalizerConfig{
		CacheTTL:         time.Second,
		CacheCapacity:    8,
		NegativeCacheTTL: time.Minute, // long enough to outlive the test
		NowFunc:          time.Now,
	})
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	// First call: tenant absent → ErrTenantUnknown + negative
	// cache entry written.
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); !errors.Is(err, ErrTenantUnknown) {
		t.Fatalf("pre-create: want ErrTenantUnknown, got %v", err)
	}
	// Operator creates the tenant and invalidates the memo.
	tenants.rows[tenantID] = repository.Tenant{ID: tenantID, Status: repository.TenantStatusActive, Name: "T"}
	n.Invalidate(tenantID, uuid.Nil, uuid.Nil)
	// Second call: tenant present → success.
	if _, err := n.Normalize(context.Background(), envelopeFor(t, tenantID, deviceID)); err != nil {
		t.Fatalf("post-invalidate: want success, got %v", err)
	}
	if got := tenants.callCount(); got != 2 {
		t.Fatalf("want 2 tenant lookups (one miss, one hit), got %d", got)
	}
}
