package tenant

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultBrandingCacheTTL is the time-to-live for cached resolved
// branding entries when a non-zero TTL is supplied to the
// constructor. Branding mutations (SetTenantBranding,
// ClearTenantBranding) invalidate the affected tenant's entry
// immediately, so the TTL only bounds staleness from out-of-band
// writes (e.g. an MSP rebrand via UpdateMSP).
const DefaultBrandingCacheTTL = 30 * time.Second

// DefaultBrandingCacheMaxEntries caps the cache to prevent memory
// growth on long-running deployments. When exceeded, the oldest
// entry by insertion time is evicted. 1024 covers the largest
// single-process tenant cardinality we currently support while
// keeping the cache footprint well under 1 MiB.
const DefaultBrandingCacheMaxEntries = 1024

// BrandingCacheOptions tunes the in-process cache that
// BrandingResolver maintains in front of the tenant + msp
// repositories. The zero value applies the package defaults
// (DefaultBrandingCacheTTL + DefaultBrandingCacheMaxEntries) —
// passing BrandingCacheOptions{} to NewBrandingResolverWithCache
// yields a cached resolver with a 30s TTL. To bypass caching
// entirely (e.g. when the caller owns its own cache layer), use
// NewBrandingResolver, or pass a negative TTL to the cached
// constructor. Round-13 of Devin Review on PR #42 flagged the
// previous "zero disables caching" wording as a doc/code
// mismatch: the constructor has always treated zero as
// "use default" and only `<0` as "disable", matching Go's
// usual zero-value-is-useful idiom.
type BrandingCacheOptions struct {
	// TTL bounds staleness for entries that have not been
	// invalidated by a local SetTenantBranding /
	// ClearTenantBranding call. Zero falls back to
	// DefaultBrandingCacheTTL; a negative value disables
	// caching entirely (NewBrandingResolverWithCache returns
	// an uncached resolver equivalent to NewBrandingResolver).
	TTL time.Duration
	// MaxEntries is the cache cap; zero defaults to
	// DefaultBrandingCacheMaxEntries.
	MaxEntries int
}

// brandingCacheEntry is the value-side of the LRU node. It is
// stored inside the lruList element's Value (`*brandingCacheNode`)
// so the eviction list can name back to the map key on pop.
type brandingCacheEntry struct {
	resolved repository.MSPBranding
	expireAt time.Time
}

// brandingCacheNode is the element-side of the LRU list. Holding
// both the tenantID and the entry on the same node lets the
// eviction path delete from `cacheEntries` in O(1) without
// scanning, which was the round-6 Devin Review concern: the
// previous map+timestamp scheme rebuilt the "oldest" search per
// store and was O(n) on the cache cap.
type brandingCacheNode struct {
	tenantID uuid.UUID
	entry    brandingCacheEntry
}

// DefaultBranding is the platform-wide branding fallback. Returned
// fields are intentionally generic — operators are expected to
// override at either the MSP or tenant level.
var DefaultBranding = repository.MSPBranding{
	LogoURL:         "/assets/sng-logo.svg",
	PrimaryColor:    "#0E1F3A",
	SecondaryColor:  "#1FB6FF",
	CustomDomain:    "",
	PortalSupportTo: "support@example.com",
}

// BrandingResolver computes the effective branding for a tenant
// by walking the resolution chain tenant override > MSP default >
// platform default. Per-field — not whole-record — overrides:
// a tenant that only sets PrimaryColor inherits LogoURL etc from
// the MSP layer.
//
// The resolver MAY cache resolved branding in-process when
// constructed via NewBrandingResolverWithCache; the bare
// NewBrandingResolver path stays uncached and hits the tenant +
// msp repositories on every Resolve. SetTenantBranding /
// ClearTenantBranding always invalidate the affected tenant's
// cache entry on success, so a local write is immediately
// visible. MSP-level rebrands (UpdateMSP) become visible within
// the configured TTL.
type BrandingResolver struct {
	tenants repository.TenantRepository
	msps    repository.MSPRepository

	// Cache fields. cacheTTL == 0 means caching is disabled
	// (cacheEntries is also nil) and the fast-path checks below
	// short-circuit immediately. When caching is enabled,
	// cacheMu protects both `cacheEntries` and `cacheLRU`. We
	// use a plain Mutex (not RWMutex) because every cache hit
	// promotes the entry to the front of the LRU list, which
	// requires write access — the RWMutex's read-then-upgrade
	// pattern is not available in Go and a separate try-then-fall
	// back path would add latency without changing the per-call
	// lock acquisition cost (still exactly one Lock/Unlock).
	cacheMu      sync.Mutex
	cacheTTL     time.Duration
	cacheMax     int
	cacheEntries map[uuid.UUID]*list.Element // map[uuid.UUID]*list.Element{Value: *brandingCacheNode}
	cacheLRU     *list.List                  // doubly-linked list of *brandingCacheNode, front = most-recently used
	// now is injected for tests; production code uses time.Now.
	now func() time.Time
}

// NewBrandingResolver returns an uncached resolver. Every Resolve
// call hits the tenant + msp repositories. Use this when the
// caller owns its own caching layer or when the lookup volume is
// low enough that a per-process cache is not warranted.
func NewBrandingResolver(tenants repository.TenantRepository, msps repository.MSPRepository) *BrandingResolver {
	return &BrandingResolver{tenants: tenants, msps: msps, now: time.Now}
}

// NewBrandingResolverWithCache wires a TTL+capped in-process
// cache in front of the resolver. Pass a zero-value
// BrandingCacheOptions to fall back to the defaults
// (DefaultBrandingCacheTTL, DefaultBrandingCacheMaxEntries). A
// TTL of <0 disables caching (equivalent to NewBrandingResolver).
//
// The cache invalidation contract:
//   - SetTenantBranding / ClearTenantBranding evict the affected
//     tenant entry synchronously on success.
//   - Invalidate(tenantID) / InvalidateAll() are public for
//     callers performing out-of-band writes (e.g. an MSP rebrand
//     via UpdateMSP would call InvalidateAll because the cache
//     keys on tenantID, not mspID).
//   - Entries past TTL are lazily expired on the next Resolve
//     hitting that key; there is no background sweeper.
func NewBrandingResolverWithCache(tenants repository.TenantRepository, msps repository.MSPRepository, opts BrandingCacheOptions) *BrandingResolver {
	if opts.TTL < 0 {
		return NewBrandingResolver(tenants, msps)
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultBrandingCacheTTL
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultBrandingCacheMaxEntries
	}
	return &BrandingResolver{
		tenants:      tenants,
		msps:         msps,
		cacheTTL:     ttl,
		cacheMax:     maxEntries,
		cacheEntries: make(map[uuid.UUID]*list.Element, maxEntries),
		cacheLRU:     list.New(),
		now:          time.Now,
	}
}

// Invalidate evicts a single tenant's cache entry. Safe to call
// on an uncached resolver (no-op).
func (r *BrandingResolver) Invalidate(tenantID uuid.UUID) {
	if r.cacheEntries == nil {
		return
	}
	r.cacheMu.Lock()
	if elem, ok := r.cacheEntries[tenantID]; ok {
		r.cacheLRU.Remove(elem)
		delete(r.cacheEntries, tenantID)
	}
	r.cacheMu.Unlock()
}

// InvalidateAll clears every cached entry. Use after a write that
// could affect many tenants (e.g. updating an MSP's branding
// defaults — the cache keys on tenantID and cannot be
// selectively flushed without an msp_id → tenants index that the
// resolver does not maintain).
func (r *BrandingResolver) InvalidateAll() {
	if r.cacheEntries == nil {
		return
	}
	r.cacheMu.Lock()
	r.cacheEntries = make(map[uuid.UUID]*list.Element, r.cacheMax)
	r.cacheLRU.Init()
	r.cacheMu.Unlock()
}

// cacheLookup returns (resolved, true) on hit, zero+false on
// miss or stale entry. Promotes the entry to the front of the
// LRU on hit. Holds cacheMu for the duration.
func (r *BrandingResolver) cacheLookup(tenantID uuid.UUID) (repository.MSPBranding, bool) {
	if r.cacheEntries == nil {
		return repository.MSPBranding{}, false
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	elem, ok := r.cacheEntries[tenantID]
	if !ok {
		return repository.MSPBranding{}, false
	}
	node := elem.Value.(*brandingCacheNode)
	if r.now().After(node.entry.expireAt) {
		// Stale — evict eagerly so the LRU stays accurate. We
		// hold the write lock so this is safe; the caller will
		// recompute and reinsert via cacheStore.
		r.cacheLRU.Remove(elem)
		delete(r.cacheEntries, tenantID)
		return repository.MSPBranding{}, false
	}
	r.cacheLRU.MoveToFront(elem)
	return node.entry.resolved, true
}

// cacheStore writes a resolved entry. Evicts the least-recently-
// used entry in O(1) via the doubly-linked list when the cap is
// exceeded. Holds cacheMu for the duration.
//
// Round-6 of Devin Review caught the previous O(n) scan over the
// map per store: at cap=1024 the linear search was tolerable but
// scaled poorly with the cap and any growth of the platform's
// active-tenant cardinality. The container/list-backed LRU keeps
// every cache operation O(1) (lookup + promote + evict) without
// changing the public API or the invalidation contract.
func (r *BrandingResolver) cacheStore(tenantID uuid.UUID, b repository.MSPBranding) {
	if r.cacheEntries == nil {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := r.now()
	entry := brandingCacheEntry{
		resolved: b,
		expireAt: now.Add(r.cacheTTL),
	}
	if elem, ok := r.cacheEntries[tenantID]; ok {
		// Refresh in place — update value + promote.
		node := elem.Value.(*brandingCacheNode)
		node.entry = entry
		r.cacheLRU.MoveToFront(elem)
		return
	}
	if r.cacheLRU.Len() >= r.cacheMax {
		// Pop the LRU (tail) entry. The tail's tenantID is on
		// the node so we can delete from the map in O(1).
		if tail := r.cacheLRU.Back(); tail != nil {
			evicted := tail.Value.(*brandingCacheNode)
			r.cacheLRU.Remove(tail)
			delete(r.cacheEntries, evicted.tenantID)
		}
	}
	elem := r.cacheLRU.PushFront(&brandingCacheNode{tenantID: tenantID, entry: entry})
	r.cacheEntries[tenantID] = elem
}

// tenantBrandingSettings is the shape of the optional
// `branding` key inside tenants.settings JSONB. Tenants without
// any override leave the key absent; the resolver treats absence
// the same as an empty-fields struct (every field falls through
// to the next layer).
type tenantBrandingSettings struct {
	Branding *repository.MSPBranding `json:"branding,omitempty"`
}

// Resolve returns the effective branding for a tenant. The
// returned struct has every field populated — either from the
// tenant override, the MSP default, or DefaultBranding.
//
// Lookup order:
//  1. tenant.settings.branding (per-field override)
//  2. msp.branding (only consulted when the tenant has an
//     msp_id pointer — i.e. an MSP owner binding)
//  3. DefaultBranding (platform fallback)
//
// Returns ErrNotFound if the tenant does not exist.
//
// When caching is enabled (see NewBrandingResolverWithCache),
// Resolve short-circuits to the cached entry on hit. The cache
// keys on tenantID, so a stale MSP-level rebrand surfaces within
// cacheTTL. On miss the result is computed via ResolveForTenant
// and stored back into the cache. ResolveForTenant itself is
// uncached because its caller already has the tenant row in
// hand — the savings would be the tenant Get only, while the
// callers that hit ResolveForTenant (setBranding RMW path) are
// not the hot read path the cache is sized for.
func (r *BrandingResolver) Resolve(ctx context.Context, tenantID uuid.UUID) (repository.MSPBranding, error) {
	if tenantID == uuid.Nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: %w", repository.ErrInvalidArgument)
	}
	if cached, ok := r.cacheLookup(tenantID); ok {
		return cached, nil
	}
	tn, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: get tenant: %w", err)
	}
	resolved, err := r.ResolveForTenant(ctx, tn)
	if err != nil {
		return repository.MSPBranding{}, err
	}
	r.cacheStore(tenantID, resolved)
	return resolved, nil
}

// ResolveForTenant computes the effective branding starting from
// an already-fetched tenant row. Callers that have just performed
// a tenant write (e.g. setBranding's SetTenantBranding) avoid the
// duplicate Get the all-in-one Resolve would otherwise issue.
//
// Layered identically to Resolve:
//  1. Tenant override (per-field) — already on the supplied tn.
//  2. MSP default — fetched only when tn.MSPID is non-nil.
//  3. Platform DefaultBranding fallback.
//
// ErrNotFound on the MSP fetch is tolerated (dangling MSPID) so a
// soft-deleted MSP cannot break branding resolution for tenants
// whose denormalised pointer was not cleared.
func (r *BrandingResolver) ResolveForTenant(ctx context.Context, tn repository.Tenant) (repository.MSPBranding, error) {
	out := DefaultBranding

	// Layer 2: MSP default, if the tenant has an owner MSP. A
	// nil MSPID means the tenant is unmanaged (direct platform
	// customer) — skip the layer.
	if tn.MSPID != nil {
		msp, err := r.msps.Get(ctx, *tn.MSPID)
		if err != nil {
			// A dangling MSPID (e.g. the MSP was soft-deleted
			// and the denormalised pointer was not cleared)
			// must not break branding resolution. Log via the
			// returned error path but allow the resolver to
			// fall through to the platform default.
			if !errors.Is(err, repository.ErrNotFound) {
				return repository.MSPBranding{}, fmt.Errorf("branding resolve: get msp: %w", err)
			}
		} else {
			out = mergeBranding(out, msp.Branding)
		}
	}

	// Layer 1: tenant.settings.branding (per-field override).
	override, err := extractTenantBranding(tn.Settings)
	if err != nil {
		return repository.MSPBranding{}, fmt.Errorf("branding resolve: decode tenant settings: %w", err)
	}
	if override != nil {
		out = mergeBranding(out, *override)
	}

	return out, nil
}

// extractTenantBranding pulls the optional `branding` key out of
// the tenants.settings JSONB. Returns nil if settings is empty,
// the key is absent, or settings is a JSON `null`.
//
// A separate decode (rather than promoting branding to a typed
// column) is intentional: settings is a free-form JSONB used by
// multiple subsystems, and migration 015 stops short of carving
// out a typed `tenants.branding` column. The per-tenant override
// only needs a thin marshal/unmarshal.
func extractTenantBranding(settings json.RawMessage) (*repository.MSPBranding, error) {
	if len(settings) == 0 || string(settings) == "null" {
		return nil, nil
	}
	var s tenantBrandingSettings
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	return s.Branding, nil
}

// mergeBranding overlays `override` onto `base` per field. Empty
// strings in `override` leave the corresponding `base` field
// untouched, which is what gives us the per-field semantics: a
// tenant override that only sets `primary_color` inherits the
// remaining fields from the lower layer (MSP or platform default).
func mergeBranding(base, override repository.MSPBranding) repository.MSPBranding {
	out := base
	if override.LogoURL != "" {
		out.LogoURL = override.LogoURL
	}
	if override.PrimaryColor != "" {
		out.PrimaryColor = override.PrimaryColor
	}
	if override.SecondaryColor != "" {
		out.SecondaryColor = override.SecondaryColor
	}
	if override.CustomDomain != "" {
		out.CustomDomain = override.CustomDomain
	}
	if override.PortalSupportTo != "" {
		out.PortalSupportTo = override.PortalSupportTo
	}
	return out
}

// SetTenantBranding writes the per-field branding override into
// tenants.settings.branding. Empty fields in `override` are kept
// in the persisted JSON exactly as supplied — they are NOT
// canonicalised to absent — so the round-trip preserves the
// caller's intent (e.g. an operator deliberately blanks the
// custom domain).
//
// The settings JSON is read-modify-written: any other keys (e.g.
// feature flags belonging to other subsystems) are preserved.
func (r *BrandingResolver) SetTenantBranding(
	ctx context.Context,
	tenantID uuid.UUID,
	override repository.MSPBranding,
) (repository.Tenant, error) {
	if tenantID == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: %w", repository.ErrInvalidArgument)
	}
	// Encode the branding override into JSON and hand it to the
	// repository's atomic settings merge primitive. Round-17 of
	// Devin Review on PR #42 (ANALYSIS_0003) flagged that the
	// previous implementation did
	// Get→unmarshal→merge→marshal→Update entirely in the service
	// layer — two concurrent SetTenantBranding calls (or one
	// SetTenantBranding racing with ClearTenantBranding) could
	// each read the same `tn.Settings` baseline and the second
	// write would silently overwrite the first. Pushing the
	// jsonb_set into the row UPDATE makes the merge atomic at
	// the row level (postgres) / under the store mutex (memory),
	// preserving any other settings keys verbatim.
	encoded, err := json.Marshal(override)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: encode override: %w", err)
	}
	updated, err := r.tenants.UpdateSettingsKey(ctx, tenantID, "branding", encoded)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant branding: update settings: %w", err)
	}
	// Synchronous invalidation — a follow-up Resolve(tenantID)
	// after a successful SetTenantBranding MUST observe the new
	// override. Doing this after the Update succeeds (rather than
	// before) means a failed write does not leave an empty cache
	// behind that would force a needless recompute.
	r.Invalidate(tenantID)
	return updated, nil
}

// ClearTenantBranding removes the `branding` key from
// tenants.settings, restoring full inheritance from the MSP
// (or platform) default. Other settings keys are preserved. The
// removal is delegated to the repository's atomic
// DeleteSettingsKey so a concurrent SetTenantBranding cannot lose
// updates (see SetTenantBranding comment above and round-17 of
// Devin Review on PR #42 — ANALYSIS_0003).
func (r *BrandingResolver) ClearTenantBranding(ctx context.Context, tenantID uuid.UUID) (repository.Tenant, error) {
	if tenantID == uuid.Nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: %w", repository.ErrInvalidArgument)
	}
	updated, err := r.tenants.DeleteSettingsKey(ctx, tenantID, "branding")
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("clear tenant branding: update settings: %w", err)
	}
	// Synchronous invalidation — see SetTenantBranding above.
	r.Invalidate(tenantID)
	return updated, nil
}
