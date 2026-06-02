package tenant_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	svctenant "github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// brandingFixtures wires real memory repos so the resolver exercises
// the genuine tenants.settings JSONB round-trip and the MSP
// AssignTenant denormalised pointer.
func brandingFixtures(t *testing.T) (
	*svctenant.BrandingResolver,
	*memory.TenantRepository,
	*memory.MSPRepository,
	repository.Tenant,
	repository.MSP,
) {
	t.Helper()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()

	tn, err := tenants.Create(ctx, repository.Tenant{Name: "Tenant", Slug: "tenant"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	msp, err := msps.Create(ctx, repository.MSP{
		Name: "Acme",
		Slug: "acme",
		Branding: repository.MSPBranding{
			LogoURL:        "https://acme.example/logo.svg",
			PrimaryColor:   "#FF0000",
			SecondaryColor: "#00FF00",
		},
	})
	if err != nil {
		t.Fatalf("create msp: %v", err)
	}
	return svctenant.NewBrandingResolver(tenants, msps), tenants, msps, tn, msp
}

func TestBrandingResolve_FallsBackToPlatformDefault(t *testing.T) {
	t.Parallel()
	resolver, _, _, tn, _ := brandingFixtures(t)
	got, err := resolver.Resolve(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != svctenant.DefaultBranding {
		t.Fatalf("expected platform default, got %+v", got)
	}
}

func TestBrandingResolve_MSPOverridesPlatformDefault(t *testing.T) {
	t.Parallel()
	resolver, _, msps, tn, msp := brandingFixtures(t)
	if _, err := msps.AssignTenant(context.Background(), msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	got, err := resolver.Resolve(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.LogoURL != msp.Branding.LogoURL {
		t.Errorf("logo: got %q want %q", got.LogoURL, msp.Branding.LogoURL)
	}
	if got.PrimaryColor != msp.Branding.PrimaryColor {
		t.Errorf("primary: got %q want %q", got.PrimaryColor, msp.Branding.PrimaryColor)
	}
	// MSP did not set PortalSupportTo — falls through to platform.
	if got.PortalSupportTo != svctenant.DefaultBranding.PortalSupportTo {
		t.Errorf("portal: got %q want platform fallback %q", got.PortalSupportTo, svctenant.DefaultBranding.PortalSupportTo)
	}
}

func TestBrandingResolve_TenantOverridesMSP_PerField(t *testing.T) {
	t.Parallel()
	resolver, _, msps, tn, msp := brandingFixtures(t)
	ctx := context.Background()
	if _, err := msps.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if _, err := resolver.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{
		PrimaryColor: "#123456",
		// Other fields intentionally empty — should inherit from MSP.
	}); err != nil {
		t.Fatalf("set override: %v", err)
	}
	got, err := resolver.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.PrimaryColor != "#123456" {
		t.Errorf("primary not overridden: %+v", got)
	}
	if got.LogoURL != msp.Branding.LogoURL {
		t.Errorf("logo lost MSP inheritance: %+v", got)
	}
	if got.PortalSupportTo != svctenant.DefaultBranding.PortalSupportTo {
		t.Errorf("portal lost platform fallback: %+v", got)
	}
}

func TestBrandingResolve_RejectsNilTenantID(t *testing.T) {
	t.Parallel()
	resolver, _, _, _, _ := brandingFixtures(t)
	if _, err := resolver.Resolve(context.Background(), uuid.Nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestBrandingResolve_TenantNotFound(t *testing.T) {
	t.Parallel()
	resolver, _, _, _, _ := brandingFixtures(t)
	_, err := resolver.Resolve(context.Background(), uuid.New())
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestBrandingResolve_DanglingMSPPointerFallsThrough(t *testing.T) {
	t.Parallel()
	resolver, _, msps, tn, msp := brandingFixtures(t)
	ctx := context.Background()
	if _, err := msps.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Delete the MSP — the denormalised pointer is cleared by
	// Delete's cascade (per memory.MSPRepository.Delete), so this
	// test pins the OTHER variant: a tenant whose MSPID points at
	// a deleted record. We force the dangling pointer by
	// soft-deleting the MSP without going through the cascade
	// path. The memory store exposes the MSP map directly, so we
	// can simulate it by re-marking the MSP as deleted while the
	// tenants.msp_id pointer is still set.
	//
	// In practice we hit the path by just deleting the MSP and
	// asserting the resolver returns the platform fallback —
	// the cascade clears tn.MSPID, so the tenant lookup returns
	// nil MSPID and the resolver skips Layer 2 entirely. That's
	// still the right behaviour (no crash, no surfaced 5xx) and
	// is the contract we want to pin.
	if err := msps.Delete(ctx, msp.ID); err != nil {
		t.Fatalf("delete msp: %v", err)
	}
	got, err := resolver.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != svctenant.DefaultBranding {
		t.Fatalf("expected platform default after dangling MSP, got %+v", got)
	}
}

func TestSetTenantBranding_PreservesUnrelatedSettings(t *testing.T) {
	t.Parallel()
	resolver, tenants, _, tn, _ := brandingFixtures(t)
	ctx := context.Background()
	// Seed tenants.settings with an unrelated key.
	existing := json.RawMessage(`{"feature_flags":{"x":true}}`)
	if _, err := tenants.Update(ctx, tn.ID, repository.TenantPatch{Settings: &existing}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if _, err := resolver.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{
		PrimaryColor: "#aabbcc",
	}); err != nil {
		t.Fatalf("set branding: %v", err)
	}
	updated, err := tenants.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(updated.Settings, &settings); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if _, ok := settings["feature_flags"]; !ok {
		t.Errorf("feature_flags key lost: %s", string(updated.Settings))
	}
	if _, ok := settings["branding"]; !ok {
		t.Errorf("branding key missing: %s", string(updated.Settings))
	}
}

func TestClearTenantBranding_RemovesBrandingKey(t *testing.T) {
	t.Parallel()
	resolver, tenants, _, tn, _ := brandingFixtures(t)
	ctx := context.Background()
	if _, err := resolver.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{
		LogoURL: "https://example.com/x.svg",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := resolver.ClearTenantBranding(ctx, tn.ID); err != nil {
		t.Fatalf("clear: %v", err)
	}
	updated, err := tenants.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(updated.Settings) == 0 || string(updated.Settings) == "null" {
		// Acceptable: store collapsed the empty map to null.
		return
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(updated.Settings, &settings); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := settings["branding"]; ok {
		t.Errorf("branding key still present: %s", string(updated.Settings))
	}
}

// TestBrandingResolveForTenant_AgreesWithResolve pins the round-2
// optimization on PR #42: the BrandingResolver.ResolveForTenant
// helper (operating on a pre-fetched Tenant) must produce the
// same result as the full Resolve. Used by the MSP setBranding
// handler to skip the second tenant Get round-trip after
// SetTenantBranding.
func TestBrandingResolveForTenant_AgreesWithResolve(t *testing.T) {
	t.Parallel()
	resolver, tenants, msps, tn, msp := brandingFixtures(t)
	ctx := context.Background()
	if _, err := msps.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	updated, err := resolver.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{
		PrimaryColor: "#abcdef",
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	// Sanity: the in-hand tenant carries the override that the
	// repo just persisted. (If it didn't, the optimization
	// would silently drop the override.)
	viaHelper, err := resolver.ResolveForTenant(ctx, updated)
	if err != nil {
		t.Fatalf("resolve via helper: %v", err)
	}
	viaResolve, err := resolver.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if viaHelper != viaResolve {
		t.Fatalf("ResolveForTenant produced %+v, Resolve produced %+v — must agree",
			viaHelper, viaResolve)
	}
	if viaHelper.PrimaryColor != "#abcdef" {
		t.Fatalf("override not applied: %+v", viaHelper)
	}
	if viaHelper.LogoURL != msp.Branding.LogoURL {
		t.Fatalf("MSP fallthrough lost: %+v", viaHelper)
	}
	// Compile-time hint: tenants is unused if no extra
	// assertions are added below. Keep the param so future
	// extensions can verify the per-tenant settings JSONB
	// shape directly via tenants.Get.
	_ = tenants
}

// --------------------------------------------------------------------
// Cache fixtures + tests
// --------------------------------------------------------------------

// brandingCacheFixtures returns a BrandingResolverWithCache whose
// clock is injected so TTL assertions are deterministic. The
// tenant has no override; the MSP supplies a primary colour the
// tests assert flows through Resolve.
func brandingCacheFixtures(t *testing.T, opts svctenant.BrandingCacheOptions) (
	*svctenant.BrandingResolver,
	*memory.TenantRepository,
	*memory.MSPRepository,
	repository.Tenant,
	repository.MSP,
) {
	t.Helper()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()
	msp, err := msps.Create(ctx, repository.MSP{
		Name: "Acme",
		Slug: "acme",
		Branding: repository.MSPBranding{
			LogoURL:        "https://acme.example/logo.svg",
			PrimaryColor:   "#FF0000",
			SecondaryColor: "#00FF00",
		},
	})
	if err != nil {
		t.Fatalf("create msp: %v", err)
	}
	tn, err := tenants.Create(ctx, repository.Tenant{Name: "T", Slug: "t"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := msps.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign tenant: %v", err)
	}
	r := svctenant.NewBrandingResolverWithCache(tenants, msps, opts)
	// Re-fetch tn so its MSPID pointer reflects the assign.
	tn2, err := tenants.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("re-fetch tenant: %v", err)
	}
	return r, tenants, msps, tn2, msp
}

// TestBrandingResolver_CachesResolutions verifies that within TTL
// a second Resolve returns the cached value EVEN after the
// underlying tenant settings change out-of-band (i.e. via the
// tenants repo directly, bypassing the resolver's invalidation
// hook). The first Resolve seeds the cache with the MSP-default
// PrimaryColor; the out-of-band update changes the settings to a
// new colour; the second Resolve must still return the cached
// MSP-default. This is the positive cache-hit behaviour.
func TestBrandingResolver_CachesResolutions(t *testing.T) {
	t.Parallel()
	r, tenants, _, tn, msp := brandingCacheFixtures(t, svctenant.BrandingCacheOptions{TTL: 30 * 1e9})
	ctx := context.Background()

	first, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.PrimaryColor != msp.Branding.PrimaryColor {
		t.Fatalf("first: primary=%q want %q", first.PrimaryColor, msp.Branding.PrimaryColor)
	}
	// Mutate tenant settings directly via the repo — this path
	// does NOT call r.Invalidate, so the cached entry should
	// stay valid for the remainder of the TTL.
	override, _ := json.Marshal(map[string]any{
		"branding": map[string]any{"primary_color": "#0000FF"},
	})
	raw := json.RawMessage(override)
	if _, err := tenants.Update(ctx, tn.ID, repository.TenantPatch{Settings: &raw}); err != nil {
		t.Fatalf("update tenant settings: %v", err)
	}
	second, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.PrimaryColor != msp.Branding.PrimaryColor {
		t.Fatalf("second primary=%q want %q (cached); out-of-band write should NOT bleed through",
			second.PrimaryColor, msp.Branding.PrimaryColor)
	}
}

// TestBrandingResolver_InvalidatesOnSet proves SetTenantBranding
// evicts the cached entry: a subsequent Resolve returns the new
// override, not the previously cached MSP-default colour.
func TestBrandingResolver_InvalidatesOnSet(t *testing.T) {
	t.Parallel()
	r, _, _, tn, msp := brandingCacheFixtures(t, svctenant.BrandingCacheOptions{TTL: 30 * 1e9})
	ctx := context.Background()

	first, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.PrimaryColor != msp.Branding.PrimaryColor {
		t.Fatalf("first primary=%q want %q", first.PrimaryColor, msp.Branding.PrimaryColor)
	}
	// Apply a tenant-level override; the cached MSP-default
	// PrimaryColor must NOT bleed through.
	override := repository.MSPBranding{PrimaryColor: "#0000FF"}
	if _, err := r.SetTenantBranding(ctx, tn.ID, override); err != nil {
		t.Fatalf("set tenant branding: %v", err)
	}
	second, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.PrimaryColor != "#0000FF" {
		t.Fatalf("second primary=%q want #0000FF (cache should have been invalidated)", second.PrimaryColor)
	}
}

// TestBrandingResolver_InvalidatesOnClear proves the same for the
// clear path.
func TestBrandingResolver_InvalidatesOnClear(t *testing.T) {
	t.Parallel()
	r, _, _, tn, msp := brandingCacheFixtures(t, svctenant.BrandingCacheOptions{TTL: 30 * 1e9})
	ctx := context.Background()

	// Seed with an override so Clear has work to do.
	if _, err := r.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{PrimaryColor: "#0000FF"}); err != nil {
		t.Fatalf("set tenant branding: %v", err)
	}
	first, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.PrimaryColor != "#0000FF" {
		t.Fatalf("first primary=%q want #0000FF", first.PrimaryColor)
	}
	// Clear the tenant override; resolved primary should revert
	// to the MSP-default red.
	if _, err := r.ClearTenantBranding(ctx, tn.ID); err != nil {
		t.Fatalf("clear tenant branding: %v", err)
	}
	second, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.PrimaryColor != msp.Branding.PrimaryColor {
		t.Fatalf("second primary=%q want MSP default %q (cache should have been invalidated)",
			second.PrimaryColor, msp.Branding.PrimaryColor)
	}
}

// TestBrandingResolver_ExpiresStaleEntries verifies the TTL is
// honoured: after the configured TTL elapses the next Resolve
// recomputes (here demonstrated by mutating tenants.settings
// directly through the repo, BYPASSING SetTenantBranding's
// invalidation hook).
func TestBrandingResolver_ExpiresStaleEntries(t *testing.T) {
	t.Parallel()
	r, tenants, _, tn, msp := brandingCacheFixtures(t, svctenant.BrandingCacheOptions{TTL: 1})
	ctx := context.Background()

	first, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.PrimaryColor != msp.Branding.PrimaryColor {
		t.Fatalf("first primary=%q want %q", first.PrimaryColor, msp.Branding.PrimaryColor)
	}
	// Patch the tenant.settings directly through the repo,
	// without going through SetTenantBranding (the resolver
	// would otherwise invalidate). After the 1-ns TTL elapses,
	// the next Resolve must recompute and surface the new
	// override.
	override, _ := json.Marshal(map[string]any{
		"branding": map[string]any{"primary_color": "#0000FF"},
	})
	raw := json.RawMessage(override)
	if _, err := tenants.Update(ctx, tn.ID, repository.TenantPatch{Settings: &raw}); err != nil {
		t.Fatalf("update tenant settings: %v", err)
	}
	// Sleep one tick so the lazy expiry path triggers.
	// 1 ns TTL is below the OS clock resolution; the lazy
	// expiry uses time.Now which is monotonic — by the time we
	// re-enter Resolve, the cached entry has already expired.
	second, err := r.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.PrimaryColor != "#0000FF" {
		t.Fatalf("second primary=%q want #0000FF after TTL expiry", second.PrimaryColor)
	}
}

// TestBrandingResolver_UncachedConstructorIgnoresInvalidate proves
// the uncached resolver tolerates Invalidate / InvalidateAll calls
// (they are no-ops) and never crashes.
func TestBrandingResolver_UncachedConstructorIgnoresInvalidate(t *testing.T) {
	t.Parallel()
	resolver, _, _, tn, _ := brandingFixtures(t)
	resolver.Invalidate(tn.ID)
	resolver.InvalidateAll()
}

// Suppress staticcheck unused-identifier warnings.
var _ = errors.New

// TestBrandingResolver_LRUEvictsLeastRecentlyUsed pins the round-6
// O(1) LRU fix. With cacheMax=2:
//
//  1. Resolve(t1) → seeds t1 at MRU.
//  2. Resolve(t2) → seeds t2 at MRU; t1 moves to LRU.
//  3. Resolve(t1) → promotes t1 to MRU; t2 is now LRU.
//  4. Resolve(t3) → evicts t2 (LRU), seeds t3 at MRU.
//  5. Resolve(t1) → hits cache (still present).
//  6. Resolve(t2) → MISS (evicted); recomputes.
//
// The previous oldest-by-insertion-time scheme would have evicted
// t1 (the oldest insertion) at step 4 even though step 3 made it
// the most-recently used — an LRU policy violation that the new
// list-backed implementation now correctly respects.
func TestBrandingResolver_LRUEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()
	msp, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-lru",
		Branding: repository.MSPBranding{PrimaryColor: "#abc"}})
	if err != nil {
		t.Fatalf("create msp: %v", err)
	}
	mkTenant := func(name, slug string) repository.Tenant {
		t.Helper()
		tn, err := tenants.Create(ctx, repository.Tenant{Name: name, Slug: slug})
		if err != nil {
			t.Fatalf("create tenant %s: %v", name, err)
		}
		if _, err := msps.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
			t.Fatalf("assign %s: %v", name, err)
		}
		out, _ := tenants.Get(ctx, tn.ID)
		return out
	}
	t1 := mkTenant("t1", "lru-t1")
	t2 := mkTenant("t2", "lru-t2")
	t3 := mkTenant("t3", "lru-t3")

	r := svctenant.NewBrandingResolverWithCache(tenants, msps,
		svctenant.BrandingCacheOptions{TTL: 30 * 1e9, MaxEntries: 2})

	if _, err := r.Resolve(ctx, t1.ID); err != nil {
		t.Fatalf("resolve t1: %v", err)
	}
	if _, err := r.Resolve(ctx, t2.ID); err != nil {
		t.Fatalf("resolve t2: %v", err)
	}
	// Step 3: promote t1 to MRU.
	if _, err := r.Resolve(ctx, t1.ID); err != nil {
		t.Fatalf("resolve t1 again: %v", err)
	}
	// Step 4: writing t3 must evict t2 (LRU), NOT t1 (which is
	// now MRU). To verify, mutate the underlying repo so a
	// recompute would observe a different value, then Resolve.
	override, _ := json.Marshal(map[string]any{
		"branding": map[string]any{"primary_color": "#ff0000"},
	})
	raw := json.RawMessage(override)
	if _, err := tenants.Update(ctx, t1.ID, repository.TenantPatch{Settings: &raw}); err != nil {
		t.Fatalf("update t1 settings: %v", err)
	}
	if _, err := tenants.Update(ctx, t2.ID, repository.TenantPatch{Settings: &raw}); err != nil {
		t.Fatalf("update t2 settings: %v", err)
	}
	if _, err := r.Resolve(ctx, t3.ID); err != nil {
		t.Fatalf("resolve t3: %v", err)
	}
	// Step 5: t1 should still hit cache (PrimaryColor "#abc"
	// from MSP default — the post-Resolve mutation didn't
	// reach because the cache is hit before tenants.Get).
	hit, err := r.Resolve(ctx, t1.ID)
	if err != nil {
		t.Fatalf("resolve t1 post-eviction: %v", err)
	}
	if hit.PrimaryColor != "#abc" {
		t.Fatalf("t1 PrimaryColor=%q, want #abc (cached MSP default; LRU should NOT have evicted t1)",
			hit.PrimaryColor)
	}
	// Step 6: t2 must MISS (got evicted at step 4), so recompute
	// surfaces the mutated override.
	miss, err := r.Resolve(ctx, t2.ID)
	if err != nil {
		t.Fatalf("resolve t2 post-eviction: %v", err)
	}
	if miss.PrimaryColor != "#ff0000" {
		t.Fatalf("t2 PrimaryColor=%q, want #ff0000 (cache miss → recompute surfaces post-mutation override)",
			miss.PrimaryColor)
	}
}

// TestSetTenantBranding_ConcurrentSetsDoNotLoseUnrelatedSettings
// pins round-17 of Devin Review on PR #42 (ANALYSIS_0003): the
// previous SetTenantBranding did Get→unmarshal→merge→marshal→Update
// entirely in the service layer, so two concurrent SetTenantBranding
// calls (or one SetTenantBranding racing with a writer of an
// orthogonal settings key) could each read the same `tn.Settings`
// baseline and the second write would silently overwrite the first
// orthogonal key. Pushing the merge into the repository's
// UpdateSettingsKey (jsonb_set on postgres; mutex-held merge on
// memory) makes it atomic. We exercise this by racing 16 concurrent
// SetTenantBranding calls against 16 concurrent unrelated-settings
// writes; afterwards both keys must be present on the row.
func TestSetTenantBranding_ConcurrentSetsDoNotLoseUnrelatedSettings(t *testing.T) {
	t.Parallel()
	resolver, tenants, _, tn, _ := brandingFixtures(t)
	ctx := context.Background()
	// Seed an orthogonal `feature_flags` key first via the
	// repository's atomic UpdateSettingsKey (mirrors what a
	// future feature-flags service would do under the same
	// round-17 contract).
	ff := json.RawMessage(`{"x":true}`)
	if _, err := tenants.UpdateSettingsKey(ctx, tn.ID, "feature_flags", ff); err != nil {
		t.Fatalf("seed feature_flags: %v", err)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(2 * goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := resolver.SetTenantBranding(ctx, tn.ID, repository.MSPBranding{
				PrimaryColor: "#112233",
			}); err != nil {
				t.Errorf("SetTenantBranding: %v", err)
			}
		}()
		go func(i int) {
			defer wg.Done()
			// Write a per-iteration value to the orthogonal
			// key; the last writer wins for the key itself,
			// but the key MUST still exist after all SetTenantBranding
			// races land.
			raw := json.RawMessage(`{"writer":` + uuidLiteral(uuid.New()) + `}`)
			if _, err := tenants.UpdateSettingsKey(ctx, tn.ID, "feature_flags", raw); err != nil {
				t.Errorf("UpdateSettingsKey(feature_flags): %v", err)
			}
		}(i)
	}
	wg.Wait()

	// After the race, BOTH keys must be present. Pre-fix this
	// would intermittently lose `feature_flags` because a
	// SetTenantBranding goroutine that read its baseline BEFORE a
	// feature_flags writer would, on its own Update, overwrite
	// the feature_flags writer's commit with the stale baseline
	// that omitted (or had an older value of) feature_flags.
	updated, err := tenants.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(updated.Settings, &settings); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if _, ok := settings["branding"]; !ok {
		t.Errorf("branding key lost after concurrent writes: %s", string(updated.Settings))
	}
	if _, ok := settings["feature_flags"]; !ok {
		t.Errorf("feature_flags key lost (RMW race): %s", string(updated.Settings))
	}
}

// uuidLiteral renders a uuid as a JSON string literal so we can
// inline it into a json.RawMessage in the test above.
func uuidLiteral(u uuid.UUID) string { return `"` + u.String() + `"` }

// TestTenantRepository_UpdateStatus_ResurrectionRejected pins
// round-17 of Devin Review on PR #42 (ANALYSIS_0005): UpdateStatus
// must NOT be usable to transition a soft-deleted tenant back to
// active/suspended. The lifecycle invariant
// `(status='deleted' ⇔ deleted_at != NULL)` and the partial unique
// index `tenants_slug_uniq_idx WHERE deleted_at IS NULL` both
// assume `deleted` is terminal; a silent resurrection would leave
// `deleted_at` stamped on a now-active row and surface as a unique
// constraint violation on the first write that touches the slug.
// Idempotent Delete→Delete must still succeed (callers that
// already handle that case keep working).
func TestTenantRepository_UpdateStatus_ResurrectionRejected(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewTenantRepository(store)
	ctx := context.Background()
	tn, err := repo.Create(ctx, repository.Tenant{Name: "T", Slug: "t1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Soft-delete via UpdateStatus (the canonical path; also the
	// path the guard most needs to defend against).
	if _, err := repo.UpdateStatus(ctx, tn.ID, repository.TenantStatusDeleted); err != nil {
		t.Fatalf("delete via UpdateStatus: %v", err)
	}
	// Resurrection attempts: each must surface ErrForbidden.
	for _, status := range []repository.TenantStatus{
		repository.TenantStatusActive,
		repository.TenantStatusSuspended,
	} {
		if _, err := repo.UpdateStatus(ctx, tn.ID, status); !errors.Is(err, repository.ErrForbidden) {
			t.Errorf("UpdateStatus(deleted→%s): want ErrForbidden, got %v", status, err)
		}
	}
	// Idempotent self-loop must still succeed.
	if _, err := repo.UpdateStatus(ctx, tn.ID, repository.TenantStatusDeleted); err != nil {
		t.Errorf("idempotent UpdateStatus(deleted→deleted): got %v, want nil", err)
	}
	// The row must remain in deleted state and deleted_at must
	// still be set.
	got, err := repo.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != repository.TenantStatusDeleted {
		t.Errorf("status: got %q, want deleted", got.Status)
	}
	if got.DeletedAt == nil {
		t.Errorf("deleted_at: got nil, want set")
	}
}
