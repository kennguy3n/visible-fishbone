// Package appdb implements the Traffic Classification engine. It
// exposes:
//
//   - CRUD on the global app_registry (admin-only writes,
//     unrestricted reads — the catalog is the same for every
//     tenant).
//   - CRUD on per-tenant app_registry_overrides — RLS-isolated.
//   - ResolveTrafficClass(tenantID, domain) — the canonical
//     "what class is this domain in?" lookup, applying tenant
//     overrides first and falling back to the global registry.
//   - CompileSteeringRules(tenantID, target) — produces the
//     per-target steering tables the policy compiler embeds in
//     bundles (see internal/service/policy).
//
// See docs/TRAFFIC_CLASSIFICATION.md for the architecture.
package appdb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Service is the traffic-classification engine.
type Service struct {
	apps      repository.AppRegistryRepository
	overrides repository.AppRegistryOverrideRepository
	audit     repository.AuditLogRepository
	logger    *slog.Logger
	now       func() time.Time
}

// New constructs a Service. audit is optional but recommended —
// every classification mutation is logged in the audit trail when
// supplied.
func New(
	apps repository.AppRegistryRepository,
	overrides repository.AppRegistryOverrideRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		apps:      apps,
		overrides: overrides,
		audit:     audit,
		logger:    logger,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall-clock source. Used by tests; not
// part of the production wiring.
func (s *Service) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// --- Global registry CRUD (admin only) -----------------------------------

// CreateApp inserts a new global app entry. Caller must be
// admin-authenticated; enforcement happens at the handler layer.
func (s *Service) CreateApp(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	out, err := s.apps.Create(ctx, app)
	if err != nil {
		return out, err
	}
	s.audited(ctx, uuid.Nil, nil, "app_registry.created", &out.ID, mustJSON(map[string]any{
		"name":          out.Name,
		"traffic_class": string(out.TrafficClass),
	}))
	return out, nil
}

// GetApp returns a global app entry by id.
func (s *Service) GetApp(ctx context.Context, id uuid.UUID) (repository.AppRegistry, error) {
	return s.apps.Get(ctx, id)
}

// UpdateApp replaces a global app entry. Caller must be
// admin-authenticated.
func (s *Service) UpdateApp(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	out, err := s.apps.Update(ctx, app)
	if err != nil {
		return out, err
	}
	s.audited(ctx, uuid.Nil, nil, "app_registry.updated", &out.ID, mustJSON(map[string]any{
		"name":          out.Name,
		"traffic_class": string(out.TrafficClass),
	}))
	return out, nil
}

// SyncAppMetadata captures the per-row delta that produced an
// app.synced audit entry. The Syncer fills it in from
// canonical-form before/after slices so operators get forensic
// context — "what did the vendor change?" — without having to
// diff two opaque snapshots.
type SyncAppMetadata struct {
	// Source identifies the vendor parser that produced the
	// update (e.g. "endpoints.office.com"). Helps an operator
	// reading the audit trail know which upstream feed moved.
	Source string
	// DomainsBefore / DomainsAfter are the canonicalised
	// (lowercased, deduped, sorted) row counts before and after
	// the sync. Zero values are legitimate (an app may legitimately
	// drop all domains if the vendor publishes an empty list).
	DomainsBefore  int
	DomainsAfter   int
	IPRangesBefore int
	IPRangesAfter  int
}

// SyncUpdateApp is the write-path the Syncer uses to commit a
// vendor-driven refresh. It is intentionally separate from
// UpdateApp so the audit trail distinguishes operator-initiated
// edits (`app_registry.updated`) from automated vendor pulls
// (`app.synced`) — operators investigating a trust-list movement
// can filter on the action name without scanning details blobs.
//
// The audit entry carries the before/after counts and the source
// (vendor host) so a reader does not have to cross-reference an
// out-of-band sync log to understand what changed.
func (s *Service) SyncUpdateApp(
	ctx context.Context,
	app repository.AppRegistry,
	meta SyncAppMetadata,
) (repository.AppRegistry, error) {
	out, err := s.apps.Update(ctx, app)
	if err != nil {
		return out, err
	}
	s.audited(ctx, uuid.Nil, nil, "app.synced", &out.ID, mustJSON(map[string]any{
		"name":             out.Name,
		"traffic_class":    string(out.TrafficClass),
		"metadata_url":     out.MetadataURL,
		"source":           meta.Source,
		"domains_before":   meta.DomainsBefore,
		"domains_after":    meta.DomainsAfter,
		"ip_ranges_before": meta.IPRangesBefore,
		"ip_ranges_after":  meta.IPRangesAfter,
	}))
	return out, nil
}

// DeleteApp removes a global app entry. Caller must be
// admin-authenticated.
func (s *Service) DeleteApp(ctx context.Context, id uuid.UUID) error {
	if err := s.apps.Delete(ctx, id); err != nil {
		return err
	}
	s.audited(ctx, uuid.Nil, nil, "app_registry.deleted", &id, nil)
	return nil
}

// ListApps returns global apps matching filter.
func (s *Service) ListApps(ctx context.Context, filter repository.AppRegistryFilter, page repository.Page) (repository.PageResult[repository.AppRegistry], error) {
	return s.apps.List(ctx, filter, page)
}

// --- Tenant overrides CRUD -----------------------------------------------

// CreateOverride installs a tenant promotion/demotion. The
// `app_registry_overrides` schema requires either app_id or
// custom_domains (xor) — enforced both at the repository and the
// schema level.
func (s *Service) CreateOverride(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	ov repository.AppRegistryOverride,
) (repository.AppRegistryOverride, error) {
	out, err := s.overrides.Create(ctx, tenantID, ov)
	if err != nil {
		return out, err
	}
	s.audited(ctx, tenantID, actorID, "app_registry.override_created", &out.ID, mustJSON(map[string]any{
		"app_id":                 out.AppID,
		"traffic_class_override": string(out.TrafficClassOverride),
		"reason":                 out.Reason,
		"expires_at":             out.ExpiresAt,
	}))
	return out, nil
}

// DeleteOverride removes a tenant override.
func (s *Service) DeleteOverride(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := s.overrides.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	s.audited(ctx, tenantID, actorID, "app_registry.override_deleted", &id, nil)
	return nil
}

// ListOverrides returns tenant overrides with cursor pagination.
func (s *Service) ListOverrides(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.AppRegistryOverride], error) {
	return s.overrides.List(ctx, tenantID, page)
}

// EffectiveApp is the tenant-merged view of an app. The classification
// is computed by overlaying any tenant override on top of the global
// registry entry; the source is reported so operators can see
// where the decision came from.
type EffectiveApp struct {
	App               repository.AppRegistry  `json:"app"`
	EffectiveClass    repository.TrafficClass `json:"effective_class"`
	Source            string                  `json:"source"`            // "global" | "override"
	OverrideID        *uuid.UUID              `json:"override_id,omitempty"`
	OverrideExpiresAt *time.Time              `json:"override_expires_at,omitempty"`
	OverrideReason    string                  `json:"override_reason,omitempty"`
}

// ListEffective returns every classification visible to the tenant
// — global apps merged with tenant overrides, plus any tenant-local
// (custom_domains) overrides expressed as synthetic
// EffectiveApp rows. This is the view the operator console
// renders on the "App Registry" tab.
func (s *Service) ListEffective(ctx context.Context, tenantID uuid.UUID) ([]EffectiveApp, error) {
	apps, err := s.apps.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("appdb: list apps: %w", err)
	}
	ovs, err := s.overrides.ListAll(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("appdb: list overrides: %w", err)
	}
	byAppID := make(map[uuid.UUID]repository.AppRegistryOverride, len(ovs))
	customs := make([]repository.AppRegistryOverride, 0, len(ovs))
	now := s.now()
	for _, ov := range ovs {
		if ov.ExpiresAt != nil && !ov.ExpiresAt.After(now) {
			continue
		}
		if ov.AppID != nil {
			byAppID[*ov.AppID] = ov
			continue
		}
		customs = append(customs, ov)
	}

	out := make([]EffectiveApp, 0, len(apps)+len(customs))
	for _, app := range apps {
		ea := EffectiveApp{
			App:            app,
			EffectiveClass: app.TrafficClass,
			Source:         "global",
		}
		if ov, ok := byAppID[app.ID]; ok {
			id := ov.ID
			ea.EffectiveClass = ov.TrafficClassOverride
			ea.Source = "override"
			ea.OverrideID = &id
			ea.OverrideExpiresAt = ov.ExpiresAt
			ea.OverrideReason = ov.Reason
		}
		out = append(out, ea)
	}
	for _, ov := range customs {
		ov := ov
		id := ov.ID
		out = append(out, EffectiveApp{
			App: repository.AppRegistry{
				ID:           uuid.Nil,
				Name:         fmt.Sprintf("tenant-custom-%s", ov.ID.String()[:8]),
				TrafficClass: ov.TrafficClassOverride,
				Scope:        repository.AppRegistryScopeGlobal,
				Domains:      append([]string(nil), ov.CustomDomains...),
			},
			EffectiveClass:    ov.TrafficClassOverride,
			Source:            "override",
			OverrideID:        &id,
			OverrideExpiresAt: ov.ExpiresAt,
			OverrideReason:    ov.Reason,
		})
	}
	// Stable ordering by name for predictable UI rendering.
	sort.Slice(out, func(i, j int) bool {
		return out[i].App.Name < out[j].App.Name
	})
	return out, nil
}

// --- Resolution + steering compilation -----------------------------------

// ResolveTrafficClass returns the effective traffic class for a
// domain, considering tenant overrides first and falling back to
// the global registry. When no entry matches the domain the result
// is `inspect_full` — the safe baseline.
//
// Matching is suffix-based and wildcard-aware:
//   - `*.example.com` matches `foo.example.com`, `a.b.example.com`,
//     and `example.com` (the bare host is a common convention).
//   - A literal entry without a leading `*.` matches only exact
//     equality.
//
// The function is allocation-light because it sits on the hot path
// of every edge / agent classification call when the bundle's
// embedded steering table cannot be used (rare — typically only
// during a partial bundle roll-out).
func (s *Service) ResolveTrafficClass(ctx context.Context, tenantID uuid.UUID, domain string) (repository.TrafficClass, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", fmt.Errorf("appdb: empty domain: %w", repository.ErrInvalidArgument)
	}

	ovs, err := s.overrides.ListAll(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("appdb: list overrides: %w", err)
	}
	// Resolve the global catalog up front and index by ID. Both
	// the override pass (app-id-bound overrides need the app's
	// domain set to test for membership) and the fallback pass
	// need it, and pulling it once avoids the N+1 pattern of one
	// `apps.Get` per app-id override that a tenant with many
	// overrides used to trigger. Mirrors the strategy
	// CompileSteeringRules already uses.
	apps, err := s.apps.ListAll(ctx)
	if err != nil {
		return "", fmt.Errorf("appdb: list apps: %w", err)
	}
	appsByID := make(map[uuid.UUID]repository.AppRegistry, len(apps))
	for _, app := range apps {
		appsByID[app.ID] = app
	}
	now := s.now()
	// Walk overrides first — tenant intent wins.
	for _, ov := range ovs {
		if ov.ExpiresAt != nil && !ov.ExpiresAt.After(now) {
			continue
		}
		// Custom-domain override: match domain directly.
		if ov.AppID == nil {
			if matchAny(domain, ov.CustomDomains) {
				return ov.TrafficClassOverride, nil
			}
			continue
		}
		// Global-app override: consult the indexed catalog
		// rather than issuing a fresh Get per override.
		app, ok := appsByID[*ov.AppID]
		if !ok {
			// Override references a deleted app — leave the
			// row for the operator to clean up; treat as a
			// no-op on this resolution.
			continue
		}
		if matchAny(domain, app.Domains) {
			return ov.TrafficClassOverride, nil
		}
	}

	// Fall back to global classification using the same indexed catalog.
	// Match the most specific entry first (longest static suffix
	// wins) so a literal `outlook.office365.com` beats
	// `*.office365.com` when both exist.
	type hit struct {
		class    repository.TrafficClass
		score    int
		isLiteral bool
	}
	var best *hit
	for _, app := range apps {
		for _, pat := range app.Domains {
			if !matchesPattern(domain, pat) {
				continue
			}
			h := hit{class: app.TrafficClass, score: len(pat), isLiteral: !strings.HasPrefix(pat, "*.")}
			if best == nil || h.score > best.score || (h.score == best.score && h.isLiteral && !best.isLiteral) {
				bb := h
				best = &bb
			}
		}
	}
	if best != nil {
		return best.class, nil
	}
	return repository.TrafficClassInspectFull, nil
}

// SteeringRuleSet is the per-target output of CompileSteeringRules.
// It is JSON-serialisable so the policy compiler can embed it into
// the bundle envelope without an extra encoding step.
type SteeringRuleSet struct {
	// Target is the bundle target this rule set was compiled for
	// (mirrors repository.PolicyBundleTarget). Carried in the
	// envelope so a receiver can guard against bundle-shape drift.
	Target string `json:"target"`

	// SchemaVersion bumps when the on-wire shape changes
	// incompatibly. Receivers SHOULD refuse a higher version they
	// don't understand.
	//
	// Intentionally no CompiledAt field — the policy bundle
	// envelope that wraps this rule set already carries a
	// `CompiledAt`, and embedding a second wall-clock here would
	// break byte determinism (two compilations against the same
	// catalog would differ only in this timestamp, defeating
	// signature-cache de-dup).
	SchemaVersion int `json:"schema_version"`

	// Classes is the per-class rule slice, ordered by the
	// enumeration in AllTrafficClasses() for byte-deterministic
	// output.
	Classes []SteeringClassRules `json:"classes"`
}

// SteeringClassRules is the steering table for one traffic class.
type SteeringClassRules struct {
	Class    repository.TrafficClass `json:"class"`
	Action   string                  `json:"action"`              // direct | media_bypass | swg_lite | swg_full | tunnel | block
	Domains  []string                `json:"domains,omitempty"`   // sorted ascending for determinism
	IPRanges []string                `json:"ip_ranges,omitempty"` // sorted ascending
	CertPins []string                `json:"cert_pins,omitempty"` // sorted ascending
	Apps     []SteeringAppRef        `json:"apps,omitempty"`      // app provenance for telemetry / UI
}

// SteeringAppRef is a minimal reference to the app that produced a
// classification — enough for receivers to attribute a flow to a
// specific app without round-tripping the whole AppRegistry row.
type SteeringAppRef struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Source   string    `json:"source"` // "global" | "override"
	Category string    `json:"category,omitempty"`
}

// classAction maps a traffic class onto the canonical enforcement
// verb the receiver should apply. The receiver implements the
// verb; the control plane just emits the class + the verb.
var classAction = map[repository.TrafficClass]string{
	repository.TrafficClassTrustedDirect:      "direct",
	repository.TrafficClassTrustedMediaBypass: "media_bypass",
	repository.TrafficClassInspectLite:        "swg_lite",
	repository.TrafficClassInspectFull:        "swg_full",
	repository.TrafficClassTunnelPrivate:      "tunnel",
	repository.TrafficClassBlock:              "block",
}

// targetWantsClass reports whether `target` should receive the
// steering rules for `class`. The mapping mirrors the routing
// matrix in docs/TRAFFIC_CLASSIFICATION.md §3.
func targetWantsClass(target repository.PolicyBundleTarget, class repository.TrafficClass) bool {
	switch target {
	case repository.PolicyBundleTargetEdge:
		// Edge bundle carries the full table — every class.
		return true
	case repository.PolicyBundleTargetCloud:
		// Cloud bundle only receives inspect_full (the destination
		// for cloud-proxied traffic) and tunnel_private (the cloud
		// connector terminates the private tunnel). block is
		// included so the cloud proxy refuses traffic the rest of
		// the bundle says should never reach it.
		switch class {
		case repository.TrafficClassInspectFull,
			repository.TrafficClassTunnelPrivate,
			repository.TrafficClassBlock:
			return true
		}
		return false
	case repository.PolicyBundleTargetEndpoint:
		// Endpoint bundle needs every class to make steering
		// decisions locally (which traffic goes direct vs. cloud
		// proxy vs. tunnel).
		return true
	case repository.PolicyBundleTargetMobile:
		// Mobile carries only tunnel_private (ZTNA destinations)
		// and block.
		switch class {
		case repository.TrafficClassTunnelPrivate, repository.TrafficClassBlock:
			return true
		}
		return false
	}
	return false
}

// CompileSteeringRules produces the steering table for `target`.
// The output is byte-deterministic — equivalent inputs produce
// byte-identical bytes — so two compilations of the same policy
// graph and tenant overrides yield identical bundles. The compiler
// signature on `policy.Service` depends on this property.
func (s *Service) CompileSteeringRules(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (SteeringRuleSet, error) {
	if !isValidTarget(target) {
		return SteeringRuleSet{}, fmt.Errorf("appdb: invalid target %q: %w", target, repository.ErrInvalidArgument)
	}
	apps, err := s.apps.ListAll(ctx)
	if err != nil {
		return SteeringRuleSet{}, fmt.Errorf("appdb: list apps: %w", err)
	}
	ovs, err := s.overrides.ListAll(ctx, tenantID)
	if err != nil {
		return SteeringRuleSet{}, fmt.Errorf("appdb: list overrides: %w", err)
	}
	now := s.now()

	// Build the per-class buckets. The bucket key is the
	// effective traffic class for each app/override.
	type bucket struct {
		domains  map[string]struct{}
		ips      map[string]struct{}
		pins     map[string]struct{}
		apps     []SteeringAppRef
		seenApps map[uuid.UUID]struct{}
	}
	buckets := make(map[repository.TrafficClass]*bucket, len(repository.AllTrafficClasses()))
	for _, c := range repository.AllTrafficClasses() {
		buckets[c] = &bucket{
			domains:  map[string]struct{}{},
			ips:      map[string]struct{}{},
			pins:     map[string]struct{}{},
			seenApps: map[uuid.UUID]struct{}{},
		}
	}

	// Index overrides by app_id so we can short-circuit during the
	// apps walk.
	overrideByApp := make(map[uuid.UUID]repository.AppRegistryOverride, len(ovs))
	customs := make([]repository.AppRegistryOverride, 0, len(ovs))
	for _, ov := range ovs {
		if ov.ExpiresAt != nil && !ov.ExpiresAt.After(now) {
			continue
		}
		if ov.AppID != nil {
			overrideByApp[*ov.AppID] = ov
		} else {
			customs = append(customs, ov)
		}
	}

	// Walk global apps and slot them into the appropriate bucket.
	for _, app := range apps {
		class := app.TrafficClass
		source := "global"
		if ov, ok := overrideByApp[app.ID]; ok {
			class = ov.TrafficClassOverride
			source = "override"
		}
		b := buckets[class]
		for _, d := range app.Domains {
			b.domains[strings.ToLower(d)] = struct{}{}
		}
		for _, p := range app.IPRanges {
			b.ips[p.String()] = struct{}{}
		}
		for _, pin := range app.CertPins {
			b.pins[pin] = struct{}{}
		}
		if _, dup := b.seenApps[app.ID]; !dup {
			b.apps = append(b.apps, SteeringAppRef{
				ID: app.ID, Name: app.Name, Source: source, Category: app.Category,
			})
			b.seenApps[app.ID] = struct{}{}
		}
	}
	// Custom-domain overrides land in their target class with no
	// global app reference.
	for _, ov := range customs {
		b := buckets[ov.TrafficClassOverride]
		for _, d := range ov.CustomDomains {
			b.domains[strings.ToLower(d)] = struct{}{}
		}
	}

	// Materialise the per-target output in canonical class order.
	rs := SteeringRuleSet{
		Target:        string(target),
		SchemaVersion: 1,
		Classes:       make([]SteeringClassRules, 0, len(repository.AllTrafficClasses())),
	}
	for _, c := range repository.AllTrafficClasses() {
		if !targetWantsClass(target, c) {
			continue
		}
		b := buckets[c]
		cr := SteeringClassRules{
			Class:  c,
			Action: classAction[c],
		}
		cr.Domains = sortedKeys(b.domains)
		cr.IPRanges = sortedKeys(b.ips)
		cr.CertPins = sortedKeys(b.pins)
		// Sort app refs by ID for byte-determinism.
		if len(b.apps) > 0 {
			refs := make([]SteeringAppRef, len(b.apps))
			copy(refs, b.apps)
			sort.Slice(refs, func(i, j int) bool {
				return refs[i].ID.String() < refs[j].ID.String()
			})
			cr.Apps = refs
		}
		rs.Classes = append(rs.Classes, cr)
	}
	return rs, nil
}

// Encode renders the rule set to deterministic JSON bytes.
// Callers (the policy compiler) embed these bytes directly into
// the bundle envelope.
func (rs SteeringRuleSet) Encode() ([]byte, error) {
	return json.Marshal(rs)
}

// PolicySteeringAdapter wraps *Service so it satisfies the
// policy.SteeringCompiler interface (which returns `any` to avoid
// importing this package). The policy compiler JSON-encodes the
// result, so the interface widening is a pure type adapter — no
// allocations beyond the interface boxing.
type PolicySteeringAdapter struct{ Svc *Service }

// CompileSteeringRules dispatches to the underlying Service.
func (a PolicySteeringAdapter) CompileSteeringRules(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (any, error) {
	rs, err := a.Svc.CompileSteeringRules(ctx, tenantID, target)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// --- helpers --------------------------------------------------------------

func matchesPattern(domain, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return domain == base || strings.HasSuffix(domain, "."+base)
	}
	return domain == pattern
}

func matchAny(domain string, patterns []string) bool {
	for _, p := range patterns {
		if matchesPattern(domain, p) {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func isValidTarget(t repository.PolicyBundleTarget) bool {
	switch t {
	case repository.PolicyBundleTargetEdge,
		repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud,
		repository.PolicyBundleTargetMobile:
		return true
	}
	return false
}

func (s *Service) audited(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action string, resourceID *uuid.UUID, details json.RawMessage) {
	if s.audit == nil {
		return
	}
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	_, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: "app_registry",
		ResourceID:   resourceID,
		Details:      details,
	})
	if err != nil && s.logger != nil {
		// Audit failures used to be silently dropped, which hid
		// schema-level issues like the audit_log.tenant_id NOT
		// NULL constraint rejecting global mutations
		// (tenantID = uuid.Nil). Surfacing the failure as a
		// structured warning lets operators see when the audit
		// trail is incomplete — they should at minimum file a
		// follow-up to extend the schema for global events.
		// We deliberately do NOT propagate the error: the caller
		// has already mutated the underlying row, and failing
		// the API on audit-only errors would make the side
		// effects irreversible from the client's perspective.
		s.logger.WarnContext(ctx, "appdb: audit append failed",
			"action", action,
			"tenant_id", tenantID.String(),
			"error", err,
		)
	}
}

// netipMust is a small helper used by callers (tests, seed code)
// that already validated their CIDRs upstream and want a
// parse-or-die path.
func netipMust(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("appdb: invalid prefix %q: %v", s, err))
	}
	return p
}
