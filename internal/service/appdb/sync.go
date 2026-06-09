package appdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Syncer pulls vendor-published endpoint lists and updates the
// corresponding app_registry rows. Examples:
//
//   - Microsoft 365 endpoints JSON
//     https://endpoints.office.com/endpoints/worldwide
//   - Google IP ranges JSON
//     https://www.gstatic.com/ipranges/goog.json
//   - AWS IP ranges
//     https://ip-ranges.amazonaws.com/ip-ranges.json
//
// Each vendor publishes a different shape; the Syncer dispatches to
// a per-vendor parser by inspecting the metadata_url host. Unknown
// hosts fall back to the generic JSON parser which expects a
// `{ "domains": [...], "ip_ranges": [...] }` shape. Operators can
// extend the dispatch table with custom parsers via
// RegisterParser.
type Syncer struct {
	svc    *Service
	client *http.Client
	now    func() time.Time

	mu      sync.RWMutex
	parsers map[string]VendorParser

	// syncSem is a 1-slot buffered channel used as a context-aware
	// semaphore that serialises SyncAll across the periodic Run
	// goroutine and the admin-triggered POST /admin/app-registry/
	// sync endpoint.
	//
	// Two concurrent SyncAll invocations would otherwise (a)
	// double-fetch every vendor endpoint (wasted bandwidth,
	// possible vendor-side rate-limit trips), (b) race on the
	// repository update path producing duplicate `app.synced`
	// audit entries for the same row, and (c) interleave the
	// failure counter updates in runOnce producing nonsensical
	// streak values. A single sync invocation typically completes
	// in under a minute even with 20+ apps, so an admin-triggered
	// call arriving mid-tick blocks briefly and then runs — no
	// need for the more complex "share the in-flight result"
	// semantics of singleflight.Group (which would also surprise
	// the admin caller by returning the periodic loop's stale
	// result instead of the fresh sync they requested).
	//
	// We use a channel instead of sync.Mutex because sync.Mutex.Lock
	// is context-oblivious — wrapping it in a select-on-ctx requires
	// spawning a "wait for the lock" goroutine that outlives the
	// caller when ctx fires first, which can pile up if many short-
	// deadline admin calls hit a slow tick in succession. The
	// channel form acquires atomically inside the same select that
	// observes ctx.Done(), so cancellation is a clean no-op without
	// any orphan goroutine.
	syncSem chan struct{}

	// failures tracks consecutive sync failures per app id so the
	// Run loop can log a sustained-failure warning once the
	// threshold (3 by default, per docs/TRAFFIC_CLASSIFICATION.md
	// §8) is reached. A successful sync resets the counter for
	// that app. Protected by mu rather than syncMu because runOnce
	// is the only writer and it always holds syncMu while touching
	// these maps — mu remains in place as a defensive guard for
	// the (currently unused) external read path.
	failures            map[string]int
	sustainedThreshold  int
	sustainedReportSent map[string]bool
}

// VendorParser parses a vendor's endpoint response into a flat
// (domains, ip_ranges) tuple. The parser receives the raw response
// bytes and the AppRegistry row being refreshed so it can scope
// the parse to the relevant service (e.g. Microsoft endpoint JSON
// covers M365, Skype, Sharepoint as separate "serviceArea"s in one
// document).
type VendorParser func(body []byte, currentDomains []string) (domains []string, ipRanges []netip.Prefix, err error)

// NewSyncer constructs a Syncer with a default 30-second HTTP
// timeout and the built-in vendor parsers registered (Microsoft,
// Google, AWS, generic).
func NewSyncer(svc *Service, client *http.Client) *Syncer {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	s := &Syncer{
		svc:                 svc,
		client:              client,
		now:                 func() time.Time { return time.Now().UTC() },
		parsers:             map[string]VendorParser{},
		syncSem:             make(chan struct{}, 1),
		failures:            map[string]int{},
		sustainedThreshold:  3, // matches docs/TRAFFIC_CLASSIFICATION.md §8
		sustainedReportSent: map[string]bool{},
	}
	s.RegisterParser("endpoints.office.com", parseMicrosoftEndpoints)
	s.RegisterParser("www.gstatic.com", parseGoogleIPRanges)
	s.RegisterParser("ip-ranges.amazonaws.com", parseAWSIPRanges)
	// Plaintext CIDR-per-line feeds (Zoom, Cloudflare).
	s.RegisterParser("assets.zoom.us", parsePlaintextCIDRList)
	s.RegisterParser("www.cloudflare.com", parsePlaintextCIDRList)
	// JSON feeds with bespoke shapes.
	s.RegisterParser("api.github.com", parseGitHubMeta)
	s.RegisterParser("api.fastly.com", parseFastlyIPList)
	return s
}

// SetClock replaces the wall-clock source. Tests use this to keep
// updated_at deterministic.
func (s *Syncer) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// RegisterParser binds a parser to a metadata_url host. The most
// specific host match wins; the generic JSON parser is used when
// nothing matches.
func (s *Syncer) RegisterParser(host string, p VendorParser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parsers[strings.ToLower(host)] = p
}

// SyncResult is the per-app outcome from one SyncAll invocation.
type SyncResult struct {
	AppID          string `json:"app_id"`
	AppName        string `json:"app_name"`
	MetadataURL    string `json:"metadata_url"`
	DomainsBefore  int    `json:"domains_before"`
	DomainsAfter   int    `json:"domains_after"`
	IPRangesBefore int    `json:"ip_ranges_before"`
	IPRangesAfter  int    `json:"ip_ranges_after"`
	Updated        bool   `json:"updated"`
	Err            string `json:"error,omitempty"`
}

// SyncAll iterates every app with a non-empty metadata_url, fetches
// the upstream document, and updates the app's domains / IP ranges
// if they differ. The function never aborts on a single fetch
// failure — it accumulates per-app results so the operator can see
// which vendors are healthy.
//
// SyncAll is serialised by syncSem — only one invocation runs at
// a time across the periodic Run loop and the admin-triggered
// endpoint. See the syncSem doc on the Syncer struct for the
// rationale.
func (s *Syncer) SyncAll(ctx context.Context) ([]SyncResult, error) {
	// Acquire syncSem in a select that also observes ctx.Done(),
	// so a cancelled caller (admin client disconnect, shutdown
	// signal, request deadline) returns immediately without
	// spawning a background goroutine that would outlive the
	// caller waiting for the current sync to finish. The send
	// succeeds when the channel has spare capacity (no sync in
	// flight) and blocks otherwise; the matching receive on the
	// defer releases the slot.
	select {
	case s.syncSem <- struct{}{}:
		defer func() { <-s.syncSem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("sync: %w", ctx.Err())
	}

	apps, err := s.svc.apps.ListWithMetadataURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync: list apps with metadata: %w", err)
	}
	results := make([]SyncResult, 0, len(apps))
	for _, app := range apps {
		// Canonicalise the existing rows up front so the
		// SyncResult Before / After counts are always
		// comparable to each other (both reflect deduped,
		// lowercased, sorted sets) and consistent with the
		// audit-log entry emitted by SyncUpdateApp below.
		// mergeDomains / mergeRanges with a nil "new" slice
		// is the canonical-only form.
		currentCanonicalDomains := mergeDomains(app.Domains, nil)
		currentCanonicalRanges := mergeRanges(app.IPRanges, nil)
		r := SyncResult{
			AppID:          app.ID.String(),
			AppName:        app.Name,
			MetadataURL:    app.MetadataURL,
			DomainsBefore:  len(currentCanonicalDomains),
			IPRangesBefore: len(currentCanonicalRanges),
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, app.MetadataURL, nil)
		if err != nil {
			r.Err = fmt.Sprintf("new request: %v", err)
			results = append(results, r)
			continue
		}
		req.Header.Set("User-Agent", "shieldnet-gateway-appdb-sync/1.0")
		resp, err := s.client.Do(req)
		if err != nil {
			r.Err = fmt.Sprintf("http: %v", err)
			results = append(results, r)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			r.Err = fmt.Sprintf("read body: %v", readErr)
			results = append(results, r)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			r.Err = fmt.Sprintf("http %d: %s", resp.StatusCode, snippet(body))
			results = append(results, r)
			continue
		}

		parser := s.parserFor(app.MetadataURL)
		newDomains, newRanges, perr := parser(body, app.Domains)
		if perr != nil {
			r.Err = fmt.Sprintf("parse: %v", perr)
			results = append(results, r)
			continue
		}
		// Compare against the *canonical* form of the existing
		// rows (lowercase, deduped, sorted — pre-computed above)
		// on both sides so a sync whose only effect is
		// normalisation -- e.g. an existing row has
		// "Outlook.Office.com" / unsorted CIDRs and the vendor
		// publishes the same data with different case or order
		// -- does not register as a change. Without
		// canonicalising the existing slices, the first sync
		// after a release would rewrite every app that was
		// admin-inserted with mixed case or insertion-ordered
		// CIDRs, generating spurious UPDATE rows + audit-log
		// entries + NATS bundle invalidations even when the
		// vendor data is unchanged.
		merged := mergeDomains(app.Domains, newDomains)
		mergedRanges := mergeRanges(app.IPRanges, newRanges)
		changed := !equalStringSlices(merged, currentCanonicalDomains) ||
			!equalRangeSlices(mergedRanges, currentCanonicalRanges)

		r.DomainsAfter = len(merged)
		r.IPRangesAfter = len(mergedRanges)
		if changed {
			app.Domains = merged
			app.IPRanges = mergedRanges
			app.UpdatedAt = s.now()
			// Route through SyncUpdateApp (not the raw
			// repository) so the mutation emits a dedicated
			// `app.synced` audit entry with before/after
			// counts. Calling s.svc.apps.Update directly
			// bypassed the audit trail entirely — a poisoned
			// vendor endpoint could rewrite domains and
			// ip_ranges with zero forensic record. Using the
			// generic UpdateApp would log an `app_registry.updated`
			// entry instead, which is harder for an operator
			// to filter for "what did the auto-sync touch?".
			meta := SyncAppMetadata{
				Source:         hostFromURL(app.MetadataURL),
				DomainsBefore:  len(currentCanonicalDomains),
				DomainsAfter:   len(merged),
				IPRangesBefore: len(currentCanonicalRanges),
				IPRangesAfter:  len(mergedRanges),
			}
			if _, uerr := s.svc.SyncUpdateApp(ctx, app, meta); uerr != nil {
				r.Err = fmt.Sprintf("update: %v", uerr)
				results = append(results, r)
				continue
			}
			r.Updated = true
		}
		results = append(results, r)
	}
	return results, nil
}

// Run launches the periodic sync loop. Returns when ctx is
// canceled. The loop calls SyncAll on every tick and inspects the
// per-app results so individual fetch / parse / update failures
// (which SyncAll returns inside SyncResult.Err rather than as a
// top-level error) are surfaced to operators. Sustained per-app
// failures (≥ sustainedThreshold consecutive misses, default 3
// per docs/TRAFFIC_CLASSIFICATION.md §8) escalate from a per-app
// warning to a per-app error and set a sticky flag so the operator
// only sees the louder log line once per failure streak.
//
// The first sync runs immediately at startup rather than waiting
// a full interval. With the default 24h cadence, a tick-only loop
// would leave a fresh deployment running on stale seed data for
// up to a day before the first vendor pull — a real correctness
// gap if a vendor has rotated their published CIDRs since the
// seed migration was authored. The startup pass is best-effort:
// any error is logged and the periodic loop continues normally,
// matching the in-loop error-handling contract.
//
// app.sync_failed webhook delivery (docs §8) is intentionally not
// fired here yet — the webhook event-type registry has not grown
// the new event, and registering it spans the webhook subsystem.
// Sustained failures are surfaced via structured logging in the
// meantime; the webhook hookpoint is documented inline so the
// follow-up is discoverable.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	s.runOnce(ctx, "appdb startup sync")
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.runOnce(ctx, "appdb sync")
		}
	}
}

// runOnce executes a single SyncAll and surfaces per-app failures
// to the logger. Successes reset the consecutive-failure counter
// and clear the sustained-failure sticky flag.
func (s *Syncer) runOnce(ctx context.Context, label string) {
	results, err := s.SyncAll(ctx)
	if err != nil {
		s.svc.logger.ErrorContext(ctx, label+" failed", "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		if r.Err == "" {
			if s.failures[r.AppID] > 0 || s.sustainedReportSent[r.AppID] {
				s.svc.logger.InfoContext(ctx, "appdb sync recovered",
					"app_id", r.AppID,
					"app_name", r.AppName,
					"after_consecutive_failures", s.failures[r.AppID],
				)
			}
			delete(s.failures, r.AppID)
			delete(s.sustainedReportSent, r.AppID)
			continue
		}
		s.failures[r.AppID]++
		streak := s.failures[r.AppID]
		if streak >= s.sustainedThreshold && !s.sustainedReportSent[r.AppID] {
			// One-shot sustained-failure escalation. The webhook
			// emission lives here when the app.sync_failed event
			// type is registered.
			s.svc.logger.ErrorContext(ctx, "appdb sync sustained failure",
				"app_id", r.AppID,
				"app_name", r.AppName,
				"metadata_url", r.MetadataURL,
				"consecutive_failures", streak,
				"threshold", s.sustainedThreshold,
				"latest_error", r.Err,
			)
			s.sustainedReportSent[r.AppID] = true
			continue
		}
		s.svc.logger.WarnContext(ctx, "appdb sync per-app failure",
			"app_id", r.AppID,
			"app_name", r.AppName,
			"metadata_url", r.MetadataURL,
			"consecutive_failures", streak,
			"error", r.Err,
		)
	}
}

func (s *Syncer) parserFor(metadataURL string) VendorParser {
	host := hostFromURL(metadataURL)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.parsers[host]; ok {
		return p
	}
	return parseGenericJSON
}

func hostFromURL(u string) string {
	// Lightweight host extraction — full url.Parse is heavier
	// than necessary for a dispatch key. We tolerate inputs
	// without a scheme.
	t := strings.TrimSpace(strings.ToLower(u))
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?"); i >= 0 {
		t = t[:i]
	}
	if i := strings.Index(t, ":"); i >= 0 {
		t = t[:i]
	}
	return t
}

func snippet(b []byte) string {
	const maxLen = 200
	if len(b) > maxLen {
		return string(b[:maxLen]) + "…"
	}
	return string(b)
}

// --- Vendor parsers -------------------------------------------------------

// microsoftEndpoint is a single entry in the M365 endpoints JSON.
// The document is an array of these objects.
type microsoftEndpoint struct {
	URLs []string `json:"urls"`
	IPs  []string `json:"ips"`
}

// parseMicrosoftEndpoints walks the M365 endpoints document and
// flattens the urls + ips fields. Wildcards (`*.office.com`) come
// through as-is.
func parseMicrosoftEndpoints(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var entries []microsoftEndpoint
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil, fmt.Errorf("ms endpoints: %w", err)
	}
	var (
		domains []string
		ranges  []netip.Prefix
	)
	for _, e := range entries {
		domains = append(domains, e.URLs...)
		for _, ip := range e.IPs {
			p, err := netip.ParsePrefix(ip)
			if err != nil {
				continue
			}
			ranges = append(ranges, p)
		}
	}
	return domains, ranges, nil
}

// googleIPRanges parses the Google IP ranges JSON.
type googleIPRangesDoc struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func parseGoogleIPRanges(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var doc googleIPRangesDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("google ipranges: %w", err)
	}
	var ranges []netip.Prefix
	for _, p := range doc.Prefixes {
		for _, raw := range []string{p.IPv4Prefix, p.IPv6Prefix} {
			if raw == "" {
				continue
			}
			pref, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			ranges = append(ranges, pref)
		}
	}
	// Google publishes only IPs — domains stay as in the registry.
	return nil, ranges, nil
}

type awsIPRangesDoc struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

func parseAWSIPRanges(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var doc awsIPRangesDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("aws ipranges: %w", err)
	}
	var ranges []netip.Prefix
	for _, p := range doc.Prefixes {
		pref, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil {
			continue
		}
		ranges = append(ranges, pref)
	}
	for _, p := range doc.IPv6Prefixes {
		pref, err := netip.ParsePrefix(p.IPv6Prefix)
		if err != nil {
			continue
		}
		ranges = append(ranges, pref)
	}
	return nil, ranges, nil
}

// parsePlaintextCIDRList parses a feed that lists one CIDR (or bare
// IP) per line — the shape Zoom and Cloudflare publish. Blank lines
// and `#`/`;` comments are ignored, and any token that is not a
// valid prefix/address is skipped rather than failing the whole feed
// (vendors occasionally interleave headers or notes). Bare addresses
// are normalised to /32 or /128 so downstream callers always see a
// prefix.
func parsePlaintextCIDRList(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var ranges []netip.Prefix
	for _, line := range strings.Split(string(body), "\n") {
		tok := strings.TrimSpace(line)
		if tok == "" || strings.HasPrefix(tok, "#") || strings.HasPrefix(tok, ";") {
			continue
		}
		if p, err := netip.ParsePrefix(tok); err == nil {
			ranges = append(ranges, p)
			continue
		}
		if addr, err := netip.ParseAddr(tok); err == nil {
			ranges = append(ranges, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	// Plaintext feeds carry only IPs — domains stay as in the registry.
	return nil, ranges, nil
}

// parseGitHubMeta parses https://api.github.com/meta. The document is
// a flat object whose values are mostly []string CIDR lists keyed by
// service (hooks, web, api, git, packages, pages, actions, …), plus a
// few non-CIDR fields (ssh_keys, ssh_key_fingerprints, booleans) and a
// nested `domains` object. We flatten every string array, keep the
// tokens that parse as prefixes as IP ranges, and collect the nested
// `domains` values as domains. New service keys GitHub adds later are
// picked up automatically.
func parseGitHubMeta(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("github meta: %w", err)
	}
	var (
		domains []string
		ranges  []netip.Prefix
	)
	for key, val := range raw {
		// The nested domains object: { "website": [...], ... }.
		if key == "domains" {
			var groups map[string][]string
			if err := json.Unmarshal(val, &groups); err == nil {
				for _, g := range groups {
					domains = append(domains, g...)
				}
			}
			continue
		}
		var list []string
		if err := json.Unmarshal(val, &list); err != nil {
			continue // bool / object / non-array field
		}
		for _, tok := range list {
			if p, err := netip.ParsePrefix(tok); err == nil {
				ranges = append(ranges, p)
			}
		}
	}
	return domains, ranges, nil
}

// fastlyIPList is the shape of https://api.fastly.com/public-ip-list.
type fastlyIPList struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

func parseFastlyIPList(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	var doc fastlyIPList
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("fastly ip list: %w", err)
	}
	var ranges []netip.Prefix
	for _, raw := range append(doc.Addresses, doc.IPv6Addresses...) {
		if p, err := netip.ParsePrefix(raw); err == nil {
			ranges = append(ranges, p)
		}
	}
	return nil, ranges, nil
}

// parseGenericJSON expects { "domains": [...], "ip_ranges": [...] }.
// Used as the fallback when no vendor-specific parser matches.
type genericDoc struct {
	Domains  []string `json:"domains"`
	IPRanges []string `json:"ip_ranges"`
}

func parseGenericJSON(body []byte, _ []string) ([]string, []netip.Prefix, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil, nil
	}
	var doc genericDoc
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil, nil, fmt.Errorf("generic: %w", err)
	}
	var ranges []netip.Prefix
	for _, raw := range doc.IPRanges {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		ranges = append(ranges, p)
	}
	return doc.Domains, ranges, nil
}

// --- Set-merge helpers ----------------------------------------------------
//
// mergeDomains and mergeRanges implement ADDITIVE-ONLY (union)
// semantics. A vendor removal does NOT shrink the stored set.
// This is a deliberate safety trade-off:
//
//   - A poisoned or buggy vendor response (empty payload,
//     rate-limited 429, partial JSON, MITM) cannot silently wipe
//     an app's entire trusted domain list.
//   - Stale domains are handled at a different layer: the demotion
//     engine reacts to threat-feed signals by immediately demoting
//     the app to inspect_full (zero operator latency); operators
//     can also prune stale entries via the admin API.
//   - The catalog grows monotonically under automation. Manual
//     pruning uses PUT /admin/app-registry/{id} (full replace)
//     or DELETE.
//
// See docs/TRAFFIC_CLASSIFICATION.md §8 for the rationale.

func mergeDomains(a, b []string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	// Canonicalise both inputs identically: lowercase, trim,
	// drop blanks. Filtering only on the `b` side would let an
	// existing row with a whitespace-only domain (or a literal
	// "") survive every sync forever, polluting bundle output
	// and matchesPattern with junk entries. Drop on the `a`
	// side too so the first sync after a release self-heals
	// such rows.
	for _, d := range a {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		set[d] = struct{}{}
	}
	for _, d := range b {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		set[d] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeRanges(a, b []netip.Prefix) []netip.Prefix {
	set := make(map[string]netip.Prefix, len(a)+len(b))
	for _, p := range a {
		set[p.String()] = p
	}
	for _, p := range b {
		set[p.String()] = p
	}
	out := make([]netip.Prefix, 0, len(set))
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, set[k])
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalRangeSlices(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
