package appdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
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

// --- URL-categorisation training feedback --------------------------------
//
// The first-party URL categoriser (crates/sng-swg/src/url_ml.rs) ships
// an Ed25519-signed ML model whose Tier 3 classifier is trained
// offline on labelled (domain, category) examples. The control plane
// is the authoritative source of those labels: every curated
// app_registry row that carries a Category is an operator-confirmed
// example, and the community-feed ingestion below adds bulk labels at
// a lower trust weight. AggregateCategoryFeedback turns the live
// catalog into the deduplicated, weighted corpus the offline trainer
// consumes — no tenant data, no per-user URLs, no request logs ever
// enter the corpus, so the privacy surface is the same as the
// already-global catalog.

const (
	// categoryLabelWeightOperator is the training weight of a label
	// sourced from an operator-curated registry row. Operator labels
	// are scarce and high-trust, so they outrank bulk community
	// labels when the same domain is labelled by both.
	categoryLabelWeightOperator = 1.0
	// categoryLabelWeightCommunity is the training weight of a label
	// sourced from an ingested community feed (Shallalist, UT1).
	// Community feeds are large but noisier and occasionally stale,
	// so they contribute at a quarter of an operator label's weight.
	categoryLabelWeightCommunity = 0.25
)

// CategoryLabel is one labelled training example: a canonical domain,
// the category assigned to it, the source that assigned it, and the
// trust weight the trainer should give the example.
type CategoryLabel struct {
	Domain   string  `json:"domain"`
	Category string  `json:"category"`
	Source   string  `json:"source"`
	Weight   float64 `json:"weight"`
}

// CategoryTrainingCorpus is the aggregated, deduplicated set of
// labelled examples exported for offline model training. Exactly one
// label is kept per domain (see preferLabel for the conflict rule) so
// the trainer never sees a domain with two contradictory categories.
type CategoryTrainingCorpus struct {
	// Labels is the per-domain corpus, sorted by domain for stable,
	// reproducible training inputs.
	Labels []CategoryLabel `json:"labels"`
	// PerCategory / PerSource are histograms over the chosen labels,
	// letting an operator spot class imbalance or a feed that is
	// dominating the corpus before a training run.
	PerCategory map[string]int `json:"per_category"`
	PerSource   map[string]int `json:"per_source"`
	GeneratedAt time.Time      `json:"generated_at"`
}

// AggregateCategoryFeedback walks the global app_registry and builds
// the labelled training corpus for the URL-categorisation model. Each
// row with a non-empty Category contributes one (domain, category)
// label per domain; operator-curated rows weigh more than
// community-feed rows. When two rows label the same domain with
// different categories the higher-weight label wins, with a
// deterministic category tie-break so the corpus is byte-stable across
// runs regardless of repository iteration order.
func (s *Syncer) AggregateCategoryFeedback(ctx context.Context) (CategoryTrainingCorpus, error) {
	apps, err := s.svc.apps.ListAll(ctx)
	if err != nil {
		return CategoryTrainingCorpus{}, fmt.Errorf("aggregate category feedback: list apps: %w", err)
	}
	best := make(map[string]CategoryLabel)
	for _, app := range apps {
		category := strings.ToLower(strings.TrimSpace(app.Category))
		if category == "" {
			// An uncategorised row carries no supervised signal.
			continue
		}
		weight := categoryLabelWeightOperator
		if isCommunityFeedVendor(app.Vendor) {
			weight = categoryLabelWeightCommunity
		}
		source := strings.ToLower(strings.TrimSpace(app.Vendor))
		if source == "" {
			source = "operator"
		}
		for _, raw := range app.Domains {
			domain := canonicalCategoryDomain(raw)
			if domain == "" {
				continue
			}
			cand := CategoryLabel{
				Domain:   domain,
				Category: category,
				Source:   source,
				Weight:   weight,
			}
			if cur, ok := best[domain]; ok && !preferLabel(cand, cur) {
				continue
			}
			best[domain] = cand
		}
	}

	corpus := CategoryTrainingCorpus{
		Labels:      make([]CategoryLabel, 0, len(best)),
		PerCategory: make(map[string]int),
		PerSource:   make(map[string]int),
		GeneratedAt: s.now(),
	}
	for _, label := range best {
		corpus.Labels = append(corpus.Labels, label)
		corpus.PerCategory[label.Category]++
		corpus.PerSource[label.Source]++
	}
	sort.Slice(corpus.Labels, func(i, j int) bool {
		return corpus.Labels[i].Domain < corpus.Labels[j].Domain
	})
	return corpus, nil
}

// preferLabel reports whether candidate should replace incumbent as
// the single label kept for a domain. Higher weight wins so an
// operator label always beats a community label; equal weights break
// on the lexicographically smaller category so the result is
// independent of map iteration order.
func preferLabel(cand, cur CategoryLabel) bool {
	if cand.Weight != cur.Weight {
		return cand.Weight > cur.Weight
	}
	return cand.Category < cur.Category
}

// canonicalCategoryDomain normalises a registry or feed hostname into
// the token the categorisation tokenizer expects: lowercased,
// trimmed, with a leading "*." suffix-match marker removed (the model
// trains on concrete hostnames, not match patterns). It returns "" for
// blanks, comment lines, and tokens that do not look like a bare
// hostname (carrying a scheme, path, port, or whitespace) so URL and
// comment lines in a community feed never leak in as fake hostnames.
func canonicalCategoryDomain(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" || strings.HasPrefix(h, "#") || strings.HasPrefix(h, ";") {
		return ""
	}
	h = strings.TrimPrefix(h, "*.")
	if strings.ContainsAny(h, " \t\r/?:@") {
		return ""
	}
	if !strings.Contains(h, ".") {
		return ""
	}
	return h
}

// --- Community category-feed ingestion ------------------------------------
//
// Shallalist and the Université Toulouse UT1 blacklists publish
// gzip-compressed tar archives laid out as a tree of per-category
// directories, each holding a `domains` file of one hostname per
// line. We ingest each category into the app_registry as a global
// inspect_full row named "community:<feed>:<category>" so the domains
// flow down to the agents through the existing bundle path and feed
// the categorisation corpus above. inspect_full is deliberate: these
// feeds are risk blocklists (ads, adult, malware), so the fail-safe
// steering tier is full inspection — never a trusted bypass.

const (
	// CommunityFeedShallalist / CommunityFeedUT1 are the recognised
	// community feed identifiers. They double as the Vendor stamped
	// on the rows the ingestion creates.
	CommunityFeedShallalist = "shallalist"
	CommunityFeedUT1        = "ut1"

	// communityFeedDownloadLimit bounds a feed archive download.
	// Shallalist/UT1 archives are tens of MB; 256 MiB leaves ample
	// headroom while still capping a hostile or runaway response.
	communityFeedDownloadLimit = 256 << 20
	// communityFeedMemberLimit bounds a single decompressed tar
	// member so a zip-bomb member cannot exhaust memory.
	communityFeedMemberLimit = 64 << 20
	// communityFeedTotalLimit bounds the *aggregate* decompressed
	// bytes read across all members of one archive. The per-member
	// cap alone does not bound an archive of thousands of near-limit
	// members, so this caps the cumulative expansion: a 256 MiB
	// gzip of highly compressible text could otherwise inflate to
	// tens of GiB. 1 GiB is multiples above a legitimate
	// Shallalist/UT1 archive (tens of MiB decompressed) while
	// turning a decompression bomb into a bounded, clearly-labelled
	// error instead of an OOM.
	communityFeedTotalLimit = 1 << 30
)

// isCommunityFeedVendor reports whether a registry row's Vendor marks
// it as community-ingested (and therefore a lower-weight training
// source).
func isCommunityFeedVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case CommunityFeedShallalist, CommunityFeedUT1:
		return true
	}
	return false
}

// CommunityIngestResult is the per-category outcome of ingesting a
// community feed.
type CommunityIngestResult struct {
	Feed          string `json:"feed"`
	Category      string `json:"category"`
	AppName       string `json:"app_name"`
	DomainsBefore int    `json:"domains_before"`
	DomainsAfter  int    `json:"domains_after"`
	Created       bool   `json:"created"`
	Updated       bool   `json:"updated"`
	Err           string `json:"error,omitempty"`
}

// ParseCommunityCategoryFeed parses a Shallalist/UT1-style category
// blacklist archive (a gzip-compressed tar) into per-feed-category
// domain sets keyed by the feed's own category name (the directory
// immediately containing each `domains` file). Comment lines, URL
// lines, and malformed hosts are dropped.
//
// Decompression is bounded both per member (communityFeedMemberLimit)
// and in aggregate across every regular member (communityFeedTotalLimit)
// so a crafted archive — one oversized member, or thousands of small
// ones — cannot exhaust memory or CPU. The aggregate bound is charged
// against *all* regular members, including ones we discard, because
// advancing tar.Reader still decompresses a skipped member's bytes;
// counting only retained members would leave the discarded-member
// decompression work unbounded. Hitting either bound is a distinct,
// clearly labelled error rather than a silent truncation that would
// later surface as a confusing gzip/tar decode failure.
func ParseCommunityCategoryFeed(body []byte) (map[string][]string, error) {
	return parseCommunityCategoryFeed(body, communityFeedMemberLimit, communityFeedTotalLimit)
}

// parseCommunityCategoryFeed is the limit-parameterised core of
// ParseCommunityCategoryFeed. The limits are arguments (rather than
// the package constants directly) so the bomb-protection paths are
// exercisable in tests with tiny archives instead of multi-GiB ones.
func parseCommunityCategoryFeed(body []byte, memberLimit, totalLimit int64) (map[string][]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("community feed: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	out := map[string][]string{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("community feed: tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(hdr.Name)
		// Charge the member's declared decompressed size against both
		// bounds up front, before deciding whether to keep it: even a
		// member we skip below is decompressed by tar.Reader when it
		// advances to the next header, so the work it costs must count
		// toward the limits. hdr.Size is the authoritative decompressed
		// length tar enforces while reading/skipping the member.
		if hdr.Size > memberLimit {
			return nil, fmt.Errorf(
				"community feed: member %q exceeds per-member limit of %d bytes",
				name, memberLimit,
			)
		}
		total += hdr.Size
		if total > totalLimit {
			return nil, fmt.Errorf(
				"community feed: total decompressed size exceeds limit of %d bytes",
				totalLimit,
			)
		}
		if path.Base(name) != "domains" {
			continue
		}
		category := strings.ToLower(path.Base(path.Dir(name)))
		if category == "" || category == "." || category == "/" {
			continue
		}
		// Read one byte past the per-member limit so a member whose
		// header under-declared its size is still detected explicitly
		// rather than silently truncated by io.LimitReader.
		data, err := io.ReadAll(io.LimitReader(tr, memberLimit+1))
		if err != nil {
			return nil, fmt.Errorf("community feed: read %q: %w", name, err)
		}
		if int64(len(data)) > memberLimit {
			return nil, fmt.Errorf(
				"community feed: member %q exceeds per-member limit of %d bytes",
				name, memberLimit,
			)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if host := canonicalCategoryDomain(line); host != "" {
				out[category] = append(out[category], host)
			}
		}
	}
	return out, nil
}

// mapCommunityCategory maps a feed's own category name into the
// operator dotted-category namespace shared across the DNS, firewall
// and SWG planes (see crates/sng-swg/src/categorizer.rs). Unknown feed
// categories pass through under a sanitised "community." prefix so a
// new upstream category is still ingested (and visibly namespaced)
// rather than silently dropped.
func mapCommunityCategory(feedCategory string) string {
	switch feedCategory {
	case "adv", "ads", "tracker", "trackers", "tracking":
		return "advertising"
	case "porn", "adult", "sex", "sexuality":
		return "adult.content"
	case "gamble", "gambling", "gamblings":
		return "gambling"
	case "spyware", "malware", "phishing", "fraud", "trojan", "warez":
		return "security.threat"
	case "hacking", "hacker", "remotecontrol":
		return "security.hacking"
	case "socialnet", "social", "socialnetworking":
		return "social.media"
	case "webmail", "mail", "email":
		return "webmail"
	case "violence", "weapons", "weapon":
		return "violence"
	case "drugs", "drug":
		return "drugs"
	case "anonvpn", "anonymizer", "anon", "proxy":
		return "anonymizer"
	default:
		return "community." + sanitizeCategoryToken(feedCategory)
	}
}

// sanitizeCategoryToken reduces an arbitrary feed category name to the
// [a-z0-9] alphabet (other runes collapse to "_") so a passthrough
// category is a safe, stable dotted-namespace token.
func sanitizeCategoryToken(in string) string {
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range strings.ToLower(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "uncategorised"
	}
	return out
}

// IngestCommunityFeed parses a community category-feed archive and
// upserts the per-category domain sets into the app_registry. One row
// per canonical category, named "community:<feed>:<category>", with
// domains merged additively (the same monotonic-growth contract as the
// vendor sync — see mergeDomains). Like SyncAll it never aborts on a
// single category failure; per-category outcomes are returned for the
// operator. The results are ordered by canonical category for stable
// output.
//
// Concurrency: this is the low-level building block and does NOT
// acquire syncSem itself — it writes the global app_registry through
// the GetByName -> CreateApp / SyncUpdateApp path, so it must not run
// concurrently with SyncAll or another registry writer (two callers
// could both miss the same row on GetByName and both CreateApp, which
// a unique-name constraint rejects). The safe entry point is
// SyncCommunityFeeds, which holds syncSem for the whole batch; a
// direct caller is responsible for its own serialisation.
func (s *Syncer) IngestCommunityFeed(ctx context.Context, feed string, body []byte) ([]CommunityIngestResult, error) {
	feed = strings.ToLower(strings.TrimSpace(feed))
	if !isCommunityFeedVendor(feed) {
		return nil, fmt.Errorf("ingest community feed: unknown feed %q", feed)
	}
	byFeedCategory, err := ParseCommunityCategoryFeed(body)
	if err != nil {
		return nil, fmt.Errorf("ingest community feed %q: %w", feed, err)
	}
	// Collapse feed categories into the canonical namespace, unioning
	// domains where several feed categories map to the same canonical
	// category (e.g. "porn" and "adult" both -> "adult.content").
	byCanonical := map[string][]string{}
	for feedCategory, domains := range byFeedCategory {
		canonical := mapCommunityCategory(feedCategory)
		byCanonical[canonical] = append(byCanonical[canonical], domains...)
	}
	canonicals := make([]string, 0, len(byCanonical))
	for canonical := range byCanonical {
		canonicals = append(canonicals, canonical)
	}
	sort.Strings(canonicals)

	results := make([]CommunityIngestResult, 0, len(canonicals))
	for _, canonical := range canonicals {
		results = append(results, s.ingestCommunityCategory(ctx, feed, canonical, byCanonical[canonical]))
	}
	return results, nil
}

// ingestCommunityCategory upserts a single canonical category's domain
// set as one app_registry row. A new category is created; an existing
// one is merged additively and updated only when the merge changes the
// stored set (so a re-ingest of unchanged data is a no-op that emits
// no audit churn).
func (s *Syncer) ingestCommunityCategory(ctx context.Context, feed, canonical string, rawDomains []string) CommunityIngestResult {
	name := fmt.Sprintf("community:%s:%s", feed, canonical)
	res := CommunityIngestResult{Feed: feed, Category: canonical, AppName: name}

	incoming := mergeDomains(rawDomains, nil)
	if len(incoming) == 0 {
		res.Err = "no valid domains in category"
		return res
	}

	existing, err := s.svc.apps.GetByName(ctx, name)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		created, cerr := s.svc.CreateApp(ctx, repository.AppRegistry{
			Name:         name,
			Vendor:       feed,
			TrafficClass: repository.TrafficClassInspectFull,
			Scope:        repository.AppRegistryScopeGlobal,
			Domains:      incoming,
			Category:     canonical,
			IsSystem:     true,
		})
		if cerr != nil {
			res.Err = fmt.Sprintf("create: %v", cerr)
			return res
		}
		res.Created = true
		res.DomainsAfter = len(created.Domains)
		return res
	case err != nil:
		res.Err = fmt.Sprintf("lookup: %v", err)
		return res
	}

	before := mergeDomains(existing.Domains, nil)
	after := mergeDomains(existing.Domains, incoming)
	res.DomainsBefore = len(before)
	res.DomainsAfter = len(after)
	if equalStringSlices(before, after) {
		return res
	}
	existing.Domains = after
	existing.Category = canonical
	existing.UpdatedAt = s.now()
	meta := SyncAppMetadata{
		Source:        "community:" + feed,
		DomainsBefore: len(before),
		DomainsAfter:  len(after),
	}
	if _, uerr := s.svc.SyncUpdateApp(ctx, existing, meta); uerr != nil {
		res.Err = fmt.Sprintf("update: %v", uerr)
		return res
	}
	res.Updated = true
	return res
}

// SyncCommunityFeeds fetches and ingests every configured community
// feed, keyed by feed name -> archive URL. Like SyncAll it never
// aborts on a single feed failure: a fetch or ingest error is captured
// in a per-feed result and the next feed is attempted. Feeds are
// processed in name order for deterministic output.
//
// It shares SyncAll's syncSem so community ingestion is serialised
// against the vendor sync (and against another community-feed run):
// both write the global app_registry through the GetByName ->
// CreateApp / SyncUpdateApp path, and two concurrent runs could race
// there — e.g. two callers both seeing ErrNotFound for the same
// community:<feed>:<category> row and both issuing CreateApp, which a
// Postgres unique-name constraint would reject. Holding the same
// 1-slot semaphore as SyncAll makes the registry's writer single-
// threaded across all sync paths; a cancelled caller returns at once
// without spawning an orphan goroutine.
func (s *Syncer) SyncCommunityFeeds(ctx context.Context, sources map[string]string) ([]CommunityIngestResult, error) {
	select {
	case s.syncSem <- struct{}{}:
		defer func() { <-s.syncSem }()
	case <-ctx.Done():
		return nil, fmt.Errorf("sync community feeds: %w", ctx.Err())
	}

	feeds := make([]string, 0, len(sources))
	for feed := range sources {
		feeds = append(feeds, feed)
	}
	sort.Strings(feeds)

	var all []CommunityIngestResult
	for _, feed := range feeds {
		body, err := s.fetchFeed(ctx, sources[feed])
		if err != nil {
			all = append(all, CommunityIngestResult{Feed: feed, Err: err.Error()})
			continue
		}
		results, err := s.IngestCommunityFeed(ctx, feed, body)
		if err != nil {
			all = append(all, CommunityIngestResult{Feed: feed, Err: err.Error()})
			continue
		}
		all = append(all, results...)
	}
	return all, nil
}

// fetchFeed performs the bounded GET shared by the community-feed
// sync. The body is read under communityFeedDownloadLimit so a hostile
// or runaway response cannot exhaust memory. An over-limit response is
// reported as an explicit "exceeds download limit" error rather than
// being silently truncated, which would otherwise surface downstream
// as a misleading gzip/tar decode failure.
func (s *Syncer) fetchFeed(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", "shieldnet-gateway-appdb-sync/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Check the status before draining the body: a non-200 (e.g. a
	// verbose 403/500 HTML page) only needs a short snippet for the
	// error message, so reading just a few KiB here avoids pulling up
	// to communityFeedDownloadLimit bytes of error content we discard.
	if resp.StatusCode != http.StatusOK {
		snip, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, snippet(snip))
	}
	// Read one byte past the limit so an over-limit body is detected
	// explicitly instead of being silently truncated at the bound.
	body, err := io.ReadAll(io.LimitReader(resp.Body, communityFeedDownloadLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > communityFeedDownloadLimit {
		return nil, fmt.Errorf(
			"feed response exceeds download limit of %d bytes",
			communityFeedDownloadLimit,
		)
	}
	return body, nil
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
