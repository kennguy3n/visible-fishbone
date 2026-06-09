package casb

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Shadow-IT auto-discovery
// ------------------------
// The API-mode discovery in service.go finds SaaS apps a tenant has
// *deliberately* connected (a connector with credentials). Shadow IT
// is the opposite problem: SaaS a tenant's users reach over the SWG
// without any sanctioned connector. The SWG already emits DNS and
// HTTP telemetry for every resolved name / request (schema.DNSEvent,
// schema.HTTPEvent); this discoverer turns that exhaust into a
// per-tenant inventory of the SaaS apps actually in use, including
// the unsanctioned ones, and folds them into the same
// casb_discovered_apps table the operator portal already renders.
//
// Privacy (5000 SME tenants share this pipeline): the discoverer
// keeps device IDs in memory *only* long enough to count distinct
// active devices per app within a flush window. Nothing about the
// observed hostnames, the device IDs, or the users is persisted —
// only the per-app aggregate (name, vendor, category, distinct
// device count, first/last seen) is written, and always under the
// observed tenant's row-level-security scope. The in-memory state is
// windowed (reset on every Flush) so it cannot grow unbounded.
//
// Performance: Observe runs inline on the telemetry hot path, so it
// must be cheap. A non-matching hostname (the overwhelming majority
// of DNS/HTTP traffic) costs one normalisation pass plus a handful of
// map probes and returns without taking any lock. Matching events
// take a single sharded lock keyed on the tenant, so 5000 tenants do
// not contend on one mutex.

// shadowApp is a catalog entry: a SaaS product and the static risk
// metadata attached to *unsanctioned* use of it.
type shadowApp struct {
	Name     string
	Vendor   string
	Category string
	// Risk is the baseline risk score (0-100) for unsanctioned use
	// of this app. Categories that move regulated data off-network
	// (cloud IaaS consoles, generic file-transfer, GenAI prompt
	// surfaces) score higher because shadow use bypasses the
	// tenant's DLP and posture controls.
	Risk int
}

// shadowCatalog maps a registrable host suffix to the SaaS app it
// identifies. Keys are fully-qualified suffixes ("console.aws.amazon.com",
// "slack.com"); matchHost walks a hostname's parent suffixes so any
// subdomain ("acme.slack.com") resolves to its app. Built once at
// init and treated as immutable, so it is safe for concurrent reads
// without a lock.
//
// DNS / SNI only exposes the host, so products that share a host
// (Jira and Confluence both live on *.atlassian.net) collapse to a
// single vendor entry — claiming finer precision than the wire
// carries would be a fiction.
var shadowCatalog = buildShadowCatalog(
	// --- SaaS with first-class CASB connectors --------------------
	entry(shadowApp{Name: "Box", Vendor: "Box", Category: "cloud_storage", Risk: 45},
		"box.com"),
	entry(shadowApp{Name: "Dropbox", Vendor: "Dropbox", Category: "cloud_storage", Risk: 55},
		"dropbox.com"),
	entry(shadowApp{Name: "GitHub", Vendor: "GitHub", Category: "code_repository", Risk: 60},
		"github.com"),
	entry(shadowApp{Name: "GitLab", Vendor: "GitLab", Category: "code_repository", Risk: 60},
		"gitlab.com"),
	entry(shadowApp{Name: "Atlassian Cloud", Vendor: "Atlassian", Category: "project_management", Risk: 35},
		"atlassian.net"),
	entry(shadowApp{Name: "ServiceNow", Vendor: "ServiceNow", Category: "itsm", Risk: 45},
		"service-now.com"),
	entry(shadowApp{Name: "Zendesk", Vendor: "Zendesk", Category: "support", Risk: 35},
		"zendesk.com"),
	entry(shadowApp{Name: "HubSpot", Vendor: "HubSpot", Category: "crm", Risk: 40},
		"hubspot.com"),
	entry(shadowApp{Name: "Zoom", Vendor: "Zoom", Category: "conferencing", Risk: 30},
		"zoom.us"),
	entry(shadowApp{Name: "Microsoft Teams", Vendor: "Microsoft", Category: "collaboration", Risk: 25},
		"teams.microsoft.com", "teams.live.com"),
	entry(shadowApp{Name: "Microsoft 365", Vendor: "Microsoft", Category: "collaboration", Risk: 35},
		"sharepoint.com", "outlook.office.com", "onedrive.live.com"),
	entry(shadowApp{Name: "AWS Console", Vendor: "Amazon", Category: "cloud_iaas", Risk: 70},
		"console.aws.amazon.com", "signin.aws.amazon.com"),
	entry(shadowApp{Name: "GCP Console", Vendor: "Google", Category: "cloud_iaas", Risk: 70},
		"console.cloud.google.com"),
	entry(shadowApp{Name: "Azure Portal", Vendor: "Microsoft", Category: "cloud_iaas", Risk: 70},
		"portal.azure.com"),
	entry(shadowApp{Name: "Okta", Vendor: "Okta", Category: "identity", Risk: 55},
		"okta.com", "oktapreview.com"),
	entry(shadowApp{Name: "Workday", Vendor: "Workday", Category: "hcm", Risk: 45},
		"workday.com", "myworkday.com"),
	entry(shadowApp{Name: "Google Workspace", Vendor: "Google", Category: "collaboration", Risk: 45},
		"drive.google.com", "docs.google.com", "mail.google.com"),
	entry(shadowApp{Name: "Slack", Vendor: "Slack", Category: "collaboration", Risk: 35},
		"slack.com"),
	entry(shadowApp{Name: "Salesforce", Vendor: "Salesforce", Category: "crm", Risk: 45},
		"salesforce.com", "force.com"),

	// --- Common unsanctioned SaaS (no connector) ------------------
	// The real payoff of shadow-IT discovery: surfacing apps the
	// tenant has no connector for and likely does not know are in
	// use.
	entry(shadowApp{Name: "Notion", Vendor: "Notion Labs", Category: "productivity", Risk: 45},
		"notion.so"),
	entry(shadowApp{Name: "Asana", Vendor: "Asana", Category: "project_management", Risk: 35},
		"asana.com"),
	entry(shadowApp{Name: "Trello", Vendor: "Atlassian", Category: "project_management", Risk: 35},
		"trello.com"),
	entry(shadowApp{Name: "Airtable", Vendor: "Airtable", Category: "database", Risk: 45},
		"airtable.com"),
	entry(shadowApp{Name: "Figma", Vendor: "Figma", Category: "design", Risk: 35},
		"figma.com"),
	entry(shadowApp{Name: "Canva", Vendor: "Canva", Category: "design", Risk: 30},
		"canva.com"),
	entry(shadowApp{Name: "monday.com", Vendor: "monday.com", Category: "project_management", Risk: 35},
		"monday.com"),
	entry(shadowApp{Name: "Grammarly", Vendor: "Grammarly", Category: "productivity", Risk: 55},
		"grammarly.com"),
	entry(shadowApp{Name: "WeTransfer", Vendor: "WeTransfer", Category: "file_transfer", Risk: 65},
		"wetransfer.com"),
	entry(shadowApp{Name: "Mailchimp", Vendor: "Intuit", Category: "marketing", Risk: 40},
		"mailchimp.com"),
	entry(shadowApp{Name: "OpenAI ChatGPT", Vendor: "OpenAI", Category: "generative_ai", Risk: 70},
		"chatgpt.com", "openai.com"),
	entry(shadowApp{Name: "Telegram", Vendor: "Telegram", Category: "messaging", Risk: 60},
		"telegram.org", "web.telegram.org"),
	entry(shadowApp{Name: "WhatsApp", Vendor: "Meta", Category: "messaging", Risk: 55},
		"web.whatsapp.com"),
)

// catalogEntry pairs an app with the host suffixes that resolve to it.
type catalogEntry struct {
	app      shadowApp
	suffixes []string
}

func entry(app shadowApp, suffixes ...string) catalogEntry {
	return catalogEntry{app: app, suffixes: suffixes}
}

func buildShadowCatalog(entries ...catalogEntry) map[string]shadowApp {
	m := make(map[string]shadowApp, len(entries)*2)
	for _, e := range entries {
		for _, s := range e.suffixes {
			m[s] = e.app
		}
	}
	return m
}

// matchHost resolves a hostname to a catalog app, or (zero, false)
// when the host is not a known SaaS. It normalises the host
// (lower-cases, drops a trailing dot and any :port) and then walks
// the parent suffixes from most to least specific so a subdomain
// resolves to the most specific catalog entry.
func matchHost(host string) (shadowApp, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return shadowApp{}, false
	}
	// Drop a port if SNI/host carried one, and any trailing dot from
	// a fully-qualified name.
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// Only strip when the tail is a port (all digits); an IPv6
		// literal would contain ':' too but is never a SaaS host.
		if isAllDigits(h[i+1:]) {
			h = h[:i]
		}
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return shadowApp{}, false
	}
	// Walk parent suffixes: "a.b.slack.com" -> "a.b.slack.com",
	// "b.slack.com", "slack.com", "com". Stops at the first hit.
	for {
		if app, ok := shadowCatalog[h]; ok {
			return app, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return shadowApp{}, false
		}
		h = h[i+1:]
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// DefaultShadowITFlushInterval is how often Run persists the
// accumulated shadow-IT inventory. Sized for a near-real-time
// operator inventory without hammering the database: each flush is
// one upsert per (tenant, app) pair that saw traffic in the window.
const DefaultShadowITFlushInterval = 5 * time.Minute

// maxDevicesPerApp caps the distinct-device set held per (tenant,
// app) within a window so a single busy app cannot grow the working
// set without bound. Once the cap is hit the count saturates; the
// inventory's purpose (which apps are in use, by roughly how many
// endpoints) is unaffected by the exact tail beyond the cap.
const maxDevicesPerApp = 8192

// shadowAggregator is the persistence dependency the discoverer
// needs: the casb_discovered_apps upsert. *repository.CASBDiscoveredAppRepository
// satisfies it; tests pass a fake.
type shadowAggregator interface {
	Upsert(ctx context.Context, tenantID uuid.UUID, app repository.CASBDiscoveredApp) (repository.CASBDiscoveredApp, error)
}

// shadowKey identifies a per-tenant, per-app aggregate.
type shadowKey struct {
	tenant uuid.UUID
	app    string
}

// shadowAgg accumulates one app's activity for one tenant within the
// current flush window.
type shadowAgg struct {
	app       shadowApp
	devices   map[uuid.UUID]struct{}
	saturated bool
	firstSeen time.Time
	lastSeen  time.Time
}

// shadowShard is one stripe of the aggregation map with its own lock,
// so observations for tenants hashing to different shards do not
// contend.
type shadowShard struct {
	mu   sync.Mutex
	aggs map[shadowKey]*shadowAgg
}

// ShadowITDiscoverer turns SWG DNS/HTTP telemetry into a per-tenant
// shadow-IT inventory. Construct with NewShadowITDiscoverer, feed it
// with ObserveHost from the telemetry consumer, and run Flush (or the
// Run loop) to persist. Safe for concurrent use.
type ShadowITDiscoverer struct {
	apps    shadowAggregator
	logger  *slog.Logger
	nowFunc func() time.Time

	shards []*shadowShard
	mask   uint64

	// Lifecycle: Start launches the flush loop, Stop joins it after a
	// final flush. stopCh is closed by Stop to wind the loop down even
	// when the parent context is still live (the early-return shutdown
	// path); doneCh is closed when the loop has returned so Stop can
	// block until the final DB flush completes — this is what keeps the
	// final upserts from racing pool.Close() on shutdown.
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// NewShadowITDiscoverer constructs a discoverer that persists through
// the supplied repository. shardCount is rounded up to a power of two
// (so the tenant hash can mask instead of modulo); zero selects a
// sensible default.
func NewShadowITDiscoverer(apps shadowAggregator, logger *slog.Logger) *ShadowITDiscoverer {
	if logger == nil {
		logger = slog.Default()
	}
	const shardCount = 64 // power of two; ~80 tenants/shard at 5000
	shards := make([]*shadowShard, shardCount)
	for i := range shards {
		shards[i] = &shadowShard{aggs: make(map[shadowKey]*shadowAgg)}
	}
	return &ShadowITDiscoverer{
		apps:    apps,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
		shards:  shards,
		mask:    uint64(shardCount - 1),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (d *ShadowITDiscoverer) shardFor(tenantID uuid.UUID) *shadowShard {
	// FNV-1a over the 16 UUID bytes — cheap and well-distributed.
	// Constants are the canonical 64-bit FNV-1a offset basis and prime.
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	for _, b := range tenantID {
		h ^= uint64(b)
		h *= prime
	}
	return d.shards[h&d.mask]
}

// ObserveHost records that a device in a tenant reached the given
// hostname at ts. Hosts that are not in the SaaS catalog are ignored
// without taking a lock. Satisfies the telemetry consumer's
// shadow-IT observer hook.
func (d *ShadowITDiscoverer) ObserveHost(tenantID, deviceID uuid.UUID, host string, ts time.Time) {
	if tenantID == uuid.Nil {
		return
	}
	app, ok := matchHost(host)
	if !ok {
		return
	}
	if ts.IsZero() {
		ts = d.nowFunc()
	} else {
		ts = ts.UTC()
	}
	key := shadowKey{tenant: tenantID, app: app.Name}
	sh := d.shardFor(tenantID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	agg := sh.aggs[key]
	if agg == nil {
		agg = &shadowAgg{
			app:       app,
			devices:   make(map[uuid.UUID]struct{}, 1),
			firstSeen: ts,
			lastSeen:  ts,
		}
		sh.aggs[key] = agg
	}
	if ts.Before(agg.firstSeen) {
		agg.firstSeen = ts
	}
	if ts.After(agg.lastSeen) {
		agg.lastSeen = ts
	}
	if deviceID != uuid.Nil && !agg.saturated {
		if _, seen := agg.devices[deviceID]; !seen {
			if len(agg.devices) >= maxDevicesPerApp {
				agg.saturated = true
			} else {
				agg.devices[deviceID] = struct{}{}
			}
		}
	}
}

// Flush persists the inventory accumulated since the last flush and
// resets the in-memory window. Each (tenant, app) that saw traffic
// becomes one casb_discovered_apps upsert under the tenant's RLS
// scope. A per-app upsert failure is logged and does not abort the
// rest; Flush returns the first error encountered so callers can
// surface persistent failures.
func (d *ShadowITDiscoverer) Flush(ctx context.Context) error {
	type pending struct {
		tenant uuid.UUID
		app    repository.CASBDiscoveredApp
	}
	// Snapshot-and-reset under each shard lock, then upsert outside
	// the lock so a slow database never blocks Observe.
	var batch []pending
	for _, sh := range d.shards {
		sh.mu.Lock()
		if len(sh.aggs) == 0 {
			sh.mu.Unlock()
			continue
		}
		for key, agg := range sh.aggs {
			// UsersCount is the number of distinct devices that
			// reached this app within the window being flushed —
			// a "recently active" signal, not an all-time total.
			// This is deliberate: device IDs are never persisted
			// (privacy), so an all-time distinct count cannot be
			// reconstructed DB-side, and retaining every device ID
			// in memory across windows would be unbounded across
			// 5000 tenants. The repository upsert replaces
			// users_count on conflict (correct for the API-mode
			// discovery in service.go, which reports a full roster);
			// because Flush only upserts apps that saw traffic this
			// window, a quiet window writes nothing and the prior
			// value is retained rather than reset to zero.
			count := len(agg.devices)
			if agg.saturated {
				count = maxDevicesPerApp
			}
			risk := agg.app.Risk
			batch = append(batch, pending{
				tenant: key.tenant,
				app: repository.CASBDiscoveredApp{
					Name:       agg.app.Name,
					Vendor:     agg.app.Vendor,
					Category:   agg.app.Category,
					RiskScore:  &risk,
					UsersCount: count,
					FirstSeen:  agg.firstSeen,
					LastSeen:   agg.lastSeen,
				},
			})
		}
		// Reset the window: drop the map so memory tracks only the
		// next window's working set.
		sh.aggs = make(map[shadowKey]*shadowAgg)
		sh.mu.Unlock()
	}

	var firstErr error
	for _, p := range batch {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := d.apps.Upsert(ctx, p.tenant, p.app); err != nil {
			d.logger.Warn("casb: shadow-it upsert failed",
				slog.String("tenant_id", p.tenant.String()),
				slog.String("app", p.app.Name),
				slog.Any("error", err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Start launches the flush loop in a background goroutine and returns
// immediately. interval <= 0 selects DefaultShadowITFlushInterval.
// Start is idempotent; pair it with a deferred Stop so the final flush
// is joined before the DB pool is closed on shutdown. It is the
// one-call "no ops" path for keeping the inventory current.
func (d *ShadowITDiscoverer) Start(ctx context.Context, interval time.Duration) {
	d.startOnce.Do(func() {
		d.started.Store(true)
		go d.run(ctx, interval)
	})
}

// Stop winds the flush loop down and blocks until its final flush has
// completed, so the last window's upserts finish before the caller
// proceeds to close the DB pool. Closing stopCh also aborts the loop
// on the early-return path where the parent context is still live.
// Stop is idempotent and safe to call when Start was never invoked.
func (d *ShadowITDiscoverer) Stop() {
	d.stopOnce.Do(func() { close(d.stopCh) })
	if d.started.Load() {
		<-d.doneCh
	}
}

// run flushes the inventory on a ticker until the parent context is
// cancelled or Stop is called, then performs a final flush so
// in-flight observations are not lost on shutdown.
func (d *ShadowITDiscoverer) run(ctx context.Context, interval time.Duration) {
	defer close(d.doneCh)
	if interval <= 0 {
		interval = DefaultShadowITFlushInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.finalFlush()
			return
		case <-d.stopCh:
			d.finalFlush()
			return
		case <-ticker.C:
			if err := d.Flush(ctx); err != nil {
				d.logger.Warn("casb: shadow-it flush failed", slog.Any("error", err))
			}
		}
	}
}

// finalFlush persists the last window on a short detached deadline so
// it completes even though the parent context is already cancelled.
func (d *ShadowITDiscoverer) finalFlush() {
	flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Flush(flushCtx); err != nil {
		d.logger.Warn("casb: shadow-it final flush failed", slog.Any("error", err))
	}
}
