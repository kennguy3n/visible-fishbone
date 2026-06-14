// Package config loads ShieldNet Gateway (SNG) control-plane runtime
// configuration from the environment.
//
// All configuration is environment-driven (12-factor). A `.env` file is
// loaded up front if present, but real values are read from the process
// environment so that container deployments (k8s, ECS, Nomad) work
// without source changes.
//
// The package deliberately has no external dependencies beyond the Go
// standard library so it can be safely imported from tests, tooling,
// and migrations.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment is the deployment stage the service is running in.
type Environment string

const (
	EnvironmentLocal Environment = "local"
	EnvironmentDev   Environment = "dev"
	EnvironmentQA    Environment = "qa"
	EnvironmentUAT   Environment = "uat"
	EnvironmentProd  Environment = "prod"
)

// IsDevelopment reports whether the environment is local or dev.
func (e Environment) IsDevelopment() bool {
	return e == EnvironmentLocal || e == EnvironmentDev
}

// IsProduction reports whether the environment requires production-grade
// security controls. Returns true for UAT and prod; QA, dev, and local
// are exempt (they may legitimately use weak secrets or mock signing
// keys).
func (e Environment) IsProduction() bool {
	return e == EnvironmentUAT || e == EnvironmentProd
}

// Valid reports whether the value is a recognised environment.
func (e Environment) Valid() bool {
	switch e {
	case EnvironmentLocal, EnvironmentDev, EnvironmentQA, EnvironmentUAT, EnvironmentProd:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (e Environment) String() string { return string(e) }

// Config is the top-level service configuration.
//
// All sub-structs are exported so that tests and helper packages can
// build custom configurations without re-reading the environment.
type Config struct {
	Environment Environment
	AppName     string

	Log                Log
	HTTP               HTTP
	NATS               NATS
	Postgres           Postgres
	RateLimit          RateLimit
	TenantRateLimit    TenantRateLimit
	BruteForce         BruteForce
	CORS               CORS
	Webhook            Webhook
	Integration        Integration
	Auth               Auth
	IAMCore            IAMCore
	Policy             Policy
	Telemetry          Telemetry
	Metrics            Metrics
	TelemetryAnalytics TelemetryAnalytics
	AppRegistry        AppRegistry
	CASB               CASB
	AI                 AI
	ThreatIntel        ThreatIntel
	ManagedDNSFeeds    ManagedDNSFeeds
	MobileAuth         MobileAuth
	Metering           Metering
	PoP                PoP
	Sandbox            Sandbox
	RBI                RBI
	TenantMigration    TenantMigration
	Activity           Activity
	RolloutAutopilot   RolloutAutopilot
	Hibernation        Hibernation
	AlertFeedback      AlertFeedback
}

// AlertFeedback carries the runtime knobs for the leader-only alert
// false-positive feedback tuning loop (internal/service/alert
// feedback.go). The loop walks every (tenant, dimension, window)
// baseline and nudges its anomaly-detection Z-threshold from the
// accumulated operator-feedback false-positive rate.
//
// DEFAULT-OFF: TuningEnabled gates whether the loop is registered at
// all, so a fresh deployment never starts mutating baseline thresholds
// on upgrade — the loop only runs once an operator opts in. When
// enabled, the sweep is activity-tiered (tenancy.TieredSweep) so dormant
// trials are re-tuned at a reduced cadence instead of every cycle, while
// active tenants stay on the per-cycle cadence and cycle 0 still tunes
// everyone.
type AlertFeedback struct {
	// TuningEnabled registers the leader-only tuning loop. Default
	// false (the loop is constructed regardless for on-demand
	// TuneDimension calls, but the periodic sweep is off).
	TuningEnabled bool
	// TuningInterval is the cadence of the tuning sweep. Defaults to
	// 30m. Only consulted when TuningEnabled is true.
	TuningInterval time.Duration
}

// Activity carries the runtime knobs for per-tenant activity tracking
// (internal/service/activity): the data-plane + control-plane signal
// that advances tenants.last_active_at so the dormancy planner
// (internal/service/tenancy) can bucket tenants into activity tiers and
// skip sweeps on idle/dormant ones.
//
// Enabled defaults to ON: the recorder is the writer that makes the
// dormancy story real (without it last_active_at is never populated and
// the planner sees every tenant as dormant). It is debounced and writes
// asynchronously, so the hot-path cost is negligible; the knobs exist to
// tune the debounce window and the drain queue under extreme fleets, or
// to disable the writer entirely for diagnostics.
type Activity struct {
	// Enabled wires the activity recorder onto the telemetry consumer
	// and the authenticated API chain. Default true. When false the
	// recorder is not constructed and last_active_at is not written.
	Enabled bool
	// MinInterval is the per-tenant debounce window: at most one
	// last_active_at write per tenant per interval. Must be well under
	// the planner's IdleAfter (24h). Defaults to 5m. Anything <= 0 is
	// treated as the recorder default by the constructor.
	MinInterval time.Duration
	// QueueSize bounds the in-flight touches buffered for the async
	// drain worker; beyond it, touches are dropped (forward-only, so
	// the next activity re-establishes the signal). Defaults to 4096.
	QueueSize int
}

// Hibernation carries the runtime knobs for dormant-tenant scale-to-zero
// hibernation (internal/service/tenancy/hibernation): the leader-only
// controller that parks a tenant's ongoing telemetry / NATS / warm-state
// draw once it reaches the dormant tier, and the wake-on-activity path
// that rehydrates it on the first sign of life.
//
// Enabled defaults to OFF so a fresh deployment (and every upgrade)
// hibernates nothing until an operator opts in — no surprise enforcement
// on upgrade. When off, none of the hibernation loops are constructed
// and the telemetry/retention/metering hooks are not wired, so the
// feature is fully inert.
type Hibernation struct {
	// Enabled gates the whole feature: the leader-only controller, the
	// per-replica registry sync + wake coordinator, and the telemetry /
	// retention / metering hooks. Default false. When false, a tenant is
	// never parked and behaves exactly as before this feature shipped.
	Enabled bool
	// SweepInterval is the cadence of the leader-only controller's
	// reconcile loop (classify every tenant, hibernate newly-dormant
	// ones, wake any that climbed back out as a backstop). Defaults to
	// 1h. Anything <= 0 is treated as the default by the loop; the
	// strict parser still rejects un-parseable values.
	SweepInterval time.Duration
	// RegistrySyncInterval is the cadence at which each replica refreshes
	// its in-memory hibernation registry from the store, so the
	// telemetry sampler and retention resolver on every replica honor the
	// leader's decisions. Defaults to 30s. The activity-triggered wake
	// path clears a tenant inline, so this only bounds how fast a newly
	// hibernated tenant's telemetry pause propagates to followers.
	RegistrySyncInterval time.Duration
}

// TenantMigration carries the runtime knobs for the WS11 cross-region
// tenant-migration state machine (internal/service/tenant). A migration
// is normally driven synchronously by the API handler, but a crash or a
// cancelled request context can strand one in a non-terminal state; the
// leader-only resume loop re-drives any such migration from its durable
// checkpoint.
type TenantMigration struct {
	// ResumeInterval is the cadence of the leader-only loop that scans
	// for in-flight (non-terminal) migrations and re-drives them from
	// their durable checkpoint. It bounds how long a migration stranded
	// by a crash or a cancelled request context waits before being
	// picked up, independent of leadership changes. Defaults to 5m: long
	// enough that the cross-tenant ListResumable scan is cheap, short
	// enough that a stranded tenant does not sit in dual-read for long.
	ResumeInterval time.Duration
}

// RBI carries the runtime knobs for Remote Browser Isolation
// (internal/service/rbi, Gap #8). When a URL matches the RBI
// trigger policy the SWG redirects it to the RBI proxy, which
// renders the page in a disposable headless-Chromium container.
// All knobs are optional: with ProxyBaseURL unset the RBI service
// still runs (sessions can be inspected) but CreateSession reports
// "not configured" so the SWG falls back to a normal allow/block.
//
// Parsed leniently (plain RBI_* strings/duration + a CSV category
// list): a misconfig degrades to "not configured" rather than
// failing boot.
type RBI struct {
	// ProxyBaseURL is the externally-reachable URL of the RBI proxy
	// (e.g. "https://rbi.example.com"). Empty disables RBI.
	ProxyBaseURL string
	// SessionTTL is how long an RBI session stays active. Defaults
	// to 15m.
	SessionTTL time.Duration
	// TriggerCategories lists URL categories that trigger isolation
	// (comma-separated RBI_TRIGGER_CATEGORIES). Empty disables
	// category-based triggering.
	TriggerCategories []string
	// RiskScoreThreshold (RBI_RISK_SCORE_THRESHOLD), when >0,
	// triggers RBI for URLs whose risk score meets or exceeds it.
	// Range [0,100]; 0 disables risk-score triggering. Parsed
	// leniently — a bad value falls back to 0 (disabled).
	RiskScoreThreshold int
	// IsolateUncategorised (RBI_ISOLATE_UNCATEGORISED) triggers RBI
	// for any URL the categoriser cannot classify.
	IsolateUncategorised bool
	// ExplicitIsolate (RBI_EXPLICIT_ISOLATE) lists host patterns that
	// always route to RBI regardless of category/risk (comma-
	// separated). Highest precedence; deny-wins against ExplicitBypass.
	ExplicitIsolate []string
	// ExplicitBypass (RBI_EXPLICIT_BYPASS) lists host patterns that are
	// never isolated even when a category/risk rule would match
	// (comma-separated). Overridden by ExplicitIsolate.
	ExplicitBypass []string
	// ArtifactRegion (RBI_ARTIFACT_REGION) is the region the control
	// plane persists RBI artifact records in. When set, artifact
	// writes are gated by the fail-closed data-residency Guard against
	// this region; empty disables residency enforcement for artifacts
	// (opt-in, matching the residency service's unconstrained default).
	ArtifactRegion string
	// Artifact transfer gates. Each defaults to false: isolation
	// defaults to a sealed boundary and an operator opts specific
	// transfers back in.
	//   RBI_ARTIFACT_CLIPBOARD_INBOUND  remote→endpoint paste-in
	//   RBI_ARTIFACT_CLIPBOARD_OUTBOUND endpoint→remote copy-out
	//   RBI_ARTIFACT_FILE_DOWNLOAD      remote→endpoint download
	//   RBI_ARTIFACT_FILE_UPLOAD        endpoint→remote upload
	ArtifactClipboardInbound  bool
	ArtifactClipboardOutbound bool
	ArtifactFileDownload      bool
	ArtifactFileUpload        bool
}

// Sandbox carries the runtime knobs for zero-day file analysis
// (internal/service/sandbox, Gap #7). When the SWG malware stage
// sees a file whose hash it has no static verdict for, the control
// plane submits it to the configured detonation provider and caches
// the verdict by SHA-256. All knobs are optional: with Provider
// unset (the default) the sandbox service still runs and serves
// persisted verdicts, but submissions return "no provider" rather
// than detonating — so the data-plane integration is fail-open.
//
// Parsed leniently (plain SANDBOX_* strings/duration): a misconfig
// degrades to "no provider" rather than failing boot, matching the
// fail-open posture of an opportunistic enrichment feature.
type Sandbox struct {
	// Provider selects the detonation backend: "" / "none" (disabled),
	// "cuckoo", "cape", "generic" (BYO webhook), or "reputation"
	// (multi-provider hash-lookup aggregator over VirusTotal +
	// Hybrid Analysis — see VirusTotalAPIKey / HybridAnalysisAPIKey).
	// An unrecognised value is treated as disabled.
	Provider string
	// CacheTTL is how long a resolved verdict stays in the in-memory
	// hot-path cache in front of Postgres. Defaults to 1h.
	CacheTTL time.Duration
	// Cuckoo* configure the Cuckoo Sandbox REST adapter.
	CuckooBaseURL  string
	CuckooAPIToken string
	// CAPE* configure the CAPEv2 REST adapter.
	CAPEBaseURL  string
	CAPEAPIToken string
	// Generic* configure the bring-your-own webhook adapter.
	GenericSubmitURL  string
	GenericStatusURL  string
	GenericAuthHeader string
	GenericAuthValue  string
	// VirusTotalAPIKey enables the VirusTotal v3 hash-reputation
	// provider when Provider is "reputation". Empty leaves it out of
	// the aggregator.
	VirusTotalAPIKey string
	// VirusTotalCacheTTL overrides the verdict cache TTL for
	// VirusTotal-sourced verdicts. Defaults to CacheTTL when unset.
	VirusTotalCacheTTL time.Duration
	// HybridAnalysisAPIKey enables the Hybrid Analysis hash-reputation
	// provider when Provider is "reputation". Empty leaves it out.
	HybridAnalysisAPIKey string
	// HybridAnalysisCacheTTL overrides the verdict cache TTL for
	// Hybrid-Analysis-sourced verdicts. Defaults to CacheTTL.
	HybridAnalysisCacheTTL time.Duration
}

// Metering carries the runtime knobs for the cost-metering and
// budget-guardrail subsystem (internal/service/metering). The metering
// service accumulates per-tenant resource consumption in atomic
// counters and flushes them to Postgres every FlushInterval;
// BudgetEnforcer gates LLM (and other) usage against per-tenant
// budgets that resolve in precedence order
// override → tier default → global default → unbounded.
type Metering struct {
	// FlushInterval is the cadence at which accumulated usage deltas
	// are batch-upserted into tenant_usage. Defaults to 60s. Parsed
	// strictly (METERING_FLUSH_INTERVAL) so a typo fails boot rather
	// than silently reverting and skewing cost accounting.
	FlushInterval time.Duration
	// DefaultBudgets is the global, tier-independent fallback map of
	// per-meter hard limits applied only when neither a tenant
	// override nor a tier default exists. Keys are meter names (e.g.
	// "s3_bytes_archived"); an unknown meter name or a non-positive
	// value is a fatal config error — the enforcer fails construction
	// (boot fails) rather than silently dropping it. Populated from
	// METERING_DEFAULT_BUDGETS as a comma-separated "meter=value"
	// list. Optional: nil means the only fallbacks are the built-in
	// per-tier defaults.
	//
	// These also act as the fail-open safety net: if the budget store
	// is unreachable and there is no cached limit set for a tenant, the
	// enforcer falls back to these global defaults. With none configured
	// the fallback is unbounded (budget enforcement is fail-open during
	// a store outage — appropriate for a cost-control, not security,
	// feature), so operators who need cost containment to hold even
	// during a DB outage should configure them.
	DefaultBudgets map[string]int64
}

// PoP carries the runtime knobs for the Cloud PoP
// (Point-of-Presence) service — the cloud-delivered SWG/DNS/ZTNA
// edge for tenants without an on-premise edge VM (see
// internal/service/pop). The control plane keeps an in-memory
// registry of PoP locations refreshed from Postgres, ingests their
// health beacons over NATS, routes cloud-only tenants to their
// nearest healthy PoP, and publishes GeoDNS steering records.
type PoP struct {
	// RegistryRefreshInterval is how often each replica reloads the
	// PoP fleet from Postgres into its lock-free in-memory registry.
	// Defaults to 30s. Beacons keep the registry fresh between
	// refreshes; this bounds how long a newly-registered or disabled
	// PoP takes to appear/disappear fleet-wide.
	RegistryRefreshInterval time.Duration
	// HealthTTL is how recent a PoP's last health beacon must be for
	// the PoP to count as healthy for assignment. Beacons older than
	// this drop the PoP out of the assignable set. Defaults to 90s.
	HealthTTL time.Duration
	// HighWaterFraction is the utilization (0,1] at or above which a
	// PoP is considered overloaded: excluded from new assignments and
	// a rebalance candidate. Defaults to 0.85.
	HighWaterFraction float64
	// GeoDNSHostname is the steering FQDN clients resolve during
	// enrolment. Defaults to edge.sng.example.com.
	GeoDNSHostname string
	// GeoDNSRoutingPolicy selects the DNS steering strategy:
	// latency | weighted | simple. Defaults to latency.
	GeoDNSRoutingPolicy string
	// GeoDNSTTL is the TTL stamped on every emitted steering record.
	// Short TTLs let a failed PoP drain quickly. Defaults to 30s.
	GeoDNSTTL time.Duration
	// GeoDNSPublishInterval is how often the leader re-publishes the
	// steering zone from the live registry. Defaults to 30s.
	GeoDNSPublishInterval time.Duration
	// RebalanceEnabled gates the leader-only capacity rebalancer that
	// drains overloaded PoPs by moving non-override tenants to
	// less-loaded PoPs. Defaults to true.
	RebalanceEnabled bool
	// RebalanceInterval is the cadence of the capacity rebalancer.
	// Defaults to 60s.
	RebalanceInterval time.Duration
}

// MobileAuth carries the runtime knobs for control-plane IdP
// federation — the mobile native-SSO flow where a mobile agent
// presents an OIDC ID token and the control plane exchanges it for
// an SNG session bound to device + user identity (see
// internal/service/identity/oidc.go).
type MobileAuth struct {
	// SessionTokenTTL is how long a minted SNG mobile session token
	// is valid. Independent of Auth.AccessTokenTTL so operators can
	// give mobile sessions a different (typically shorter) lifetime
	// than operator-console tokens. Defaults to 1h.
	SessionTokenTTL time.Duration
	// DiscoveryCacheTTL is how long an OIDC discovery document (and
	// its JWKS) is cached per issuer before re-fetching. Defaults to
	// 24h, matching the OIDC ecosystem's typical key-rotation window.
	DiscoveryCacheTTL time.Duration
	// MaxProvidersPerTenant caps how many IdP configs a single tenant
	// may register. Defaults to 10. The handler enforces this at
	// create time.
	MaxProvidersPerTenant int
	// AutoProvisionUsers controls just-in-time user provisioning: when
	// a validated ID token maps to an email with no existing user in
	// the tenant, the OIDCService creates one (reusing the SCIM user
	// shape). Defaults to true. Set false to require users be
	// pre-provisioned (e.g. via SCIM) before they can federate.
	AutoProvisionUsers bool
	// DirectorySyncEnabled gates the leader-only IdP directory-sync
	// loop (internal/service/identity.SyncService) in main(). When
	// false (the default) the loop never starts and the per-config
	// directory-credential admin endpoints stay unmounted, so this is
	// a strictly opt-in feature. When true, the loop reconciles each
	// tenant's directory (Okta / Microsoft Graph / Google) on the
	// DirectorySyncInterval cadence, off-boarding upstream-removed
	// users and pushing ZTNA revocations. Only configs that have a
	// stored directory credential are synced; the rest are skipped.
	DirectorySyncEnabled bool
	// DirectorySyncInterval is the cadence of the directory-sync loop
	// (only consulted when DirectorySyncEnabled). Defaults to 1h. The
	// activity-tiered dormancy planner further reduces how often idle
	// and dormant tenants are reconciled within this cadence.
	DirectorySyncInterval time.Duration
}

// AppRegistry carries the runtime knobs for the curated
// app-classification engine. The Syncer pulls vendor-published
// endpoint lists (Microsoft 365, Google IP ranges, AWS, etc.) on
// a periodic schedule; SyncEnabled gates the background loop and
// SyncInterval sets its cadence. Both default to "on" with a
// 24-hour cadence so a fresh deployment behaves the way
// docs/TRAFFIC_CLASSIFICATION.md describes — operators do not
// have to set anything to get the periodic refresh. Set
// APP_REGISTRY_SYNC_ENABLED=false to disable (useful for local
// development, air-gapped clusters, and replicas that should not
// duplicate the primary's outbound vendor fetches).
type AppRegistry struct {
	// SyncEnabled toggles the periodic vendor-endpoint sync loop
	// in main(). When false, the admin-triggered
	// `POST /admin/app-registry/sync` endpoint still works — only
	// the background ticker is suppressed.
	SyncEnabled bool
	// SyncInterval is the cadence of the background sync loop.
	// Defaults to 24h. Anything <= 0 is treated as the default by
	// the Syncer; the strict parser still rejects un-parseable
	// values so an operator typo doesn't silently revert.
	SyncInterval time.Duration
}

// CASB carries the runtime knobs for the per-tenant shadow-IT NoOps
// pipeline (migration 061): the discovery hook that classifies and
// acts on each newly discovered app, and the leader-only periodic
// Reconcile + per-tenant digest sweep.
//
// Both gates default to OFF so a fresh deployment keeps the prior
// discover-and-display-only behaviour until an operator opts in.
// NoOpsEnabled turns on classification, recommendations, the audit
// trail and digests (all non-mutating). NoOpsAutoEnforce additionally
// wires the enforcement primitive so the engine's deliberately narrow
// auto window (high-confidence, high-risk, unsanctioned apps, acted on
// only with the non-blocking Protect verb) takes effect — a separate,
// explicit decision so enabling observation never silently starts
// mutating tenant traffic classes.
type CASB struct {
	// NoOpsEnabled gates the whole pipeline (discovery hook +
	// leader-only Reconcile/digest loop). Default false.
	NoOpsEnabled bool
	// NoOpsAutoEnforce wires the appdb enforcer into the engine so
	// the narrow auto window enforces; when false the engine is
	// recommend-only (classify + audit + digest, never mutate).
	// Default false. Ignored unless NoOpsEnabled is true.
	NoOpsAutoEnforce bool
	// NoOpsReconcileInterval is the cadence of the leader-only sweep
	// that reconciles inventory drift and builds per-tenant digests.
	// Defaults to 1h. Anything <= 0 is treated as the default by the
	// loop; the strict parser still rejects un-parseable values.
	NoOpsReconcileInterval time.Duration
}

// RolloutAutopilot carries the fleet/MSP-level knobs for the NoOps
// auto-promoter (WS-5). The autopilot advances tenant/capability rollout
// state along the existing off->monitor->enforce machine without operator
// action: it auto-enrols a fresh tenant into monitor (dry-run) and, once
// the monitor-phase guardrail metrics have held under the promotion
// ceiling for the dwell window, promotes monitor->enforce.
//
// It is itself a DEFAULT-OFF gate: Enabled defaults false, so an upgrade
// never silently starts auto-promoting — turning on the NoOps autopilot
// is an explicit operator decision. The auto-demote-to-safety guardrail
// (CapabilityRollout's Threshold) is unchanged and always faster/easier
// than promotion: demotion needs no dwell and no minimum evidence beyond
// its own MinSamples, while promotion needs the full dwell window, the
// MinSamples floor, and an under-ceiling reading.
type RolloutAutopilot struct {
	// Enabled is the master default-OFF gate. When false the autopilot
	// is neither constructed nor scheduled and nothing auto-advances.
	Enabled bool
	// Interval is the cadence of the leader-only promotion sweep.
	// Defaults to 1h. Anything <= 0 is treated as the default by the
	// loop; the strict parser still rejects un-parseable values.
	Interval time.Duration
	// AutoEnrol advances off->monitor on enrolment so a freshly-seeded
	// tenant begins dry-running with zero operator clicks. Defaults true
	// (only consulted when Enabled). Set false for the most conservative
	// posture: promote only tenants an operator already moved to monitor.
	AutoEnrol bool
	// DwellWindow is the minimum time a capability must dwell in monitor
	// before it is eligible for monitor->enforce. Defaults to 24h. A
	// value <= 0 disables promotion (the autopilot is enrol-only).
	DwellWindow time.Duration
	// MinSamples is the minimum monitor observations required as
	// promotion evidence. Defaults to 200. Must be >= the demote
	// threshold's MinSamples (the autopilot constructor enforces this).
	MinSamples int
	// MaxErrorRate is the promotion ceiling on the monitor-phase error
	// rate (0..1). Defaults to 0.01. Must be <= the demote threshold's
	// MaxErrorRate so a demote-worthy reading also blocks promotion.
	MaxErrorRate float64
	// MaxDenyRate is the promotion ceiling on the monitor-phase
	// would-have-block (deny) rate (0..1). Defaults to 0.05. Must be <=
	// the demote threshold's MaxDenyRate.
	MaxDenyRate float64
	// Capabilities restricts which rollout capabilities the autopilot
	// governs (CSV of capability ids, e.g. "idp_directory_sync"). Empty
	// means "all governed capabilities". A capability not in the set is
	// only ever advanced by an operator.
	Capabilities []string
}

// AI carries runtime knobs for the AI assistant service
// (Phase 3 Block 6). When Endpoint is empty the service runs in
// template-only mode — all summaries are deterministic and the
// suggest-policy / troubleshoot endpoints return 503.
type AI struct {
	Endpoint string
	APIKey   string
	Model    string
	// ModelFamily tunes the LLM system prompt to the configured
	// model's strengths. Recognised values: "ternary-bonsai",
	// "openai-compat", or "auto" (infer from the model name).
	// Defaults to "auto".
	ModelFamily string
	Timeout     time.Duration
	// GuardrailMaxRequestsPerMinute is the per-tenant request rate
	// limit applied to every LLM-backed AI call. Defaults to 60.
	GuardrailMaxRequestsPerMinute int
	// GuardrailMaxTokensPerDay is the per-tenant daily token budget
	// for LLM-backed AI calls (cost control). Defaults to 100000.
	GuardrailMaxTokensPerDay int

	// InferencePoolEnabled gates the WS-9 fleet-scale shared inference
	// pool: a fair, tenant-aware admission layer with a bounded global
	// concurrency cap in front of the single shared LLM backend.
	// DEFAULT-OFF — when false the LLM path is exactly as before
	// (per-tenant guardrails directly wrapping the HTTP provider) so an
	// upgrade introduces no new scheduling behaviour. When true, every
	// tenant's call is fair-queued so one bursty tenant cannot starve
	// the fleet's shared model capacity.
	InferencePoolEnabled bool
	// InferencePoolMaxConcurrent is the global cap on in-flight requests
	// to the shared backend. Size it to the model server's real
	// parallelism (e.g. llama-server --parallel), NOT the tenant count.
	// Defaults to 4.
	InferencePoolMaxConcurrent int
	// InferencePoolMaxQueuePerTenant bounds how many requests one tenant
	// may have waiting before the pool sheds its load (graceful
	// template fallback). Defaults to 8.
	InferencePoolMaxQueuePerTenant int
	// InferencePoolMaxWait caps how long a request may sit queued before
	// it degrades to the template path. 0 ⇒ bounded only by the request
	// context. Defaults to the AI_LLM_TIMEOUT-aligned 15s.
	InferencePoolMaxWait time.Duration
}

// ThreatIntel carries the runtime knobs for the WORKSTREAM 8 threat
// feed aggregator (internal/service/ai feed_*.go). Each upstream is
// gated behind its URL: with no URLs set the aggregator still runs
// (the in-memory IOC store + expiry sweeper) but pulls nothing, so
// the IOC->enforcement path is a safe no-op until an operator points
// it at real feeds. Network calls happen only for configured feeds,
// honouring the "gate real network calls behind config" rule.
//
// Parsed leniently (plain THREATINTEL_* strings/durations): a
// misconfig degrades to "feed disabled" rather than failing boot,
// matching the fail-open posture of the other enrichment features.
type ThreatIntel struct {
	// RefreshInterval is the default per-feed refresh cadence.
	// Defaults to 1h (the workstream's mandated hourly default).
	RefreshInterval time.Duration
	// DefaultTTL ages out indicators a feed did not date itself.
	// Zero leaves them permanent (matching the demotion engine's
	// threat_feed TTL).
	DefaultTTL time.Duration
	// MinConfidence is the store-wide confidence floor in [0,1];
	// indicators below it are dropped at ingest. Defaults to 0.
	MinConfidence float64
	// TAXIIURL / TAXIIToken configure a STIX/TAXII 2.1 collection
	// endpoint. The token, when set, is sent as a Bearer
	// Authorization header.
	TAXIIURL   string
	TAXIIToken string
	// OTXURL / OTXAPIKey configure the AlienVault OTX subscribed-
	// pulses API. The key is sent as the X-OTX-API-KEY header.
	OTXURL    string
	OTXAPIKey string
	// URLhausURL / MalwareBazaarURL / FeodoTrackerURL configure the
	// three abuse.ch community feeds (malware URLs, malware hashes,
	// C2 IPs respectively).
	URLhausURL       string
	MalwareBazaarURL string
	FeodoTrackerURL  string
	// CSVURL / JSONURL configure a generic CERT/ISAC flat-file feed
	// in CSV (indicator-per-row) or JSON (array-of-objects) form.
	CSVURL  string
	JSONURL string
	// MISPURL / MISPAuthKey configure a MISP feed (events or
	// attributes REST-search export, or a static event JSON). The
	// key, when set, is sent as the MISP "Authorization" header.
	MISPURL     string
	MISPAuthKey string
	// MISPIncludeNonIDs, when true, ingests MISP attributes that are
	// NOT flagged `to_ids`. Defaults to false: only `to_ids:true`
	// attributes (MISP's "intended for automated detection"
	// convention) become enforceable IOCs, so contextual attributes
	// never cause a false-positive block.
	MISPIncludeNonIDs bool
	// Persistence snapshots the in-memory IOC store to Postgres and
	// restores it on boot, so a control-plane restart does not open
	// an enforcement gap until every feed re-fetches during warm-up
	// (which, with hourly feeds and a slow/unreachable upstream, can
	// be a long window). Defaults to true; disable with
	// THREATINTEL_PERSISTENCE=false. Parsed leniently, matching the
	// rest of this section.
	Persistence bool
	// PersistInterval is how often the active indicator set is
	// flushed to durable storage while running; a final flush also
	// runs on graceful shutdown so the freshest snapshot survives a
	// restart. Defaults to 5m. Only meaningful when Persistence is
	// enabled.
	PersistInterval time.Duration
	// AutoRecompile, when true (the default), schedules a policy
	// recompile after every feed update so freshly-ingested IP / URL
	// / hash IOCs reach enforcement bundles without waiting for an
	// operator-triggered Compile. Set THREATINTEL_AUTO_RECOMPILE=false
	// to keep the prior pull-only behaviour.
	AutoRecompile bool
	// RecompileMinInterval is the minimum spacing between two
	// feed-driven recompiles; bursts of feed updates coalesce into at
	// most one recompile per window. Defaults to 5m.
	RecompileMinInterval time.Duration
	// StaleFactor multiplies a feed's refresh interval to derive its
	// staleness window: a feed that has not refreshed successfully
	// within StaleFactor x its interval is reported stale (metric +
	// log). Defaults to 3.
	StaleFactor float64
	// HealthInterval is how often per-feed staleness and store-size
	// telemetry is evaluated and published. Defaults to 1m.
	HealthInterval time.Duration
}

// ManagedDNSFeeds carries the runtime knobs for the MANAGED DNS
// threat-intel feed pipeline (internal/service/threatintel): the
// leader-gated control-plane loop that fetches DNS reputation /
// category feeds from configured upstream URLs, normalizes them into
// the feed format the `sng-dns` crate consumes, and signs +
// distributes the resulting bundle over NATS.
//
// This is distinct from the ThreatIntel section above (the WS8 IOC
// aggregator for the IPS data plane, env prefix THREATINTEL_*). This
// section produces the DNS reputation / category feeds specifically and
// uses the THREAT_INTEL_* env prefix.
//
// The whole pipeline is DEFAULT-OFF: Enabled gates registration of the
// RunIfLeader loop, so with the flag unset no goroutine is started and
// no upstream is contacted. Parsed leniently for the non-load-bearing
// knobs; RefreshInterval is validated (> 0 when Enabled) so a typo
// fails boot rather than silently busy-looping.
type ManagedDNSFeeds struct {
	// Enabled gates the leader-only managed-feed loop. Default false.
	// THREAT_INTEL_ENABLED.
	Enabled bool
	// RefreshInterval is the cadence of the feed refresh loop. Defaults
	// to 1h. Only consulted when Enabled. THREAT_INTEL_REFRESH_INTERVAL.
	RefreshInterval time.Duration
	// SigningKeyHex is the hex-encoded Ed25519 signing key (32-byte seed
	// or 64-byte expanded). When empty the control plane logs a loud
	// warning and signs with an EPHEMERAL key (bundles then only verify
	// within this process lifetime), mirroring the compliance-evidence
	// fallback. THREAT_INTEL_SIGNING_KEY_HEX.
	SigningKeyHex string
	// KeyID labels the signing key in the published envelope so the edge
	// consumer can select the matching pinned verifying key from its
	// trust store. THREAT_INTEL_KEY_ID.
	KeyID string
	// Subject overrides the NATS subject the signed bundle is published
	// on. Empty applies the pipeline default
	// (sng.platform.policy.threatintel.dns.v1). THREAT_INTEL_SUBJECT.
	Subject string
	// ReputationURLs are upstream exact-match known-bad FQDN lists. Each
	// becomes a reputation source. THREAT_INTEL_REPUTATION_URLS (CSV).
	ReputationURLs []string
	// CategoryFeeds maps a category name to its upstream domain-list
	// URL. Configured as a CSV of `category=url` pairs.
	// THREAT_INTEL_CATEGORY_FEEDS.
	CategoryFeeds map[string]string
	// HTTPTimeout bounds a single feed fetch. Defaults to 30s.
	// THREAT_INTEL_HTTP_TIMEOUT.
	HTTPTimeout time.Duration
	// MaxFeedBytes caps a single feed response. Zero applies the
	// pipeline default (64 MiB). THREAT_INTEL_MAX_FEED_BYTES.
	MaxFeedBytes int64
}

// Log carries structured-logging configuration.
type Log struct {
	Level  string
	Format string // "json" or "text"
}

// HTTP holds the HTTP server config.
type HTTP struct {
	Host string
	Port int
	// ReadTimeout caps the total time the server spends reading
	// each request, including its body. Mapped to
	// http.Server.ReadTimeout.
	ReadTimeout time.Duration
	// ReadHeaderTimeout caps the time the server spends reading
	// just the request headers, defending against Slowloris-style
	// header-stuffing attacks independent of body upload speed.
	// Mapped to http.Server.ReadHeaderTimeout. Typically shorter
	// than ReadTimeout.
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	// ShutdownTimeout caps how long the graceful shutdown sequence
	// will wait for in-flight requests before forcibly closing
	// connections.
	ShutdownTimeout time.Duration
}

// Addr returns the listen address (host:port).
func (h HTTP) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// NATS contains all NATS / JetStream connection settings.
type NATS struct {
	URL           string
	Name          string
	User          string
	Password      string
	Token         string
	CredsFile     string
	TLSCAFile     string
	TLSCertFile   string
	TLSKeyFile    string
	TLSInsecure   bool
	ReconnectWait time.Duration
	MaxReconnects int
	// ConnectTimeout is the dial timeout for the initial TCP / TLS
	// handshake against the NATS server, mapped to nats.Timeout().
	// Defaults to 5s and is intentionally separate from
	// RequestTimeout so operators can tune dial latency budgets
	// without affecting per-request deadlines.
	ConnectTimeout time.Duration
	// RequestTimeout is the per-request deadline used for
	// JetStream request-reply calls (nats.Conn.RequestWithContext,
	// nats.JetStream PublishOpts, etc.). It is NOT used for the
	// initial connection dial — that is ConnectTimeout. Defaults
	// to 5s.
	RequestTimeout       time.Duration
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration
	DedupWindow          time.Duration
	Replicas             int
	Storage              string // "file" or "memory"
	FetchBatchSize       int
	FetchMaxWait         time.Duration
	// StreamPrefix is prepended to every JetStream stream name
	// (e.g. "SNG_TELEMETRY"). It isolates *stream names* only;
	// subject patterns (`sng.*.telemetry.>`, etc.) are hard-coded
	// and NOT parameterised by prefix. To run multiple SNG control
	// planes on the same NATS infrastructure, deploy each in its
	// own JetStream domain or NATS account — StreamPrefix is then
	// a readability aid for telling stream names apart across
	// domains, not a multi-tenancy primitive on a shared account.
	// See `nats.DefaultStreams` for the exact subject patterns and
	// why overlap rejection in JetStream makes single-account
	// sharing impractical. Defaults to "SNG".
	StreamPrefix string
	// Partitions is the number of telemetry stream cells the
	// control plane fans out across (env NATS_PARTITIONS, default
	// 1). At 1 the behaviour is identical to the historical
	// single-stream layout (`SNG_TELEMETRY`, subject
	// `sng.*.telemetry.>`). At N>1 the telemetry workload is
	// sharded into N cells `SNG_TELEMETRY_0`…`SNG_TELEMETRY_{N-1}`,
	// each scoped to a partition slot in the subject
	// (`sng.{partition}.*.telemetry.>`), so the control plane can
	// scale telemetry ingestion horizontally past the throughput
	// ceiling of a single JetStream stream. The owning tenant of an
	// event determines its partition via the consistent-hash
	// TenantPartitioner. validate() bounds this to [1, 256].
	Partitions int
}

// Postgres carries database connection config.
type Postgres struct {
	Host         string
	Port         int
	User         string
	Password     string
	Database     string
	SSLMode      string
	MaxOpenConns int
	// MinConns is the **floor** on the pgxpool connection pool — the
	// pool eagerly creates and maintains at least this many
	// connections in the background. This is **NOT** the
	// database/sql `MaxIdleConns` ceiling: pgxpool does not expose an
	// idle-connection ceiling, instead retiring excess connections
	// after `MaxConnIdleTime`. We deliberately name the field
	// `MinConns` and the env var `PG_MIN_CONNS` to match the pgx
	// semantic so an operator setting `PG_MIN_CONNS=5` gets the
	// floor they're asking for, not the inverted ceiling implied by
	// the older `PG_MAX_IDLE_CONNS` name.
	MinConns        int
	ConnMaxLifetime time.Duration
	ConnTimeout     time.Duration
	// AppRole is the PostgreSQL role the runtime adopts on every
	// new physical connection via `SET SESSION ROLE`. The login
	// user (PG_USER) authenticates the TCP connection; AppRole is
	// the role whose grants and RLS policies the application
	// actually exercises. See `docs/deploy.md` for the role-
	// separation architecture (`sng_app_login` → `sng_app`).
	//
	// Empty disables the SET SESSION ROLE hook: connections run
	// as PG_USER directly. This is intended ONLY for development
	// where a single PG_USER is granted DML directly; production
	// must always set PG_APP_ROLE (default: `sng_app`) so RLS
	// policies are enforced.
	AppRole string
	// ReadReplicaHosts is the comma-separated list of read-replica
	// hosts (env PG_READ_REPLICA_HOSTS). Empty disables the
	// read-write split — every query goes to the primary. When
	// populated, the repository layer routes read-only
	// transactions (List*/Get*/Count*, all `withTenantRO` paths)
	// to a healthy replica chosen round-robin, falling back to the
	// primary if every replica is unhealthy. RLS `set_config` runs
	// inside the replica transaction exactly as it does on the
	// primary, so tenant isolation is enforced on replicas too.
	ReadReplicaHosts []string
	// ReadReplicaPort is the TCP port the replicas listen on
	// (env PG_READ_REPLICA_PORT). 0 (the default) means "inherit
	// Port" — the common topology where every node listens on the
	// same port. validate() bounds a non-zero value to [1, 65535].
	ReadReplicaPort int
	// PgBouncerMode toggles transaction-pooling-safe behaviour
	// (env PG_PGBOUNCER_MODE). When false (default) the runtime
	// adopts AppRole once per physical connection via a
	// session-level `SET SESSION ROLE` (the AfterConnect hook).
	// That command is incompatible with a PgBouncer running in
	// transaction-pooling mode, where each transaction may land on
	// a different server-side connection and session state is
	// reset between transactions. When true, the session-level
	// hook is skipped and the repository layer instead issues a
	// transaction-local `SET LOCAL ROLE` at the top of every
	// tenant/system transaction, which is reverted on
	// commit/rollback and therefore safe under transaction
	// pooling.
	PgBouncerMode bool
}

// MigrationURL returns a `pgx5://` URL suitable for passing to
// golang-migrate/v4's pgx/v5 database driver.
//
// The migrate library uses URL parsing (net/url) rather than libpq
// keyword/value strings, so we render the components with the
// standard `userinfo@host:port/dbname?query` shape and let
// `url.URL.String()` percent-escape any awkward characters. SSL mode
// and connect timeout are carried as query parameters; the latter
// is documented by golang-migrate as `x-connect-timeout`.
func (p Postgres) MigrationURL() string {
	u := url.URL{
		Scheme: "pgx5",
		User:   url.UserPassword(p.User, p.Password),
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:   "/" + p.Database,
	}
	q := u.Query()
	if p.SSLMode != "" {
		q.Set("sslmode", p.SSLMode)
	}
	if p.ConnTimeout > 0 {
		q.Set("connect_timeout", strconv.Itoa(connectTimeoutSeconds(p.ConnTimeout)))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// DSN returns a libpq keyword/value connection string.
//
// Values containing spaces, backslashes or single-quotes are
// single-quoted per the libpq syntax so a password like
// `my secret'pass\` is parsed correctly by pgxpool.ParseConfig
// instead of producing a confusing boot-time error.
//
// libpq keyword/value rules (per the official spec):
//   - Empty values must be written as ”.
//   - Values containing whitespace or single quotes must be quoted.
//   - Within single quotes, single quotes and backslashes are
//     escaped with a leading backslash.
func (p Postgres) DSN() string {
	var b strings.Builder
	writePair := func(k, v string) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(libpqQuote(v))
	}
	writePair("host", p.Host)
	writePair("port", strconv.Itoa(p.Port))
	writePair("user", p.User)
	writePair("password", p.Password)
	writePair("dbname", p.Database)
	writePair("sslmode", p.SSLMode)
	writePair("connect_timeout", strconv.Itoa(connectTimeoutSeconds(p.ConnTimeout)))
	return b.String()
}

// ReplicaPort returns the port read replicas listen on: the
// explicit ReadReplicaPort when set, otherwise the primary Port.
// Centralising the 0-means-inherit rule here keeps DSN rendering
// and validation in agreement.
func (p Postgres) ReplicaPort() int {
	if p.ReadReplicaPort > 0 {
		return p.ReadReplicaPort
	}
	return p.Port
}

// ReplicaDSN returns a libpq keyword/value connection string for a
// read replica reachable at `host`. It is identical to DSN() except
// the host and port are overridden with the replica endpoint
// (ReplicaPort): user, password, database, sslmode, and
// connect_timeout are inherited from the primary so a replica is
// authenticated and TLS-protected exactly like the primary. The
// AppRole / RLS posture is applied by the pool layer (AfterConnect
// in session mode, SET LOCAL ROLE in PgBouncer mode), not the DSN.
func (p Postgres) ReplicaDSN(host string) string {
	rp := p
	rp.Host = host
	rp.Port = p.ReplicaPort()
	return rp.DSN()
}

// connectTimeoutSeconds renders ConnTimeout as the integer-seconds value
// libpq expects for connect_timeout. libpq treats `connect_timeout=0`
// as "wait indefinitely", so any positive sub-second duration must be
// rounded up to 1s rather than truncated to 0 — otherwise an operator
// who sets PG_CONN_TIMEOUT=500ms ends up with a libpq connect path
// that never times out. Non-positive values are written as 0
// explicitly (libpq's documented "infinite" semantic); validate() in
// turn rejects ConnTimeout <= 0 so this branch is unreachable from
// Load() but covers manually-constructed configs.
func connectTimeoutSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	s := int(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return s
}

// libpqQuote returns a libpq keyword/value-safe rendering of v.
//
// libpq's parser accepts unquoted values only when they contain no
// whitespace, backslashes, or single-quotes. Anything outside that
// safe set — plus empty strings — must be wrapped in single quotes,
// with backslash and single-quote within escaped by a leading
// backslash. See:
//
//	https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-KEYWORD-VALUE
func libpqQuote(v string) string {
	if v == "" {
		return "''"
	}
	needsQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\\' || c == '\'' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	b.WriteByte('\'')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' || c == '\'' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('\'')
	return b.String()
}

// RateLimit configures the per-IP token-bucket rate limiter that
// wraps the HTTP mux. Defaults are tuned for typical operator-console
// click traffic (30 req/s, burst 60). Operators tighten via
// RATE_LIMIT_RATE / RATE_LIMIT_BURST when sitting behind a CDN that
// already coalesces traffic, and disable entirely by setting
// RATE_LIMIT_ENABLED=false (e.g. when a dedicated WAF handles it).
type RateLimit struct {
	Enabled         bool
	Rate            float64
	Burst           int
	CleanupInterval time.Duration
	IdleTTL         time.Duration
	// TrustedProxies is the raw comma-separated list of reverse-proxy
	// CIDR ranges from RATE_LIMIT_TRUSTED_PROXIES. Parsing happens
	// at the wiring layer so a malformed entry fails boot fast
	// rather than silently widening (or narrowing) the trust set.
	//
	// When empty, the limiter buckets on r.RemoteAddr only and
	// ignores X-Forwarded-For / X-Real-IP entirely.
	TrustedProxies string
}

// TenantRateLimit configures the per-TENANT API rate limiter that
// runs after authentication (so the resolved tenant identity is in
// context). It is distinct from the per-IP RateLimit above: that one
// sheds raw network-level floods before any crypto runs, this one
// enforces a fair per-tenant request budget that scales with the
// tenant's billing tier, so one noisy tenant cannot exhaust shared
// control-plane capacity for the other 5K tenants.
//
// The limiter is a per-tenant token bucket whose capacity is the
// tier's per-minute allowance and whose refill rate is that
// allowance spread evenly across the minute. Every response carries
// the standard X-RateLimit-Limit / X-RateLimit-Remaining /
// X-RateLimit-Reset headers; a request that drains the bucket gets a
// 429 with a Retry-After.
type TenantRateLimit struct {
	// Enabled gates the middleware. When false it is a pass-through.
	Enabled bool
	// StandardPerMinute is the request budget (requests/minute) for
	// the standard tier (TenantTierStarter). Default 100.
	StandardPerMinute int
	// PremiumPerMinute is the request budget (requests/minute) for the
	// premium tiers (TenantTierProfessional, TenantTierEnterprise).
	// Default 500.
	PremiumPerMinute int
	// TierTTL is how long a tenant's resolved tier is cached on its
	// bucket before being re-resolved, so a tier upgrade/downgrade
	// takes effect without a per-request tenant lookup. Default 1m.
	TierTTL time.Duration
	// CleanupInterval is the period of the idle-bucket eviction loop.
	// Default 1m.
	CleanupInterval time.Duration
	// IdleTTL is how long an idle tenant bucket is retained before
	// eviction, bounding the map under a churn of one-shot tenants.
	// Default 10m.
	IdleTTL time.Duration
}

// BruteForce configures the IP-keyed brute-force protection applied
// to credential-validation failures (the auth middleware) and to
// failed device enrolments (the public enrolment endpoint). After a
// threshold of failures from one source IP, that IP is put into a
// fixed cooldown during which further attempts are rejected with 429
// + Retry-After. A successful attempt clears the IP's counter.
type BruteForce struct {
	// Enabled gates both guards. When false they are pass-throughs.
	Enabled bool
	// AuthMaxFailures is the number of credential-validation failures
	// from one IP that trips the auth cooldown. Default 5.
	AuthMaxFailures int
	// AuthCooldown is how long an IP is locked out after tripping the
	// auth threshold. Default 30s.
	AuthCooldown time.Duration
	// EnrollMaxFailures is the number of failed device enrolments from
	// one IP that trips the enrolment cooldown. Default 10.
	EnrollMaxFailures int
	// EnrollCooldown is how long an IP is locked out after tripping the
	// enrolment threshold. Default 5m.
	EnrollCooldown time.Duration
	// CleanupInterval is the period of the idle-entry eviction loop.
	// Default 1m.
	CleanupInterval time.Duration
	// IdleTTL is how long an idle IP entry is retained before eviction.
	// Default 10m.
	IdleTTL time.Duration
	// TrustedProxies mirrors RateLimit.TrustedProxies: the
	// comma-separated reverse-proxy CIDR list used to derive the real
	// client IP from X-Forwarded-For. When empty, r.RemoteAddr is used
	// verbatim. Defaults to the same value as RATE_LIMIT_TRUSTED_PROXIES.
	TrustedProxies string
}

// CORS configures the cross-origin policy applied to every HTTP route.
//
// AllowedOrigins is read from the CORS_ALLOWED_ORIGINS environment
// variable as a comma-separated list. A single "*" entry means
// "echo any origin"; other entries must match the request's Origin
// header exactly (case-insensitive). Defaults to empty.
type CORS struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         time.Duration
}

// Webhook holds outbound webhook delivery configuration. These
// values feed directly into the webhook.WorkerConfig at
// buildRouter time, so the operator's environment-variable knobs
// reach the live worker rather than the worker silently running on
// its compiled-in defaults (the PR6 review observed the previous
// wiring passed a zero-valued WorkerConfig).
type Webhook struct {
	// MaxAttempts is the TOTAL number of delivery attempts (first
	// try + retries) before a webhook is marked exhausted. Default
	// 6 — i.e. 1 initial delivery + 5 retries. Operators wanting a
	// single attempt with no retries set this to 1. Named
	// `MaxAttempts` (env `WEBHOOK_MAX_ATTEMPTS`) to match the
	// worker.WorkerConfig.MaxAttempts semantic exactly; the older
	// `MaxRetries` name conflated "attempts" with "retries after
	// the first" and made off-by-one delivery counts likely. The
	// validator below requires >= 1 so the publisher's fallback
	// chain (which uses <= 0 as the "unset, fall through" sentinel)
	// cannot silently override an operator's explicit value.
	MaxAttempts int
	// InitialDelay is the first retry delay; subsequent delays are
	// exponentially backed off up to MaxDelay. Default 1s.
	InitialDelay time.Duration
	// MaxDelay is the per-attempt backoff ceiling. Default 5m.
	MaxDelay time.Duration
	// DeliveryTimeout is the per-attempt HTTP client timeout.
	// Default 10s.
	DeliveryTimeout time.Duration
	// BatchSize caps the number of pending deliveries the worker
	// fetches per scheduling tick. A larger value increases
	// throughput on a backlog; a smaller value reduces per-tick
	// latency for new deliveries when the queue is shallow.
	// Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending queue
	// when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
	// ProcessingTimeout is the stuck-row recovery window. A
	// worker that crashes mid-delivery leaves its claimed rows in
	// `status='processing'`; the next ListPending re-claims them
	// once their last_attempt_at is older than
	// `now - ProcessingTimeout`. Choose to be safely longer than
	// the worst-case in-flight delivery (DeliveryTimeout +
	// scheduler overhead): too short and a single slow upstream
	// causes the same delivery to be dispatched twice, too long
	// and a true crash stalls the queue for that duration.
	// Default 5m.
	ProcessingTimeout time.Duration
	// SignatureHeader is the HTTP header carrying the HMAC-SHA256
	// signature. Defaults to "X-SNG-Signature".
	SignatureHeader string
}

// Integration carries the operator-facing knobs for the
// integration delivery worker. Round-4 of Devin Review on PR #41
// (PR D) flagged that the worker was constructed with
// `integration.WorkerConfig{}` at cmd/sng-control/main.go:496 —
// the same `WorkerConfig{}` anti-pattern that the webhook worker
// originally shipped with. The previous wiring meant every field
// silently fell back to the hard-coded defaults in
// internal/service/integration/worker.go:46-65 (BatchSize=32,
// PollInterval=1s, MaxAttempts=8, BackoffBase=30s, BackoffMax=1h,
// ProcessingTimeout=5m) — operators exporting their tuning knobs
// would see the validator accept them at boot but the values
// would never reach the live worker. This struct mirrors the
// Webhook layout so the two delivery workers are uniformly
// tunable.
type Integration struct {
	// MaxAttempts is the TOTAL number of delivery attempts (first
	// try + retries) before a delivery is marked exhausted.
	// Default 8. Operators wanting a single attempt with no
	// retries set this to 1.
	MaxAttempts int
	// BackoffBase is the base factor for exponential backoff:
	// `next_retry = now + BackoffBase * 2^(attempt-1)`, capped at
	// `BackoffMax`. Default 30s.
	BackoffBase time.Duration
	// BackoffMax is the per-attempt backoff ceiling. Default 1h.
	BackoffMax time.Duration
	// ProcessingTimeout is the stuck-row recovery window. A
	// worker that crashes mid-delivery leaves its claimed rows
	// in `status='processing'`; the next ListPending re-claims
	// them once their last_attempt_at is older than
	// `now - ProcessingTimeout`. Choose to be safely longer than
	// the worst-case in-flight delivery so a true crash is
	// reclaimed but a slow upstream is not double-dispatched.
	// Default 5m.
	ProcessingTimeout time.Duration
	// BatchSize caps the number of pending deliveries the worker
	// fetches per scheduling tick. Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending
	// queue when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
}

// Auth carries authentication configuration for the operator-facing
// API.
type Auth struct {
	// JWTSecret is the HMAC key used to sign / verify operator JWTs
	// in development. In production this is replaced by OIDC
	// verification (configured at the gateway level).
	JWTSecret string
	// JWTIssuer is the iss claim accepted on incoming JWTs.
	JWTIssuer string
	// JWTAudience is the aud claim accepted on incoming JWTs.
	JWTAudience string
	// AccessTokenTTL is how long control-plane access tokens last.
	AccessTokenTTL time.Duration
	// ClaimTokenTTL is the default lifetime of a fresh one-time
	// device-enrollment claim token (POST /claim-tokens) when the
	// API caller does not specify ttl_seconds explicitly. This is
	// the operator's window to install the agent on the new device
	// and have it call /devices/enroll before the token expires;
	// shorter is more secure, longer reduces operator friction.
	// Defaults to 24h, must be > 0.
	ClaimTokenTTL time.Duration
	// APIKeyHeader is the HTTP header carrying API keys for
	// machine-to-machine authentication (defaults to
	// "X-SNG-API-Key").
	APIKeyHeader string
	// APIKeyMaxActivePerTenant caps the number of active
	// (non-revoked, non-expired) API keys a single tenant may
	// hold. The service enforces this at Create time. Defaults to
	// apikey.DefaultMaxActiveKeys (64). Set <= 0 to disable the
	// cap entirely (test fixtures only — production must keep a
	// finite cap, see validate()).
	APIKeyMaxActivePerTenant int
}

// IAMCore configures the integration with the upstream uneycom/iam-core
// OAuth2/OIDC identity provider (Session 2A). It mirrors the canonical
// IAM_CORE_* environment contract shared by both ShieldNet products.
//
// The whole integration is optional and off by default: with Issuer
// empty the control plane wires neither the iam-core token-validation
// middleware nor the SCIM/SSO bridges, and existing API-key / mobile /
// HMAC auth is untouched. When Issuer is set, validate() enforces the
// minimum required companions (audience, and — for the Management/SSO
// paths — client credentials).
//
// Free-form URL/string knobs are parsed leniently in Load(); they are
// not load-bearing numerics, so there is no strict-parse table entry.
type IAMCore struct {
	// Issuer is the iam-core base URL (hosts /oauth2/* and
	// /.well-known/*) and the exact `iss` claim expected on every
	// token. Empty disables the entire integration.
	Issuer string
	// JWKSURL is the JWKS endpoint for signature validation. Derived
	// as ${Issuer}/oauth2/jwks when empty.
	JWKSURL string
	// DiscoveryURL is the OIDC discovery document. Derived as
	// ${Issuer}/.well-known/openid-configuration when empty.
	DiscoveryURL string
	// ClientID / ClientSecret identify ShieldNet Gateway as a
	// confidential OAuth2 client (admin SSO code exchange + the
	// client_credentials Management token). ClientSecret is secret.
	ClientID     string
	ClientSecret string
	// Audience is the expected `aud` claim on incoming iam-core access
	// tokens. Required when Issuer is set (a token-validation middleware
	// with no audience check is a privilege-escalation footgun).
	Audience string
	// ManagementBaseURL hosts the /api/v1/management/* endpoints the
	// SCIM bridge calls. Derived as Issuer when empty.
	ManagementBaseURL string
	// ManagementAudience is the audience requested when minting the
	// client_credentials Management token. Empty requests no explicit
	// audience.
	ManagementAudience string
	// RedirectURL is the admin-console OAuth2 callback URL registered
	// with iam-core for the SSO authorization-code flow.
	RedirectURL string
}

// Enabled reports whether the iam-core integration is configured.
func (i IAMCore) Enabled() bool {
	return strings.TrimSpace(i.Issuer) != ""
}

// validate enforces the cross-field invariants of the iam-core
// integration. It is a no-op when the integration is disabled (no
// issuer), so deployments that do not use iam-core are unaffected. env
// is the deployment stage; production stages additionally require a
// TLS (https) issuer.
func (i IAMCore) validate(env Environment) error {
	if !i.Enabled() {
		return nil
	}
	// The issuer is also the JWT `iss` we pin and the base for the
	// authorize/token/jwks URLs, so it must be an absolute https(s)
	// URL — a bare host or a relative value would make every derived
	// endpoint wrong and silently fail closed at runtime.
	if !strings.HasPrefix(i.Issuer, "https://") && !strings.HasPrefix(i.Issuer, "http://") {
		return fmt.Errorf("IAM_CORE_ISSUER must be an absolute http(s) URL, got %q", i.Issuer)
	}
	// In production (uat/prod) the issuer carries OAuth2 client secrets
	// (Basic auth on the token endpoint) and bearer tokens, and its JWKS
	// is the root of trust for every validated identity. A plaintext
	// http:// issuer there exposes those to interception and downgrade,
	// so require TLS. http:// stays allowed in dev/qa/local for loopback
	// test servers (mirrors the PG_SSLMODE production posture).
	if env.IsProduction() && strings.HasPrefix(i.Issuer, "http://") {
		return fmt.Errorf("IAM_CORE_ISSUER must use https:// in production environments, got %q", i.Issuer)
	}
	// A token-validation middleware with no expected audience accepts
	// any iam-core token for any relying party — a privilege-escalation
	// footgun. Require the audience whenever the integration is on.
	if strings.TrimSpace(i.Audience) == "" {
		return errors.New("IAM_CORE_AUDIENCE must be set when IAM_CORE_ISSUER is configured")
	}
	// A client secret without its id (or vice versa) is always a
	// misconfiguration: both halves are needed to authenticate the
	// confidential client for the SSO code exchange and the
	// client_credentials Management token.
	if (i.ClientID == "") != (i.ClientSecret == "") {
		return errors.New("IAM_CORE_CLIENT_ID and IAM_CORE_CLIENT_SECRET must be set together")
	}
	return nil
}

// Policy carries policy-engine configuration. PR8 adds two
// production-only knobs: a path to an out-of-band Ed25519 signing
// key (so prod can boot without DB-backed rotation) and an
// AES-256-GCM master key for at-rest wrapping of any DB-stored
// signing seeds (KMS-on-a-stick for deployments without a real
// KMS in the loop).
type Policy struct {
	// SigningKeyPath optionally points at a PEM / hex / raw
	// 32-byte file containing an Ed25519 private key. When set,
	// the policy service ignores the per-tenant DB-backed key
	// store and signs every bundle with this key — useful for
	// deployments where rotation is managed via configuration
	// management (CD pipeline replaces the file and restarts the
	// process) rather than online operator action. Mutually
	// exclusive with the DB rotation API for the active tenant
	// set.
	SigningKeyPath string
	// KeyWrapMasterB64 is a base64-encoded 32-byte AES-256 master
	// key used by the AESGCMWrapper to encrypt signing-key seeds
	// at rest in the policy_signing_keys.private_key column.
	// Mutually exclusive with KeyWrapMasterFile. Empty in both
	// places means PassthroughWrapper (plain seed on disk, at-rest
	// protection via TDE / disk encryption).
	KeyWrapMasterB64 string
	// KeyWrapMasterFile is a path to either 32 raw bytes or the
	// base64 encoding thereof. Mutually exclusive with B64.
	KeyWrapMasterFile string
}

// Telemetry carries OTel SDK bridge configuration.
type Telemetry struct {
	// OTLPEndpoint is the OTLP/HTTP collector endpoint. When empty
	// the OTel SDK bridge is disabled and the in-process tracer
	// falls back to the no-op exporter.
	OTLPEndpoint string
	// ServiceVersion populates the OTel resource attribute
	// service.version. Typically the release tag or git SHA.
	ServiceVersion string
}

// Metrics carries the Prometheus exposition configuration. The
// scrape endpoint binds to a dedicated internal-only port — kept
// separate from the public API listener (HTTP.Port) so the
// `/metrics` surface (which leaks tenant counts, pool sizes, and
// other operational internals) is never routed to the public
// ingress. Expose it only on the cluster-internal network /
// scrape target, not through the public load balancer.
type Metrics struct {
	// Enabled gates the Prometheus registry + the internal
	// metrics HTTP listener in main(). When false the middleware
	// and background collectors are not installed at all, so the
	// hot path pays nothing. Defaults to true. Parsed strictly
	// (METRICS_ENABLED) because a typo silently flipping
	// observability off in production is a real incident risk.
	Enabled bool
	// Port is the internal listener port for the Prometheus
	// `/metrics` endpoint. Defaults to 9090. Must differ from
	// HTTP.Port (validated below) so the operational surface is
	// not co-located with the public API.
	Port int
	// Namespace is the Prometheus metric namespace prefix applied
	// to every registered metric (e.g. `sng_http_requests_total`).
	// Defaults to "sng". Must be a valid Prometheus metric-name
	// prefix.
	Namespace string
}

// TelemetryAnalytics carries the wiring knobs for the hot-path
// (ClickHouse) and cold-path (S3) telemetry analytics sinks. The
// fields are independent: a deployment can enable ClickHouse
// without S3, S3 without ClickHouse, or both. Leaving every
// field empty disables both sinks — the consumer falls back to
// the no-op writers, which is the correct development default
// (the consumer loop, dedup, DLQ machinery all still run; only
// the long-term sinks are skipped).
type TelemetryAnalytics struct {
	// ClickHouse: comma-separated host:port list (native protocol
	// port 9000, secure native 9440). Empty disables the hot-path
	// sink.
	ClickHouseEndpoints []string
	// ClickHouseDatabase, ClickHouseTable scope the writer to a
	// specific database / table. Defaults: "default" / "sng_telemetry".
	ClickHouseDatabase string
	ClickHouseTable    string
	// ClickHouseUsername / Password authenticate against the
	// ClickHouse cluster. In production both must be supplied;
	// boot fails otherwise (see validate()).
	ClickHouseUsername string
	ClickHousePassword string
	// ClickHouseTLS enables the secure native protocol. The driver
	// uses the system root CA pool; a custom CA can be configured
	// via the SSL_CERT_FILE environment variable.
	ClickHouseTLS bool
	// ClickHouseFlushInterval / BatchSize tune the hot-path
	// buffering. Defaults: 2s, 1024 rows.
	ClickHouseFlushInterval time.Duration
	ClickHouseBatchSize     int
	// ClickHouseMaxBacklogMultiplier bounds how many
	// `ClickHouseBatchSize`-worth of rows the writer is willing
	// to retain in its in-memory shield across transient
	// ClickHouse outages. When the requeue path would push the
	// backlog past `BatchSize * MaxBacklogMultiplier`, the
	// OLDEST rows are shed (FIFO) and credited to BacklogDrops
	// + DroppedRows. Default 4 (≈ 8s of buffering at the 2s
	// default flush interval). Operators with tight memory
	// budgets or large batch sizes may want to lower this;
	// operators with bursty producers and a known-long
	// ClickHouse maintenance window may want to raise it.
	ClickHouseMaxBacklogMultiplier int
	// ClickHouseEnsureSchema controls whether the writer issues a
	// CREATE TABLE IF NOT EXISTS for the destination table on
	// boot. Defaults true; set false when the table is provisioned
	// out-of-band (e.g. dbt / Liquibase / a managed-service
	// provisioning workflow).
	ClickHouseEnsureSchema bool

	// ClickHouseSharding switches the hot-path writer from the
	// default single-cluster mode (where every endpoint in
	// CLICKHOUSE_ENDPOINTS is treated as an interchangeable
	// replica the driver load-balances across) to shard-aware
	// mode (env CLICKHOUSE_SHARDING). In shard-aware mode each
	// endpoint is a distinct ClickHouse shard and rows are routed
	// by a stable hash of tenant_id modulo the shard count, with
	// one independent Writer (its own batch buffer + flush loop)
	// per shard. This lifts the single-node ingest/storage ceiling
	// the platform hits past ~5,000 tenants. Cross-tenant operator
	// analytics fan out across all shards in parallel and merge.
	// Defaults false so existing single-cluster deployments are
	// unaffected; only meaningful when more than one endpoint is
	// configured (with a single endpoint the two modes are
	// identical).
	ClickHouseSharding bool

	// ClickHouseRowLimitEnabled toggles the WS8 per-tenant ClickHouse
	// row-write rate limiter on the telemetry hot path (env
	// CLICKHOUSE_ROW_LIMIT_ENABLED). Defaults true: the limiter bounds
	// the dominant write-amplification cost driver, deferring (never
	// dropping) over-budget rows. Set false to disable it entirely —
	// the operator escape hatch for a deployment that bounds ClickHouse
	// write cost another way and does not want any per-tenant ceiling.
	ClickHouseRowLimitEnabled bool
	// ClickHouseRowLimitPerSec / ClickHouseRowLimitBurst tune the
	// per-tenant token bucket (env CLICKHOUSE_ROW_LIMIT_PER_SEC, rows/s,
	// and CLICKHOUSE_ROW_LIMIT_BURST, rows). A value <= 0 means "use the
	// metering package default" (2000 rows/s, 20000 burst), so the
	// defaults live in exactly one place. Raise these for a tenant base
	// with a legitimately high steady row-write rate; the limiter is
	// per-tenant so one noisy tenant cannot consume another's budget.
	ClickHouseRowLimitPerSec float64
	ClickHouseRowLimitBurst  int

	// ClickHouseRowLimitAdaptive switches the per-tenant ClickHouse
	// row-write limiter from the static budget (above) to the WS12
	// self-calibrating limiter, whose per-tenant cap tracks 2× the
	// tenant's own trailing-median row rate (env
	// CLICKHOUSE_ROW_LIMIT_ADAPTIVE). Defaults false so existing
	// deployments keep the static cap; only consulted when
	// ClickHouseRowLimitEnabled is true. The adaptive limiter is the
	// right default for a large, heterogeneous tenant base (a single
	// static cap is simultaneously too loose for small tenants and too
	// tight for large ones), while the static cap stays available for
	// deployments that want one explicit, audited number.
	ClickHouseRowLimitAdaptive bool

	// ClickHouseAutoTuneEnabled toggles the WS12 batch-size auto-tuner
	// on the ClickHouse hot path (env CLICKHOUSE_AUTOTUNE_ENABLED).
	// Defaults true: the tuner measures each shard's insert rate and
	// adjusts its batch size to hold inserts/sec at the target,
	// avoiding the "too many parts" failure mode the static 1024-row
	// batch hits at 5000 tenants (see docs/scaling.md). Set false to
	// pin the batch size at ClickHouseBatchSize.
	ClickHouseAutoTuneEnabled bool
	// ClickHouseAutoTuneTargetInsertsPerSec is the per-shard inserts/sec
	// the auto-tuner drives toward (env
	// CLICKHOUSE_AUTOTUNE_TARGET_INSERTS_PER_SEC). <= 0 ⇒ use the
	// telemetry package default (~2/sec), so the default lives in one
	// place. The healthy per-shard ceiling is ~1–2 inserts/sec.
	ClickHouseAutoTuneTargetInsertsPerSec float64

	// ClickHouseTierSamplingEnabled toggles the WS-4 activity-tier-aware
	// telemetry sampling policy on the ClickHouse hot path (env
	// CLICKHOUSE_TIER_SAMPLING_ENABLED). DEFAULT-OFF: enabling it makes
	// idle tenants sample more aggressively and dormant tenants write
	// security-events-only, so it is opt-in to avoid silently changing
	// retention on upgrade. Security-relevant events (IPS / ZTNA / DLP)
	// and the inspect_full compliance record are always preserved at
	// 1:1 regardless. Only consulted when an adaptive sampler is wired.
	ClickHouseTierSamplingEnabled bool
	// ClickHouseTierSamplingIdleMultiplier scales the keep probability
	// for idle-tier tenants when tier sampling is enabled (env
	// CLICKHOUSE_TIER_SAMPLING_IDLE_MULTIPLIER). <= 0 ⇒ use the
	// telemetry package default (0.25), so the default lives in one
	// place. Clamped to (0,1]; dormant tenants are always
	// security-events-only and are not tunable here.
	ClickHouseTierSamplingIdleMultiplier float64
	// ClickHouseTierSamplingRefreshInterval bounds how stale a tenant's
	// activity tier may be on the hot path (env
	// CLICKHOUSE_TIER_SAMPLING_REFRESH_INTERVAL). <= 0 ⇒ use the
	// telemetry package default (60s). A waking dormant tenant is
	// re-classified active within one interval, so the security floor
	// plus this bound cap how long a now-active tenant is under-sampled.
	ClickHouseTierSamplingRefreshInterval time.Duration

	// S3: bucket name. Empty disables the cold-path sink.
	S3Bucket string
	// S3Prefix is the top-level key prefix under which archive
	// objects land. Defaults to "telemetry".
	S3Prefix string
	// S3Region is the AWS region. Required when S3Bucket is set
	// (unless S3Endpoint is set, in which case region is best-
	// effort populated by the SDK).
	S3Region string
	// S3Endpoint overrides the AWS endpoint URL. Used for MinIO,
	// R2, GCS-via-S3, and other S3-compatible stores. Empty means
	// "use the canonical AWS endpoint for S3Region".
	S3Endpoint string
	// S3AccessKeyID / S3SecretAccessKey override the SDK's default
	// credentials chain (env / file / IMDS / SSO). When both are
	// blank the writer uses the default chain.
	S3AccessKeyID     string
	S3SecretAccessKey string
	// S3StorageClass selects the S3 storage class for archive
	// objects. Defaults to STANDARD_IA. Set to STANDARD if you
	// plan to read the archive frequently.
	S3StorageClass string
	// S3FlushInterval, MaxBytesPerObject, MaxEventsPerObject:
	// tune the cold-path buffering. Defaults: 30s, 16 MiB, 50k
	// events per object.
	S3FlushInterval      time.Duration
	S3MaxBytesPerObject  int
	S3MaxEventsPerObject int

	// S3ManageLifecycle controls whether the control plane PUTs the
	// cold-archive bucket lifecycle policy (transition to Glacier Deep
	// Archive) at startup. Defaults to true — the low-ops default, so a
	// fresh deployment ages its archive into the cheapest storage class
	// without any manual step. Set to false when the bucket lifecycle is
	// owned out-of-band (Terraform, an org policy, a shared bucket) so
	// two owners don't fight over the configuration.
	S3ManageLifecycle bool
	// S3LifecycleDeepArchiveDays is the object age, in days, at which the
	// managed lifecycle policy transitions archive objects to Glacier
	// Deep Archive. Defaults to 90. Ignored when S3ManageLifecycle is
	// false.
	S3LifecycleDeepArchiveDays int

	// ReplayDurable is the JetStream durable consumer name the
	// replay worker maintains on SNG_DLQ. Defaults to
	// "sng-telemetry-replay". Allowing operators to override this
	// makes blue/green replay possible (two workers on two durable
	// names tracking separate offsets).
	ReplayDurable string
}

// Load reads configuration from the environment.
//
// It loads ".env" if present in the working directory (best-effort)
// and then parses all known variables, returning a populated
// [Config].
//
// Required variables: APP_NAME, ENVIRONMENT. Other variables fall
// back to sensible defaults so that scripts and unit tests can run
// without a full environment.
func Load() (Config, error) {
	_ = loadDotEnv(".env")

	cfg := Config{
		Environment: Environment(strings.ToLower(getStr("ENVIRONMENT", string(EnvironmentLocal)))),
		AppName:     getStr("APP_NAME", "sng-control"),

		Log: Log{
			Level:  getStr("LOG_LEVEL", "info"),
			Format: getStr("LOG_FORMAT", "json"),
		},
		// Non-load-bearing fields parsed leniently (defaults are safe
		// on typo). Load-bearing numeric fields (ports, timeouts,
		// pool sizes, retry budgets, rate-limit knobs) are NOT set
		// here — they're populated by the strictInts / strictDurations /
		// strictFloats tables below so the strict tables are the
		// single source of truth for both the default and the env
		// var name. This eliminates the dual-parse subtlety where
		// a new strict-worthy field could be added to the lenient
		// block and silently fall back to the default on typo.
		HTTP: HTTP{
			Host: getStr("HTTP_HOST", "0.0.0.0"),
		},
		NATS: NATS{
			URL:          getStr("NATS_URL", "nats://127.0.0.1:4222"),
			Name:         getStr("NATS_NAME", "sng-control"),
			User:         getStr("NATS_USER", ""),
			Password:     getStr("NATS_PASSWORD", ""),
			Token:        getStr("NATS_TOKEN", ""),
			CredsFile:    getStr("NATS_CREDS_FILE", ""),
			TLSCAFile:    getStr("NATS_TLS_CA", ""),
			TLSCertFile:  getStr("NATS_TLS_CERT", ""),
			TLSKeyFile:   getStr("NATS_TLS_KEY", ""),
			Storage:      getStr("NATS_STORAGE", "file"),
			StreamPrefix: getStr("NATS_STREAM_PREFIX", "SNG"),
			// TLSInsecure is populated by the strictBools table below so
			// that a typo (NATS_TLS_INSECURE=yes) fails boot rather than
			// silently keeping the secure default — same single-source-of-
			// truth rule that governs strict ints / durations / floats.
		},
		Postgres: Postgres{
			Host:     getStr("PG_HOST", "127.0.0.1"),
			User:     getStr("PG_USER", "sng"),
			Password: getStr("PG_PASSWORD", "sng"),
			Database: getStr("PG_DATABASE", "sng"),
			SSLMode:  getStr("PG_SSLMODE", "disable"),
			// PG_APP_ROLE uses getStrAllowEmpty (not getStr) because
			// an explicitly empty value is the documented escape
			// hatch for dev environments where a single PG_USER is
			// granted DML directly without role-separation. Treating
			// `PG_APP_ROLE=` and `PG_APP_ROLE` (unset) identically —
			// as plain getStr would — would silently bury that
			// escape hatch and force every dev to either provision
			// `sng_app` or live with confusing SET SESSION ROLE
			// errors. validate() enforces non-empty in production.
			AppRole:          getStrAllowEmpty("PG_APP_ROLE", "sng_app"),
			ReadReplicaHosts: splitCSV(getStr("PG_READ_REPLICA_HOSTS", "")),
			// ReadReplicaPort + PgBouncerMode are populated by the
			// strict tables below so a typo fails boot rather than
			// silently reverting to the default.
		},
		RateLimit: RateLimit{
			CleanupInterval: getDuration("RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("RATE_LIMIT_IDLE_TTL", 10*time.Minute),
			TrustedProxies:  getStr("RATE_LIMIT_TRUSTED_PROXIES", ""),
			// Enabled is populated by the strictBools table below.
		},
		TenantRateLimit: TenantRateLimit{
			TierTTL:         getDuration("TENANT_RATE_LIMIT_TIER_TTL", time.Minute),
			CleanupInterval: getDuration("TENANT_RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("TENANT_RATE_LIMIT_IDLE_TTL", 10*time.Minute),
			// Enabled / StandardPerMinute / PremiumPerMinute are
			// populated by the strict tables below so a typo fails
			// boot rather than silently weakening the limit.
		},
		BruteForce: BruteForce{
			CleanupInterval: getDuration("BRUTEFORCE_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("BRUTEFORCE_IDLE_TTL", 10*time.Minute),
			// TrustedProxies defaults to the per-IP limiter's list so
			// both derive the client IP identically without a second
			// env var, but can be overridden independently.
			TrustedProxies: getStr("BRUTEFORCE_TRUSTED_PROXIES", getStr("RATE_LIMIT_TRUSTED_PROXIES", "")),
			// Enabled / *MaxFailures / *Cooldown are populated by the
			// strict tables below.
		},
		CORS: CORS{
			AllowedOrigins: parseCSV(getStr("CORS_ALLOWED_ORIGINS", "")),
			AllowedMethods: parseCSV(getStr("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")),
			AllowedHeaders: parseCSV(getStr("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Request-ID,X-SNG-API-Key")),
			MaxAge:         getDuration("CORS_MAX_AGE", time.Hour),
		},
		Webhook: Webhook{
			SignatureHeader: getStr("WEBHOOK_SIGNATURE_HEADER", "X-SNG-Signature"),
		},
		Auth: Auth{
			JWTSecret:    getStr("AUTH_JWT_SECRET", ""),
			JWTIssuer:    getStr("AUTH_JWT_ISSUER", "sng-control"),
			JWTAudience:  getStr("AUTH_JWT_AUDIENCE", "sng-control"),
			APIKeyHeader: getStr("AUTH_API_KEY_HEADER", "X-SNG-API-Key"),
		},
		IAMCore: IAMCore{
			Issuer:             strings.TrimRight(getStr("IAM_CORE_ISSUER", ""), "/"),
			JWKSURL:            getStr("IAM_CORE_JWKS_URL", ""),
			DiscoveryURL:       getStr("IAM_CORE_OIDC_DISCOVERY", ""),
			ClientID:           getStr("IAM_CORE_CLIENT_ID", ""),
			ClientSecret:       getStr("IAM_CORE_CLIENT_SECRET", ""),
			Audience:           getStr("IAM_CORE_AUDIENCE", ""),
			ManagementBaseURL:  strings.TrimRight(getStr("IAM_CORE_MGMT_BASE_URL", ""), "/"),
			ManagementAudience: getStr("IAM_CORE_MGMT_AUDIENCE", ""),
			RedirectURL:        getStr("IAM_CORE_REDIRECT_URL", ""),
		},
		Policy: Policy{
			SigningKeyPath:    getStr("POLICY_SIGNING_KEY_PATH", ""),
			KeyWrapMasterB64:  getStr("POLICY_KEY_WRAP_MASTER_B64", ""),
			KeyWrapMasterFile: getStr("POLICY_KEY_WRAP_MASTER_FILE", ""),
		},
		PoP: PoP{
			// Free-form string knobs are parsed leniently; the
			// load-bearing numeric / duration / bool knobs are
			// populated by the strict tables below. The routing
			// policy and hostname are validated downstream by
			// pop.NewZoneGenerator, which fails fast on a bad value.
			GeoDNSHostname:      getStr("POP_GEODNS_HOSTNAME", "edge.sng.example.com"),
			GeoDNSRoutingPolicy: getStr("POP_GEODNS_ROUTING_POLICY", "latency"),
		},
		Sandbox: Sandbox{
			Provider:          strings.ToLower(getStr("SANDBOX_PROVIDER", "")),
			CacheTTL:          getDuration("SANDBOX_CACHE_TTL", time.Hour),
			CuckooBaseURL:     getStr("SANDBOX_CUCKOO_BASE_URL", ""),
			CuckooAPIToken:    getStr("SANDBOX_CUCKOO_API_TOKEN", ""),
			CAPEBaseURL:       getStr("SANDBOX_CAPE_BASE_URL", ""),
			CAPEAPIToken:      getStr("SANDBOX_CAPE_API_TOKEN", ""),
			GenericSubmitURL:  getStr("SANDBOX_GENERIC_SUBMIT_URL", ""),
			GenericStatusURL:  getStr("SANDBOX_GENERIC_STATUS_URL", ""),
			GenericAuthHeader: getStr("SANDBOX_GENERIC_AUTH_HEADER", ""),
			GenericAuthValue:  getStr("SANDBOX_GENERIC_AUTH_VALUE", ""),

			VirusTotalAPIKey:       getStr("SANDBOX_VIRUSTOTAL_API_KEY", ""),
			VirusTotalCacheTTL:     getDuration("SANDBOX_VIRUSTOTAL_CACHE_TTL", 0),
			HybridAnalysisAPIKey:   getStr("SANDBOX_HYBRID_ANALYSIS_API_KEY", ""),
			HybridAnalysisCacheTTL: getDuration("SANDBOX_HYBRID_ANALYSIS_CACHE_TTL", 0),
		},
		RBI: RBI{
			ProxyBaseURL:         getStr("RBI_PROXY_BASE_URL", ""),
			SessionTTL:           getDuration("RBI_SESSION_TTL", 15*time.Minute),
			TriggerCategories:    splitCSV(getStr("RBI_TRIGGER_CATEGORIES", "")),
			RiskScoreThreshold:   getIntLenient("RBI_RISK_SCORE_THRESHOLD", 0),
			IsolateUncategorised: getBoolLenient("RBI_ISOLATE_UNCATEGORISED", false),
			ExplicitIsolate:      splitCSV(getStr("RBI_EXPLICIT_ISOLATE", "")),
			ExplicitBypass:       splitCSV(getStr("RBI_EXPLICIT_BYPASS", "")),
			ArtifactRegion:       getStr("RBI_ARTIFACT_REGION", ""),

			ArtifactClipboardInbound:  getBoolLenient("RBI_ARTIFACT_CLIPBOARD_INBOUND", false),
			ArtifactClipboardOutbound: getBoolLenient("RBI_ARTIFACT_CLIPBOARD_OUTBOUND", false),
			ArtifactFileDownload:      getBoolLenient("RBI_ARTIFACT_FILE_DOWNLOAD", false),
			ArtifactFileUpload:        getBoolLenient("RBI_ARTIFACT_FILE_UPLOAD", false),
		},
		RolloutAutopilot: RolloutAutopilot{
			// Enabled, Interval, AutoEnrol, DwellWindow, MinSamples,
			// MaxErrorRate and MaxDenyRate are populated by the strict
			// tables below (single source of truth for default + env var
			// name). Only the CSV capability allow-list is parsed
			// leniently here — an empty/typo'd list safely means "all
			// governed capabilities", never a security regression.
			Capabilities: splitCSV(getStr("ROLLOUT_AUTOPILOT_CAPABILITIES", "")),
		},
		Telemetry: Telemetry{
			OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceVersion: getStr("SERVICE_VERSION", ""),
		},
		Metrics: Metrics{
			Namespace: getStr("METRICS_NAMESPACE", "sng"),
			// Enabled (METRICS_ENABLED) and Port (METRICS_PORT) are
			// populated by the strict tables below — same
			// single-source-of-truth rule as the other load-bearing
			// numeric / boolean knobs.
		},
		TelemetryAnalytics: TelemetryAnalytics{
			ClickHouseEndpoints: splitCSV(getStr("CLICKHOUSE_ENDPOINTS", "")),
			ClickHouseDatabase:  getStr("CLICKHOUSE_DATABASE", ""),
			ClickHouseTable:     getStr("CLICKHOUSE_TABLE", ""),
			ClickHouseUsername:  getStr("CLICKHOUSE_USERNAME", ""),
			ClickHousePassword:  getStr("CLICKHOUSE_PASSWORD", ""),
			S3Bucket:            getStr("S3_TELEMETRY_BUCKET", ""),
			S3Prefix:            getStr("S3_TELEMETRY_PREFIX", ""),
			S3Region:            getStr("S3_TELEMETRY_REGION", ""),
			S3Endpoint:          getStr("S3_TELEMETRY_ENDPOINT", ""),
			S3AccessKeyID:       getStr("S3_TELEMETRY_ACCESS_KEY_ID", ""),
			S3SecretAccessKey:   getStr("S3_TELEMETRY_SECRET_ACCESS_KEY", ""),
			S3StorageClass:      getStr("S3_TELEMETRY_STORAGE_CLASS", ""),
			ReplayDurable:       getStr("TELEMETRY_REPLAY_DURABLE", ""),
		},
		AI: AI{
			Endpoint:    getStr("AI_LLM_ENDPOINT", ""),
			APIKey:      getStr("AI_LLM_API_KEY", ""),
			Model:       getStr("AI_LLM_MODEL", ""),
			ModelFamily: getStr("AI_LLM_MODEL_FAMILY", "auto"),
		},
		ThreatIntel: ThreatIntel{
			RefreshInterval:      getDuration("THREATINTEL_REFRESH_INTERVAL", time.Hour),
			DefaultTTL:           getDuration("THREATINTEL_DEFAULT_TTL", 0),
			MinConfidence:        getFloatLenient("THREATINTEL_MIN_CONFIDENCE", 0),
			TAXIIURL:             getStr("THREATINTEL_TAXII_URL", ""),
			TAXIIToken:           getStr("THREATINTEL_TAXII_TOKEN", ""),
			OTXURL:               getStr("THREATINTEL_OTX_URL", ""),
			OTXAPIKey:            getStr("THREATINTEL_OTX_API_KEY", ""),
			URLhausURL:           getStr("THREATINTEL_URLHAUS_URL", ""),
			MalwareBazaarURL:     getStr("THREATINTEL_MALWAREBAZAAR_URL", ""),
			FeodoTrackerURL:      getStr("THREATINTEL_FEODOTRACKER_URL", ""),
			CSVURL:               getStr("THREATINTEL_CSV_URL", ""),
			JSONURL:              getStr("THREATINTEL_JSON_URL", ""),
			MISPURL:              getStr("THREATINTEL_MISP_URL", ""),
			MISPAuthKey:          getStr("THREATINTEL_MISP_AUTH_KEY", ""),
			MISPIncludeNonIDs:    getBoolLenient("THREATINTEL_MISP_INCLUDE_NON_IDS", false),
			Persistence:          getBoolLenient("THREATINTEL_PERSISTENCE", true),
			PersistInterval:      getDuration("THREATINTEL_PERSIST_INTERVAL", 5*time.Minute),
			AutoRecompile:        getBoolLenient("THREATINTEL_AUTO_RECOMPILE", true),
			RecompileMinInterval: getDuration("THREATINTEL_RECOMPILE_MIN_INTERVAL", 5*time.Minute),
			StaleFactor:          getFloatLenient("THREATINTEL_STALE_FACTOR", 3),
			HealthInterval:       getDuration("THREATINTEL_HEALTH_INTERVAL", time.Minute),
		},
		ManagedDNSFeeds: ManagedDNSFeeds{
			// Enabled is parsed strictly below (default-OFF feature flag).
			RefreshInterval: getDuration("THREAT_INTEL_REFRESH_INTERVAL", time.Hour),
			SigningKeyHex:   getStr("THREAT_INTEL_SIGNING_KEY_HEX", ""),
			KeyID:           getStr("THREAT_INTEL_KEY_ID", ""),
			Subject:         getStr("THREAT_INTEL_SUBJECT", ""),
			ReputationURLs:  splitCSV(getStr("THREAT_INTEL_REPUTATION_URLS", "")),
			CategoryFeeds:   parseKeyedURLs(getStr("THREAT_INTEL_CATEGORY_FEEDS", "")),
			HTTPTimeout:     getDuration("THREAT_INTEL_HTTP_TIMEOUT", 30*time.Second),
			MaxFeedBytes:    int64(getIntLenient("THREAT_INTEL_MAX_FEED_BYTES", 0)),
		},
	}

	// Critical numeric settings: re-parse with the strict helpers
	// so a typo (e.g. HTTP_PORT="80a", HTTP_READ_TIMEOUT="5second")
	// fails boot loudly instead of silently reverting to the default
	// and giving us a wildly wrong setting in production.
	//
	// Strict parsing is reserved for fields where silently using the
	// default could mask a security or correctness regression
	// (timeouts, ports, retry budgets, pool sizes, rate limits,
	// dedup windows). Lenient parsing is intentionally retained for
	// purely cosmetic / non-load-bearing fields where defaults are
	// always safe.
	strictInts := []struct {
		key string
		def int
		dst *int
	}{
		{"HTTP_PORT", 8080, &cfg.HTTP.Port},
		{"PG_PORT", 5432, &cfg.Postgres.Port},
		{"PG_MAX_OPEN_CONNS", 20, &cfg.Postgres.MaxOpenConns},
		{"PG_MIN_CONNS", 2, &cfg.Postgres.MinConns},
		// 0 = inherit primary PG_PORT (see Postgres.ReplicaPort).
		{"PG_READ_REPLICA_PORT", 0, &cfg.Postgres.ReadReplicaPort},
		{"NATS_MAX_RECONNECTS", -1, &cfg.NATS.MaxReconnects},
		{"NATS_REPLICAS", 1, &cfg.NATS.Replicas},
		{"NATS_PARTITIONS", 1, &cfg.NATS.Partitions},
		{"NATS_FETCH_BATCH_SIZE", 50, &cfg.NATS.FetchBatchSize},
		{"NATS_PUBLISH_RETRY_ATTEMPTS", 3, &cfg.NATS.PublishRetryAttempts},
		{"RATE_LIMIT_BURST", 60, &cfg.RateLimit.Burst},
		// Activity-recorder drain-queue depth. Sized for a burst of
		// distinct tenants crossing their debounce window at once.
		{"ACTIVITY_TRACKING_QUEUE_SIZE", 4096, &cfg.Activity.QueueSize},
		// Per-tenant API rate-limit budgets (requests/minute). Parsed
		// strictly because a typo silently reverting to the default
		// would weaken a load-bearing fairness/availability control.
		{"TENANT_RATE_LIMIT_STANDARD_PER_MIN", 100, &cfg.TenantRateLimit.StandardPerMinute},
		{"TENANT_RATE_LIMIT_PREMIUM_PER_MIN", 500, &cfg.TenantRateLimit.PremiumPerMinute},
		// Brute-force thresholds. Parsed strictly so a typo cannot
		// silently disable (revert) the lockout protections.
		{"BRUTEFORCE_AUTH_MAX_FAILURES", 5, &cfg.BruteForce.AuthMaxFailures},
		{"BRUTEFORCE_ENROLL_MAX_FAILURES", 10, &cfg.BruteForce.EnrollMaxFailures},
		{"WEBHOOK_MAX_ATTEMPTS", 6, &cfg.Webhook.MaxAttempts},
		{"WEBHOOK_BATCH_SIZE", 32, &cfg.Webhook.BatchSize},
		// Round-4 of Devin Review on PR #41 (PR D): wire the
		// integration delivery worker's tuning knobs through the
		// strict int parser so a typo (e.g.
		// `INTEGRATION_WORKER_BATCH_SIZE="32a"`) fails boot
		// loudly instead of silently reverting to the hard-coded
		// default. Defaults match
		// internal/service/integration/worker.go:46-65.
		{"INTEGRATION_WORKER_MAX_ATTEMPTS", 8, &cfg.Integration.MaxAttempts},
		{"INTEGRATION_WORKER_BATCH_SIZE", 32, &cfg.Integration.BatchSize},
		// Kept in sync with apikey.DefaultMaxActiveKeys; literal
		// here so the config package doesn't take a dependency on
		// internal/service/apikey.
		{"AUTH_API_KEY_MAX_ACTIVE_PER_TENANT", 64, &cfg.Auth.APIKeyMaxActivePerTenant},
		// AI guardrail tuning knobs. Defaults match
		// internal/service/ai.GuardrailConfig.normalize() (60 rpm,
		// 100000 tokens/day) so operators can tune per-tenant cost
		// controls without recompiling. Parsed strictly because a
		// typo silently reverting to the default would weaken a rate
		// limit / cost control.
		{"AI_GUARDRAIL_MAX_REQUESTS_PER_MINUTE", 60, &cfg.AI.GuardrailMaxRequestsPerMinute},
		{"AI_GUARDRAIL_MAX_TOKENS_PER_DAY", 100000, &cfg.AI.GuardrailMaxTokensPerDay},
		// WS-9 shared inference pool sizing. Parsed strictly because a
		// typo silently reverting the concurrency cap could either
		// over-subscribe the shared model (latency collapse) or
		// needlessly throttle the fleet. Defaults match
		// internal/service/ai.InferencePoolConfig.normalize().
		{"AI_INFERENCE_POOL_MAX_CONCURRENT", 4, &cfg.AI.InferencePoolMaxConcurrent},
		{"AI_INFERENCE_POOL_MAX_QUEUE_PER_TENANT", 8, &cfg.AI.InferencePoolMaxQueuePerTenant},
		{"CLICKHOUSE_BATCH_SIZE", 1024, &cfg.TelemetryAnalytics.ClickHouseBatchSize},
		{"CLICKHOUSE_MAX_BACKLOG_MULTIPLIER", 4, &cfg.TelemetryAnalytics.ClickHouseMaxBacklogMultiplier},
		// WS8 ClickHouse row-write limiter burst, in rows. 0 ⇒ use the
		// metering package default (20000). Parsed strictly so a typo
		// can't silently revert a tightened cost ceiling.
		{"CLICKHOUSE_ROW_LIMIT_BURST", 0, &cfg.TelemetryAnalytics.ClickHouseRowLimitBurst},
		{"S3_TELEMETRY_MAX_BYTES_PER_OBJECT", 16 * 1024 * 1024, &cfg.TelemetryAnalytics.S3MaxBytesPerObject},
		{"S3_TELEMETRY_MAX_EVENTS_PER_OBJECT", 50_000, &cfg.TelemetryAnalytics.S3MaxEventsPerObject},
		// Days before archived objects transition to Glacier Deep
		// Archive. Parsed strictly so a typo can't silently revert the
		// transition age and inflate the storage bill.
		{"S3_TELEMETRY_LIFECYCLE_DEEP_ARCHIVE_DAYS", 90, &cfg.TelemetryAnalytics.S3LifecycleDeepArchiveDays},
		// Per-tenant cap on registered OIDC IdP configs. Parsed
		// strictly so a typo can't silently revert the limit.
		{"MOBILE_AUTH_MAX_PROVIDERS_PER_TENANT", 10, &cfg.MobileAuth.MaxProvidersPerTenant},
		// WS-5 NoOps auto-promoter promotion evidence floor. Parsed
		// strictly so a typo can't silently lower the minimum number of
		// monitor observations required before a capability may promote.
		{"ROLLOUT_AUTOPILOT_MIN_SAMPLES", 200, &cfg.RolloutAutopilot.MinSamples},
		// Internal Prometheus scrape port. Parsed strictly so a
		// typo can't silently relocate the operational surface
		// onto an unexpected port.
		{"METRICS_PORT", 9090, &cfg.Metrics.Port},
	}
	strictDurations := []struct {
		key string
		def time.Duration
		dst *time.Duration
	}{
		{"HTTP_READ_TIMEOUT", 15 * time.Second, &cfg.HTTP.ReadTimeout},
		{"HTTP_READ_HEADER_TIMEOUT", 5 * time.Second, &cfg.HTTP.ReadHeaderTimeout},
		{"HTTP_WRITE_TIMEOUT", 30 * time.Second, &cfg.HTTP.WriteTimeout},
		{"HTTP_SHUTDOWN_TIMEOUT", 10 * time.Second, &cfg.HTTP.ShutdownTimeout},
		{"PG_CONN_TIMEOUT", 5 * time.Second, &cfg.Postgres.ConnTimeout},
		{"PG_CONN_MAX_LIFETIME", time.Hour, &cfg.Postgres.ConnMaxLifetime},
		{"NATS_CONNECT_TIMEOUT", 5 * time.Second, &cfg.NATS.ConnectTimeout},
		{"NATS_REQUEST_TIMEOUT", 5 * time.Second, &cfg.NATS.RequestTimeout},
		{"NATS_RECONNECT_WAIT", 2 * time.Second, &cfg.NATS.ReconnectWait},
		{"NATS_DEDUP_WINDOW", 2 * time.Minute, &cfg.NATS.DedupWindow},
		{"NATS_PUBLISH_RETRY_DELAY", 200 * time.Millisecond, &cfg.NATS.PublishRetryDelay},
		{"NATS_FETCH_MAX_WAIT", 200 * time.Millisecond, &cfg.NATS.FetchMaxWait},
		{"WEBHOOK_INITIAL_DELAY", time.Second, &cfg.Webhook.InitialDelay},
		{"WEBHOOK_MAX_DELAY", 5 * time.Minute, &cfg.Webhook.MaxDelay},
		{"WEBHOOK_DELIVERY_TIMEOUT", 10 * time.Second, &cfg.Webhook.DeliveryTimeout},
		{"WEBHOOK_POLL_INTERVAL", time.Second, &cfg.Webhook.PollInterval},
		{"WEBHOOK_PROCESSING_TIMEOUT", 5 * time.Minute, &cfg.Webhook.ProcessingTimeout},
		// Integration delivery worker duration knobs.
		{"INTEGRATION_WORKER_BACKOFF_BASE", 30 * time.Second, &cfg.Integration.BackoffBase},
		{"INTEGRATION_WORKER_BACKOFF_MAX", time.Hour, &cfg.Integration.BackoffMax},
		{"INTEGRATION_WORKER_POLL_INTERVAL", time.Second, &cfg.Integration.PollInterval},
		{"INTEGRATION_WORKER_PROCESSING_TIMEOUT", 5 * time.Minute, &cfg.Integration.ProcessingTimeout},
		{"AUTH_ACCESS_TOKEN_TTL", time.Hour, &cfg.Auth.AccessTokenTTL},
		{"AUTH_CLAIM_TOKEN_TTL", 24 * time.Hour, &cfg.Auth.ClaimTokenTTL},
		// Brute-force cooldown windows. Parsed strictly so a typo
		// cannot silently shorten (or zero) the lockout.
		{"BRUTEFORCE_AUTH_COOLDOWN", 30 * time.Second, &cfg.BruteForce.AuthCooldown},
		{"BRUTEFORCE_ENROLL_COOLDOWN", 5 * time.Minute, &cfg.BruteForce.EnrollCooldown},
		{"CLICKHOUSE_FLUSH_INTERVAL", 2 * time.Second, &cfg.TelemetryAnalytics.ClickHouseFlushInterval},
		// WS-4 tier-sampling activity-tier refresh cadence. 0 ⇒ use the
		// telemetry package default (60s). Bounds how stale a tenant's
		// tier may be on the hot path.
		{"CLICKHOUSE_TIER_SAMPLING_REFRESH_INTERVAL", 0, &cfg.TelemetryAnalytics.ClickHouseTierSamplingRefreshInterval},
		{"S3_TELEMETRY_FLUSH_INTERVAL", 30 * time.Second, &cfg.TelemetryAnalytics.S3FlushInterval},
		{"APP_REGISTRY_SYNC_INTERVAL", 24 * time.Hour, &cfg.AppRegistry.SyncInterval},
		{"CASB_NOOPS_RECONCILE_INTERVAL", time.Hour, &cfg.CASB.NoOpsReconcileInterval},
		// Dormant-tenant hibernation cadences (only consulted when
		// HIBERNATION_ENABLED). SweepInterval drives the leader-only
		// reconcile; RegistrySyncInterval bounds how fast a decision
		// propagates to follower replicas' telemetry hooks.
		{"HIBERNATION_SWEEP_INTERVAL", time.Hour, &cfg.Hibernation.SweepInterval},
		{"HIBERNATION_REGISTRY_SYNC_INTERVAL", 30 * time.Second, &cfg.Hibernation.RegistrySyncInterval},
		// Per-tenant activity debounce window. Must stay well under the
		// dormancy planner's 24h IdleAfter so steady traffic keeps a
		// tenant in the active tier between writes.
		{"ACTIVITY_TRACKING_MIN_INTERVAL", 5 * time.Minute, &cfg.Activity.MinInterval},
		// 15s default: local quantized (Ternary-Bonsai-8B) inference is
		// slower than a hosted API call. Matches ai.defaultTimeout.
		{"AI_LLM_TIMEOUT", 15 * time.Second, &cfg.AI.Timeout},
		// WS-9 shared inference pool max queue wait. 0 ⇒ bounded only by
		// the request context. Defaults to 15s, aligned with
		// AI_LLM_TIMEOUT, so a queued request never waits materially
		// longer than a single inference would take before degrading to
		// the deterministic template path.
		{"AI_INFERENCE_POOL_MAX_WAIT", 15 * time.Second, &cfg.AI.InferencePoolMaxWait},
		// Mobile IdP-federation session + discovery-cache lifetimes.
		{"MOBILE_AUTH_SESSION_TOKEN_TTL", time.Hour, &cfg.MobileAuth.SessionTokenTTL},
		{"MOBILE_AUTH_DISCOVERY_CACHE_TTL", 24 * time.Hour, &cfg.MobileAuth.DiscoveryCacheTTL},
		// IdP directory-sync loop cadence (only consulted when
		// IDP_DIRECTORY_SYNC_ENABLED). Defaults to 1h.
		{"IDP_DIRECTORY_SYNC_INTERVAL", time.Hour, &cfg.MobileAuth.DirectorySyncInterval},
		// Cost-metering flush cadence. Defaults to 60s (matching the
		// Session K spec and metering.DefaultFlushInterval). Parsed
		// strictly so a typo can't silently skew cost accounting.
		{"METERING_FLUSH_INTERVAL", 60 * time.Second, &cfg.Metering.FlushInterval},
		// Cloud PoP service duration knobs. Parsed strictly so an
		// operator typo fails boot rather than silently reverting to
		// the default (a stale-beacon TTL or refresh cadence quietly
		// reverting could mis-route tenant traffic).
		{"POP_REGISTRY_REFRESH_INTERVAL", 30 * time.Second, &cfg.PoP.RegistryRefreshInterval},
		{"POP_HEALTH_TTL", 90 * time.Second, &cfg.PoP.HealthTTL},
		{"POP_GEODNS_TTL", 30 * time.Second, &cfg.PoP.GeoDNSTTL},
		{"POP_GEODNS_PUBLISH_INTERVAL", 30 * time.Second, &cfg.PoP.GeoDNSPublishInterval},
		{"POP_REBALANCE_INTERVAL", 60 * time.Second, &cfg.PoP.RebalanceInterval},
		{"WS11_MIGRATION_RESUME_INTERVAL", 5 * time.Minute, &cfg.TenantMigration.ResumeInterval},
		// WS-5 NoOps auto-promoter. Sweep cadence and monitor dwell
		// window. Parsed strictly so a typo can't silently revert the
		// dwell window and let a capability promote sooner than intended.
		{"ROLLOUT_AUTOPILOT_INTERVAL", time.Hour, &cfg.RolloutAutopilot.Interval},
		{"ROLLOUT_AUTOPILOT_DWELL_WINDOW", 24 * time.Hour, &cfg.RolloutAutopilot.DwellWindow},
		// Alert false-positive feedback tuning sweep cadence (only
		// consulted when ALERT_FEEDBACK_TUNING_ENABLED). Defaults to 30m.
		{"ALERT_FEEDBACK_TUNING_INTERVAL", 30 * time.Minute, &cfg.AlertFeedback.TuningInterval},
	}
	strictFloats := []struct {
		key string
		def float64
		dst *float64
	}{
		{"RATE_LIMIT_RATE", 30.0, &cfg.RateLimit.Rate},
		// PoP overload threshold. Parsed strictly because a typo
		// silently reverting to the default would weaken the capacity
		// guardrail that keeps a PoP from being over-subscribed.
		{"POP_HIGH_WATER_FRACTION", 0.85, &cfg.PoP.HighWaterFraction},
		// WS-5 NoOps auto-promoter promotion ceilings. Parsed strictly
		// because a typo silently reverting to the default would weaken
		// the guardrail that gates monitor->enforce.
		{"ROLLOUT_AUTOPILOT_MAX_ERROR_RATE", 0.01, &cfg.RolloutAutopilot.MaxErrorRate},
		{"ROLLOUT_AUTOPILOT_MAX_DENY_RATE", 0.05, &cfg.RolloutAutopilot.MaxDenyRate},
		// WS8 ClickHouse row-write limiter steady-state rate, in rows/s.
		// 0 ⇒ use the metering package default (2000). Parsed strictly so
		// a typo can't silently revert a tightened cost ceiling.
		{"CLICKHOUSE_ROW_LIMIT_PER_SEC", 0, &cfg.TelemetryAnalytics.ClickHouseRowLimitPerSec},
		// WS12 batch auto-tune target, per-shard inserts/sec. 0 ⇒ use the
		// telemetry package default (~2/sec). Parsed strictly so a typo
		// can't silently revert the "too many parts" health target.
		{"CLICKHOUSE_AUTOTUNE_TARGET_INSERTS_PER_SEC", 0, &cfg.TelemetryAnalytics.ClickHouseAutoTuneTargetInsertsPerSec},
		// WS-4 tier-sampling idle-tier keep multiplier. 0 ⇒ use the
		// telemetry package default (0.25). Parsed strictly so a typo
		// can't silently change idle-tenant retention.
		{"CLICKHOUSE_TIER_SAMPLING_IDLE_MULTIPLIER", 0, &cfg.TelemetryAnalytics.ClickHouseTierSamplingIdleMultiplier},
	}
	// Boolean fields parsed strictly. Both entries below toggle
	// security- or correctness-adjacent behaviour:
	//   - NATS_TLS_INSECURE skips TLS verification (CA pinning is the
	//     whole point of that field), so an operator-intended
	//     "true" that lands here as the default "false" silently
	//     leaves the connection unverified — and the inverse silently
	//     leaves a self-signed dev cluster broken. Both are bad.
	//   - RATE_LIMIT_ENABLED gates the rate-limit middleware. An
	//     operator-intended "false" (load test, debug) that lands as
	//     the default "true" silently denies traffic; the inverse
	//     silently disables protection.
	// Fail boot on any value strconv.ParseBool refuses so the
	// operator's intent is never silently overridden by a default.
	strictBools := []struct {
		key string
		def bool
		dst *bool
	}{
		{"NATS_TLS_INSECURE", false, &cfg.NATS.TLSInsecure},
		{"PG_PGBOUNCER_MODE", false, &cfg.Postgres.PgBouncerMode},
		{"RATE_LIMIT_ENABLED", true, &cfg.RateLimit.Enabled},
		{"TENANT_RATE_LIMIT_ENABLED", true, &cfg.TenantRateLimit.Enabled},
		{"BRUTEFORCE_ENABLED", true, &cfg.BruteForce.Enabled},
		{"CLICKHOUSE_TLS", false, &cfg.TelemetryAnalytics.ClickHouseTLS},
		{"CLICKHOUSE_ENSURE_SCHEMA", true, &cfg.TelemetryAnalytics.ClickHouseEnsureSchema},
		{"CLICKHOUSE_SHARDING", false, &cfg.TelemetryAnalytics.ClickHouseSharding},
		{"CLICKHOUSE_ROW_LIMIT_ENABLED", true, &cfg.TelemetryAnalytics.ClickHouseRowLimitEnabled},
		{"CLICKHOUSE_ROW_LIMIT_ADAPTIVE", false, &cfg.TelemetryAnalytics.ClickHouseRowLimitAdaptive},
		{"CLICKHOUSE_AUTOTUNE_ENABLED", true, &cfg.TelemetryAnalytics.ClickHouseAutoTuneEnabled},
		{"CLICKHOUSE_TIER_SAMPLING_ENABLED", false, &cfg.TelemetryAnalytics.ClickHouseTierSamplingEnabled},
		{"S3_TELEMETRY_MANAGE_LIFECYCLE", true, &cfg.TelemetryAnalytics.S3ManageLifecycle},
		{"APP_REGISTRY_SYNC_ENABLED", true, &cfg.AppRegistry.SyncEnabled},
		{"CASB_NOOPS_ENABLED", false, &cfg.CASB.NoOpsEnabled},
		{"CASB_NOOPS_AUTO_ENFORCE", false, &cfg.CASB.NoOpsAutoEnforce},
		// WS-5 NoOps auto-promoter. DEFAULT-OFF master gate: the
		// leader-only promotion loop is only registered when this is
		// explicitly enabled, so an upgrade never silently starts
		// auto-promoting. AutoEnrol defaults true so an enabled autopilot
		// dry-runs fresh tenants with zero clicks; both parsed strictly so
		// a typo fails boot rather than silently mis-gating the autopilot.
		{"ROLLOUT_AUTOPILOT_ENABLED", false, &cfg.RolloutAutopilot.Enabled},
		{"ROLLOUT_AUTOPILOT_AUTO_ENROL", true, &cfg.RolloutAutopilot.AutoEnrol},
		// Dormant-tenant hibernation. DEFAULT-OFF: the leader-only
		// controller, registry sync, wake coordinator, and the telemetry
		// /retention/metering hooks are only wired when this is explicitly
		// enabled, so an upgrade never starts parking tenants on its own.
		{"HIBERNATION_ENABLED", false, &cfg.Hibernation.Enabled},
		{"MOBILE_AUTH_AUTO_PROVISION_USERS", true, &cfg.MobileAuth.AutoProvisionUsers},
		{"IDP_DIRECTORY_SYNC_ENABLED", false, &cfg.MobileAuth.DirectorySyncEnabled},
		// Managed DNS threat-intel feed pipeline. DEFAULT-OFF: the
		// leader-only loop is only registered when this is explicitly
		// enabled. Parsed strictly so a typo fails boot rather than
		// silently leaving the pipeline off when an operator meant to
		// turn it on.
		{"THREAT_INTEL_ENABLED", false, &cfg.ManagedDNSFeeds.Enabled},
		{"METRICS_ENABLED", true, &cfg.Metrics.Enabled},
		{"POP_REBALANCE_ENABLED", true, &cfg.PoP.RebalanceEnabled},
		// Per-tenant activity tracking. Default ON: it is the writer
		// that populates last_active_at, without which the dormancy
		// planner sees every tenant as dormant. Cheap (debounced, async)
		// so there is no reason to ship it off by default.
		{"ACTIVITY_TRACKING_ENABLED", true, &cfg.Activity.Enabled},
		// WS-9 fleet-scale shared inference pool. DEFAULT-OFF: when
		// unset the AI LLM path keeps its current behaviour (no fair
		// scheduling / admission). Parsed strictly so a typo fails boot
		// rather than silently leaving the pool off when an operator
		// meant to turn it on.
		{"AI_INFERENCE_POOL_ENABLED", false, &cfg.AI.InferencePoolEnabled},
		// Alert false-positive feedback tuning loop. DEFAULT-OFF: the
		// leader-only sweep mutates baseline Z-thresholds, so it is only
		// registered when an operator explicitly opts in. Parsed strictly
		// so a typo fails boot rather than silently leaving it off.
		{"ALERT_FEEDBACK_TUNING_ENABLED", false, &cfg.AlertFeedback.TuningEnabled},
	}

	var strictErrs []error
	for _, s := range strictInts {
		v, err := getIntStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictDurations {
		v, err := getDurationStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictFloats {
		v, err := getFloatStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictBools {
		v, err := getBoolStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	// METERING_DEFAULT_BUDGETS is a map (meter=value,...), so it cannot
	// ride the scalar strict tables; parse it strictly here so a
	// malformed entry fails boot like every other load-bearing setting.
	if budgets, err := getInt64MapStrict("METERING_DEFAULT_BUDGETS"); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Metering.DefaultBudgets = budgets
	}
	if len(strictErrs) > 0 {
		return cfg, errors.Join(strictErrs...)
	}

	// Detect retired environment variables and fail loudly so an
	// operator upgrading the binary cannot silently fall back to
	// the default while their old setting is ignored. The previous
	// `WEBHOOK_MAX_RETRIES=N` meant "N retries on top of the first
	// attempt" (i.e. N+1 total). The new `WEBHOOK_MAX_ATTEMPTS=N`
	// means "N total deliveries". Silently reading only the new
	// name would turn a previously-set `WEBHOOK_MAX_RETRIES=6`
	// (= 7 attempts) into the default `WEBHOOK_MAX_ATTEMPTS=6`
	// (= 6 attempts) — a behaviour change the operator never
	// consented to. Refusing to boot forces a conscious migration
	// (`WEBHOOK_MAX_ATTEMPTS=7` if they want the old behaviour).
	if v, ok := os.LookupEnv("WEBHOOK_MAX_RETRIES"); ok {
		return cfg, fmt.Errorf(
			"WEBHOOK_MAX_RETRIES is no longer supported (was found: %q); "+
				"rename to WEBHOOK_MAX_ATTEMPTS and add 1 to preserve the "+
				"previous behaviour (old: N retries on top of the first "+
				"attempt = N+1 total; new: N total deliveries)", v)
	}

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// MustLoad calls [Load] and panics on error. Useful in main() only.
func MustLoad() Config {
	cfg, err := Load()
	if err != nil {
		panic(err)
	}
	return cfg
}

// validate enforces minimal correctness invariants.
func (c Config) validate() error {
	if c.AppName == "" {
		return errors.New("APP_NAME must be set")
	}
	if !c.Environment.Valid() {
		return fmt.Errorf("ENVIRONMENT: invalid value %q (expected local|dev|qa|uat|prod)", c.Environment)
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP_PORT out of range: %d", c.HTTP.Port)
	}
	if c.HTTP.ReadTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_TIMEOUT must be > 0, got %s", c.HTTP.ReadTimeout)
	}
	if c.HTTP.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT must be > 0, got %s", c.HTTP.ReadHeaderTimeout)
	}
	if c.HTTP.WriteTimeout <= 0 {
		return fmt.Errorf("HTTP_WRITE_TIMEOUT must be > 0, got %s", c.HTTP.WriteTimeout)
	}
	// HTTP_READ_HEADER_TIMEOUT must be <= HTTP_READ_TIMEOUT.
	// Otherwise the header-read deadline never fires (the body-read
	// deadline always wins), defeating its Slowloris-mitigation
	// purpose.
	if c.HTTP.ReadHeaderTimeout > c.HTTP.ReadTimeout {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT (%s) must be <= HTTP_READ_TIMEOUT (%s)",
			c.HTTP.ReadHeaderTimeout, c.HTTP.ReadTimeout)
	}
	if c.HTTP.ShutdownTimeout <= 0 {
		return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be > 0, got %s", c.HTTP.ShutdownTimeout)
	}
	if c.Postgres.Port <= 0 || c.Postgres.Port > 65535 {
		return fmt.Errorf("PG_PORT out of range: %d", c.Postgres.Port)
	}
	// libpq's connect_timeout DSN field is rendered as integer seconds
	// (ceil for sub-second values), and libpq treats 0 as "infinite".
	// Reject non-positive durations here so neither the libpq fallback
	// nor the pgx dial path can race to infinity behind an operator's
	// back.
	if c.Postgres.ConnTimeout <= 0 {
		return fmt.Errorf("PG_CONN_TIMEOUT must be > 0, got %s", c.Postgres.ConnTimeout)
	}
	if c.Postgres.Host == "" {
		return errors.New("PG_HOST must be set")
	}
	if c.Postgres.Database == "" {
		return errors.New("PG_DATABASE must be set")
	}
	if c.Postgres.User == "" {
		return errors.New("PG_USER must be set")
	}
	// Connection-pool sizes are stored as Go int because env parsing
	// is via strconv.Atoi, but the pgx driver takes int32. Bound the
	// configured values so a typo like PG_MAX_OPEN_CONNS=2147483648
	// fails boot rather than wrapping to a negative number.
	if c.Postgres.MaxOpenConns < 1 || c.Postgres.MaxOpenConns > 10_000 {
		return fmt.Errorf("PG_MAX_OPEN_CONNS out of range [1,10000]: %d", c.Postgres.MaxOpenConns)
	}
	// PG_MIN_CONNS is the floor on idle connections eagerly
	// maintained by pgxpool. It must be in [0, PG_MAX_OPEN_CONNS]:
	// MinConns > MaxConns would deadlock the pool acquire loop.
	if c.Postgres.MinConns < 0 || c.Postgres.MinConns > c.Postgres.MaxOpenConns {
		return fmt.Errorf("PG_MIN_CONNS out of range [0,%d]: %d", c.Postgres.MaxOpenConns, c.Postgres.MinConns)
	}
	switch c.Postgres.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("PG_SSLMODE: invalid value %q", c.Postgres.SSLMode)
	}
	// PG_READ_REPLICA_PORT: 0 means "inherit PG_PORT" (see
	// Postgres.ReplicaPort). Any explicit value must be a valid TCP
	// port so a typo fails boot rather than producing an
	// unconnectable replica DSN at first read.
	if c.Postgres.ReadReplicaPort != 0 &&
		(c.Postgres.ReadReplicaPort < 1 || c.Postgres.ReadReplicaPort > 65535) {
		return fmt.Errorf("PG_READ_REPLICA_PORT out of range [1,65535] (0 inherits PG_PORT): %d", c.Postgres.ReadReplicaPort)
	}
	if c.NATS.URL == "" {
		return errors.New("NATS_URL must be set")
	}
	// NATS_PUBLISH_RETRY_ATTEMPTS is the total publish attempt budget
	// (first try + retries). The publisher's fallback chain
	// (opts.MaxAttempts → opts.MaxRetries → cfg.PublishRetryAttempts →
	// hard-coded 3) uses `<= 0` as the "unset, fall through" sentinel
	// at every level. Allowing 0 here would mean operators who
	// explicitly set 0 to express "single attempt, no retries" would
	// silently get the hard-coded default of 3 instead — their
	// configuration ignored. Require >= 1 so the validator and the
	// publisher agree on what "set" means. Operators wanting a single
	// attempt set this to 1.
	if c.NATS.PublishRetryAttempts < 1 {
		return fmt.Errorf("NATS_PUBLISH_RETRY_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.NATS.PublishRetryAttempts)
	}
	// NATS_CONNECT_TIMEOUT is wired to nats.Timeout() for the initial
	// dial. The nats.go client treats 0 as "no deadline" — the dial
	// will block forever waiting on a flapping server — so we reject
	// it here to match the operator's almost-certain intent.
	if c.NATS.ConnectTimeout <= 0 {
		return fmt.Errorf("NATS_CONNECT_TIMEOUT must be > 0, got %s", c.NATS.ConnectTimeout)
	}
	// NATS_REQUEST_TIMEOUT is the per-request deadline used by
	// nats.Conn.RequestWithContext and JetStream Publish opts. A zero
	// value gives an infinite request deadline; same reason as above.
	if c.NATS.RequestTimeout <= 0 {
		return fmt.Errorf("NATS_REQUEST_TIMEOUT must be > 0, got %s", c.NATS.RequestTimeout)
	}
	// NATS_DEDUP_WINDOW: zero is explicitly NOT rejected, but its
	// runtime meaning is "use the JetStream server default
	// (~2 minutes)", NOT "disabled". JetStream's `Duplicates`
	// field treats 0 as "absent → server default", and the
	// nats-server team has not exposed a true off-switch. Our
	// `DefaultStreams` wrapper folds `<=0` into the same 2m
	// default for consistency. Operators who want a different
	// window must set a positive duration; there is no "disabled"
	// option today (a follow-up could route true-disable via a
	// sentinel like -1, but no caller currently needs that).
	switch c.NATS.Storage {
	case "file", "memory":
	default:
		return fmt.Errorf("NATS_STORAGE: invalid value %q (expected file|memory)", c.NATS.Storage)
	}
	// AI_LLM_MODEL_FAMILY selects the model-tuned system prompt. "" and
	// "auto" infer the family from the model name; the explicit families
	// are validated here (mirroring PG_SSLMODE/NATS_STORAGE) so an operator
	// typo fails fast at boot instead of silently degrading to the
	// general-purpose prompt at request time.
	switch c.AI.ModelFamily {
	case "", "auto", "ternary-bonsai", "openai-compat":
	default:
		return fmt.Errorf("AI_LLM_MODEL_FAMILY: invalid value %q (expected auto|ternary-bonsai|openai-compat)", c.AI.ModelFamily)
	}
	// NATS_PARTITIONS is the telemetry stream cell count. 1 keeps
	// the historical single-stream layout; >1 fans out into N cells
	// (SNG_TELEMETRY_0…). Reject 0/negative (which would leave the
	// partitioner with no cells to hash into) and cap the upper
	// bound so a typo like NATS_PARTITIONS=100000 can't try to
	// stand up an absurd number of streams/consumers at boot.
	if c.NATS.Partitions < 1 || c.NATS.Partitions > 256 {
		return fmt.Errorf("NATS_PARTITIONS out of range [1,256]: %d", c.NATS.Partitions)
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Rate <= 0 {
			return fmt.Errorf("RATE_LIMIT_RATE must be > 0 when enabled, got %v", c.RateLimit.Rate)
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("RATE_LIMIT_BURST must be > 0 when enabled, got %d", c.RateLimit.Burst)
		}
	}
	if c.TenantRateLimit.Enabled {
		if c.TenantRateLimit.StandardPerMinute <= 0 {
			return fmt.Errorf("TENANT_RATE_LIMIT_STANDARD_PER_MIN must be > 0 when enabled, got %d", c.TenantRateLimit.StandardPerMinute)
		}
		if c.TenantRateLimit.PremiumPerMinute <= 0 {
			return fmt.Errorf("TENANT_RATE_LIMIT_PREMIUM_PER_MIN must be > 0 when enabled, got %d", c.TenantRateLimit.PremiumPerMinute)
		}
		if c.TenantRateLimit.TierTTL <= 0 {
			return fmt.Errorf("TENANT_RATE_LIMIT_TIER_TTL must be > 0 when enabled, got %v", c.TenantRateLimit.TierTTL)
		}
	}
	if c.BruteForce.Enabled {
		if c.BruteForce.AuthMaxFailures <= 0 {
			return fmt.Errorf("BRUTEFORCE_AUTH_MAX_FAILURES must be > 0 when enabled, got %d", c.BruteForce.AuthMaxFailures)
		}
		if c.BruteForce.AuthCooldown <= 0 {
			return fmt.Errorf("BRUTEFORCE_AUTH_COOLDOWN must be > 0 when enabled, got %v", c.BruteForce.AuthCooldown)
		}
		if c.BruteForce.EnrollMaxFailures <= 0 {
			return fmt.Errorf("BRUTEFORCE_ENROLL_MAX_FAILURES must be > 0 when enabled, got %d", c.BruteForce.EnrollMaxFailures)
		}
		if c.BruteForce.EnrollCooldown <= 0 {
			return fmt.Errorf("BRUTEFORCE_ENROLL_COOLDOWN must be > 0 when enabled, got %v", c.BruteForce.EnrollCooldown)
		}
	}
	// WEBHOOK_MAX_ATTEMPTS is the total delivery-attempt budget
	// (first try + retries). The worker's defaults() function uses
	// `<= 0` as the "unset, fall through to package default"
	// sentinel, which means an operator who set MaxAttempts=0 to
	// express "single attempt, no retries" would silently get the
	// hard-coded default of 8 instead — their configuration ignored.
	// Require >= 1 (same pattern as NATS_PUBLISH_RETRY_ATTEMPTS) so
	// the validator and the worker agree on what "set" means.
	// Operators wanting a single attempt with no retries set this
	// to 1.
	if c.Webhook.MaxAttempts < 1 {
		return fmt.Errorf("WEBHOOK_MAX_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.Webhook.MaxAttempts)
	}
	if c.Webhook.InitialDelay <= 0 {
		return fmt.Errorf("WEBHOOK_INITIAL_DELAY must be > 0, got %s", c.Webhook.InitialDelay)
	}
	if c.Webhook.MaxDelay < c.Webhook.InitialDelay {
		return fmt.Errorf("WEBHOOK_MAX_DELAY (%s) must be >= WEBHOOK_INITIAL_DELAY (%s)", c.Webhook.MaxDelay, c.Webhook.InitialDelay)
	}
	// WEBHOOK_DELIVERY_TIMEOUT is mapped to the per-attempt
	// http.Client.Timeout. Go's net/http treats 0 as "no timeout",
	// which against an unresponsive subscriber would pin a worker
	// goroutine + connection indefinitely and exhaust the delivery
	// pool. Reject 0 explicitly so the strict parser's 0s acceptance
	// can't slip through.
	if c.Webhook.DeliveryTimeout <= 0 {
		return fmt.Errorf("WEBHOOK_DELIVERY_TIMEOUT must be > 0, got %s", c.Webhook.DeliveryTimeout)
	}
	if c.Webhook.BatchSize <= 0 {
		return fmt.Errorf("WEBHOOK_BATCH_SIZE must be > 0, got %d", c.Webhook.BatchSize)
	}
	if c.Webhook.PollInterval <= 0 {
		return fmt.Errorf("WEBHOOK_POLL_INTERVAL must be > 0, got %s", c.Webhook.PollInterval)
	}
	// WEBHOOK_PROCESSING_TIMEOUT <= DeliveryTimeout would let the
	// stuck-row reaper steal a row from a worker that's still
	// inside its HTTP call — double-delivery hazard. Force the
	// reaper window to be strictly larger than the per-attempt
	// timeout so a genuinely in-flight delivery cannot be
	// reclaimed under any race.
	if c.Webhook.ProcessingTimeout <= c.Webhook.DeliveryTimeout {
		return fmt.Errorf("WEBHOOK_PROCESSING_TIMEOUT (%s) must be > WEBHOOK_DELIVERY_TIMEOUT (%s) to prevent stuck-row reaper from racing in-flight deliveries", c.Webhook.ProcessingTimeout, c.Webhook.DeliveryTimeout)
	}
	// Integration delivery worker — same invariants as the
	// webhook worker. Reject 0 explicitly so the strict parser's
	// 0s acceptance cannot let an operator's misconfigured value
	// fall through to the worker's hard-coded default.
	if c.Integration.MaxAttempts < 1 {
		return fmt.Errorf("INTEGRATION_WORKER_MAX_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.Integration.MaxAttempts)
	}
	if c.Integration.BackoffBase <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_BACKOFF_BASE must be > 0, got %s", c.Integration.BackoffBase)
	}
	if c.Integration.BackoffMax < c.Integration.BackoffBase {
		return fmt.Errorf("INTEGRATION_WORKER_BACKOFF_MAX (%s) must be >= INTEGRATION_WORKER_BACKOFF_BASE (%s)", c.Integration.BackoffMax, c.Integration.BackoffBase)
	}
	if c.Integration.BatchSize <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_BATCH_SIZE must be > 0, got %d", c.Integration.BatchSize)
	}
	if c.Integration.PollInterval <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_POLL_INTERVAL must be > 0, got %s", c.Integration.PollInterval)
	}
	if c.Integration.ProcessingTimeout <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_PROCESSING_TIMEOUT must be > 0, got %s", c.Integration.ProcessingTimeout)
	}
	// AUTH_ACCESS_TOKEN_TTL <= 0 makes every issued token already
	// expired, which would silently lock every operator out of the
	// console. Forbid here so the strict parser's lenient acceptance
	// of "0s" is caught at boot rather than at first sign-in.
	if c.Auth.AccessTokenTTL <= 0 {
		return fmt.Errorf("AUTH_ACCESS_TOKEN_TTL must be > 0, got %s", c.Auth.AccessTokenTTL)
	}
	if c.Auth.ClaimTokenTTL <= 0 {
		return fmt.Errorf("AUTH_CLAIM_TOKEN_TTL must be > 0, got %s", c.Auth.ClaimTokenTTL)
	}
	// AUTH_JWT_SECRET drives the symmetric (HMAC) dev-signing path
	// that lets a developer mint operator JWTs without standing up an
	// IdP. Production (uat/prod) terminates identity at the gateway
	// via OIDC and the HMAC verification path is compiled out of
	// production builds entirely (see the //go:build !production guard
	// in internal/middleware/auth.go and SECURITY.md). A configured
	// AUTH_JWT_SECRET in production is therefore either dead config or
	// — worse — an operator's mistaken belief that HMAC auth is
	// active; either way it is a security-relevant misconfiguration we
	// refuse to boot with rather than silently ignore.
	if c.Auth.JWTSecret != "" && c.Environment.IsProduction() {
		return errors.New("AUTH_JWT_SECRET must NOT be set in production environments: the HMAC JWT signing/verification path is excluded from production builds; terminate identity at the gateway via OIDC instead (see SECURITY.md and docs/deploy.md)")
	}
	if c.Environment.IsProduction() && c.NATS.TLSInsecure {
		return errors.New("NATS_TLS_INSECURE must be false in production environments")
	}
	// PG_APP_ROLE must be set in production. The Postgres pool's
	// AfterConnect hook adopts this role via SET SESSION ROLE so
	// RLS policies — which Postgres bypasses for superusers — apply
	// to every query. Running production with an empty AppRole
	// means the pool connects as PG_USER directly; if PG_USER is a
	// superuser (the common case for cloud-managed PG), RLS would
	// silently bypass. Fail boot rather than running with the
	// security model neutered.
	if c.Environment.IsProduction() && c.Postgres.AppRole == "" {
		return errors.New("PG_APP_ROLE must be set to a non-empty role in production environments (the runtime adopts this role via SET SESSION ROLE to enforce RLS; see docs/deploy.md)")
	}
	// The active-key cap blocks unbounded creation; disabling it
	// in production is almost always a misconfiguration. Tests
	// can still pass 0 via WithMaxActiveKeys directly without
	// going through env-config.
	if c.Environment.IsProduction() && c.Auth.APIKeyMaxActivePerTenant <= 0 {
		return errors.New("AUTH_API_KEY_MAX_ACTIVE_PER_TENANT must be > 0 in production environments (the cap protects against unbounded key creation; see docs/deploy.md)")
	}
	// Same rationale as the API-key cap above: the IdP-config handler
	// treats <= 0 as "unlimited", so allowing it in production would
	// silently disable the per-tenant provider cap and permit
	// unbounded idp_configs creation.
	if c.Environment.IsProduction() && c.MobileAuth.MaxProvidersPerTenant <= 0 {
		return errors.New("MOBILE_AUTH_MAX_PROVIDERS_PER_TENANT must be > 0 in production environments (the cap protects against unbounded IdP-config creation; see docs/deploy.md)")
	}
	// Same rationale as AUTH_ACCESS_TOKEN_TTL above: a <= 0 value would
	// be silently overridden by the service's 1h default
	// (OIDCService.sessionTTL) instead of honouring operator intent, so
	// "0s" must fail loudly at boot rather than minting unexpectedly
	// scoped sessions.
	if c.MobileAuth.SessionTokenTTL <= 0 {
		return fmt.Errorf("MOBILE_AUTH_SESSION_TOKEN_TTL must be > 0, got %s", c.MobileAuth.SessionTokenTTL)
	}
	// When the directory-sync loop is enabled its cadence must be
	// positive: a <= 0 interval is silently overridden by
	// SyncService.Run's DefaultSyncInterval, so fail loudly rather than
	// running on a cadence the operator never chose. Only enforced when
	// the loop is enabled (the default-off path ignores the interval).
	if c.MobileAuth.DirectorySyncEnabled && c.MobileAuth.DirectorySyncInterval <= 0 {
		return fmt.Errorf("IDP_DIRECTORY_SYNC_INTERVAL must be > 0 when IDP_DIRECTORY_SYNC_ENABLED=true, got %s", c.MobileAuth.DirectorySyncInterval)
	}
	// Managed DNS threat-intel feed pipeline: when enabled its refresh
	// cadence must be positive (a <= 0 interval would otherwise be
	// silently overridden by the service's DefaultRefreshInterval rather
	// than the cadence the operator chose). Only enforced when the
	// pipeline is enabled — the default-off path ignores the interval.
	if c.ManagedDNSFeeds.Enabled && c.ManagedDNSFeeds.RefreshInterval <= 0 {
		return fmt.Errorf("THREAT_INTEL_REFRESH_INTERVAL must be > 0 when THREAT_INTEL_ENABLED=true, got %s", c.ManagedDNSFeeds.RefreshInterval)
	}
	// WS-9 shared inference pool: when enabled, the concurrency cap and
	// per-tenant queue depth must be positive. A <= 0 value would
	// otherwise be silently overridden by InferencePoolConfig.normalize()
	// (4 / 8 respectively), so an operator who sets the cap to 0 expecting
	// "no pooling" would instead get a 4-slot pool. Fail loudly rather
	// than run on sizing the operator never chose. Only enforced when the
	// pool is enabled — the default-off path ignores these values.
	if c.AI.InferencePoolEnabled {
		if c.AI.InferencePoolMaxConcurrent <= 0 {
			return fmt.Errorf("AI_INFERENCE_POOL_MAX_CONCURRENT must be > 0 when AI_INFERENCE_POOL_ENABLED=true, got %d", c.AI.InferencePoolMaxConcurrent)
		}
		if c.AI.InferencePoolMaxQueuePerTenant <= 0 {
			return fmt.Errorf("AI_INFERENCE_POOL_MAX_QUEUE_PER_TENANT must be > 0 when AI_INFERENCE_POOL_ENABLED=true, got %d", c.AI.InferencePoolMaxQueuePerTenant)
		}
	}
	// Alert feedback tuning loop: when enabled its cadence must be
	// positive (a <= 0 interval would be silently overridden by the
	// service's default rather than the cadence the operator chose).
	// Only enforced when the loop is enabled — the default-off path
	// ignores the interval.
	if c.AlertFeedback.TuningEnabled && c.AlertFeedback.TuningInterval <= 0 {
		return fmt.Errorf("ALERT_FEEDBACK_TUNING_INTERVAL must be > 0 when ALERT_FEEDBACK_TUNING_ENABLED=true, got %s", c.AlertFeedback.TuningInterval)
	}
	// Likewise, a <= 0 discovery-cache TTL would silently fall back to
	// the service's 24h default rather than the configured value.
	if c.MobileAuth.DiscoveryCacheTTL <= 0 {
		return fmt.Errorf("MOBILE_AUTH_DISCOVERY_CACHE_TTL must be > 0, got %s", c.MobileAuth.DiscoveryCacheTTL)
	}
	if err := c.IAMCore.validate(c.Environment); err != nil {
		return err
	}
	if c.Policy.KeyWrapMasterB64 != "" && c.Policy.KeyWrapMasterFile != "" {
		return errors.New("POLICY_KEY_WRAP_MASTER_B64 and POLICY_KEY_WRAP_MASTER_FILE are mutually exclusive")
	}
	// Telemetry analytics: production requires authenticated
	// ClickHouse (anonymous default-user access is dangerous when
	// the cluster is reachable from the network) and an explicit
	// AWS region for the cold archive bucket (otherwise the SDK
	// silently picks `us-east-1`, which can violate data-residency
	// requirements). Both rules are skipped when the corresponding
	// sink is disabled.
	if c.Environment.IsProduction() && len(c.TelemetryAnalytics.ClickHouseEndpoints) > 0 {
		if c.TelemetryAnalytics.ClickHouseUsername == "" || c.TelemetryAnalytics.ClickHousePassword == "" {
			return errors.New("CLICKHOUSE_USERNAME and CLICKHOUSE_PASSWORD must be set in production when CLICKHOUSE_ENDPOINTS is configured (anonymous default-user access is unsafe over the network)")
		}
	}
	if c.TelemetryAnalytics.S3Bucket != "" && c.TelemetryAnalytics.S3Region == "" && c.TelemetryAnalytics.S3Endpoint == "" {
		return errors.New("S3_TELEMETRY_REGION must be set when S3_TELEMETRY_BUCKET is configured (or set S3_TELEMETRY_ENDPOINT for non-AWS S3-compatible stores)")
	}
	// Metrics: the internal scrape listener must bind to a port
	// distinct from the public API. Co-locating them would expose
	// the operational `/metrics` surface (tenant counts, pool
	// sizes, NATS lag) on the public ingress. Skipped when the
	// metrics subsystem is disabled.
	if c.Metrics.Enabled {
		if c.Metrics.Port <= 0 || c.Metrics.Port > 65535 {
			return fmt.Errorf("METRICS_PORT out of range: %d", c.Metrics.Port)
		}
		if c.Metrics.Port == c.HTTP.Port {
			return fmt.Errorf("METRICS_PORT (%d) must differ from HTTP_PORT (%d): the internal metrics surface must not be co-located with the public API", c.Metrics.Port, c.HTTP.Port)
		}
		if !isValidMetricPrefix(c.Metrics.Namespace) {
			return fmt.Errorf("METRICS_NAMESPACE %q is not a valid Prometheus metric-name prefix (must match [a-zA-Z_][a-zA-Z0-9_]*)", c.Metrics.Namespace)
		}
	}
	if c.Environment.IsProduction() {
		// In production we require a sslmode that guarantees TLS.
		// `disable` is unencrypted; `allow` attempts plaintext
		// first and only upgrades if the server insists; `prefer`
		// attempts TLS but silently falls back to plaintext if
		// TLS fails. Only `require`, `verify-ca`, and
		// `verify-full` provide a hard guarantee that the
		// connection is encrypted (verify-ca / verify-full also
		// authenticate the server). The validator runs after the
		// generic enum whitelist above, so any value reaching
		// here is already a recognised mode.
		switch c.Postgres.SSLMode {
		case "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("PG_SSLMODE must be one of require|verify-ca|verify-full in production environments, got %q", c.Postgres.SSLMode)
		}
	}
	// Cloud PoP service knobs. The strict parser accepts "0s"/0 and the
	// service-level options (WithHighWaterFraction, WithHealthTTL)
	// silently ignore out-of-range values, so an operator typo would
	// quietly run with a default instead of the intended value. A zero
	// POP_REGISTRY_REFRESH_INTERVAL is worse than silent — it panics
	// time.NewTicker. Fail boot loudly, mirroring the Rust edge config
	// (crates/sng-edge/src/config.rs) which rejects the same
	// out-of-range high-water fraction.
	//
	// The bound is written as the negation of the in-range predicate
	// (not `<= 0 || > 1`) so it also rejects NaN: strconv.ParseFloat
	// accepts "NaN", and every NaN comparison is false, so the
	// open-coded form would let NaN through to silently revert to the
	// 0.85 default. This matches the Rust edge's `!(f > 0.0 && f <= 1.0)`.
	if !(c.PoP.HighWaterFraction > 0 && c.PoP.HighWaterFraction <= 1) {
		return fmt.Errorf("POP_HIGH_WATER_FRACTION must be in (0, 1], got %v", c.PoP.HighWaterFraction)
	}
	if c.PoP.RegistryRefreshInterval <= 0 {
		return fmt.Errorf("POP_REGISTRY_REFRESH_INTERVAL must be > 0, got %s", c.PoP.RegistryRefreshInterval)
	}
	if c.PoP.HealthTTL <= 0 {
		return fmt.Errorf("POP_HEALTH_TTL must be > 0, got %s", c.PoP.HealthTTL)
	}
	if c.PoP.GeoDNSTTL <= 0 {
		return fmt.Errorf("POP_GEODNS_TTL must be > 0, got %s", c.PoP.GeoDNSTTL)
	}
	if c.PoP.GeoDNSPublishInterval <= 0 {
		return fmt.Errorf("POP_GEODNS_PUBLISH_INTERVAL must be > 0, got %s", c.PoP.GeoDNSPublishInterval)
	}
	if c.PoP.RebalanceInterval <= 0 {
		return fmt.Errorf("POP_REBALANCE_INTERVAL must be > 0, got %s", c.PoP.RebalanceInterval)
	}
	if c.TenantMigration.ResumeInterval <= 0 {
		return fmt.Errorf("WS11_MIGRATION_RESUME_INTERVAL must be > 0, got %s", c.TenantMigration.ResumeInterval)
	}
	return nil
}

// --- env helpers ------------------------------------------------------------

// isValidMetricPrefix reports whether s is a valid Prometheus
// metric-name prefix, i.e. matches [a-zA-Z_][a-zA-Z0-9_]*. Kept
// dependency-free (no regexp) in keeping with this package's
// stdlib-only constraint and to stay allocation-free on the boot
// path.
func isValidMetricPrefix(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 {
			if !isAlpha {
				return false
			}
			continue
		}
		if !isAlpha && !isDigit {
			return false
		}
	}
	return true
}

// splitCSV splits a comma-separated env-style list, trimming
// whitespace and dropping empty entries. Empty input → empty
// slice (not nil-vs-empty distinguished — callers treat both as
// "no values"). Used by env helpers that resolve into list-typed
// config fields (e.g. ClickHouse endpoints).
func splitCSV(in string) []string {
	if in == "" {
		return nil
	}
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func getStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// parseKeyedURLs parses a CSV of `key=value` pairs into a map, used for
// the THREAT_INTEL_CATEGORY_FEEDS knob (`ads=https://…,gambling=https://…`).
// Whitespace around keys / values is trimmed; entries without a `=` or
// with an empty key / value are skipped (lenient: a single malformed
// pair never poisons the whole map). On the first `=` only, so values
// containing `=` (query strings) survive. Returns nil for empty input.
//
// The comma is the pair separator, so a value (feed URL) must not
// contain a raw comma; percent-encode it as %2C. In practice feed URLs
// don't carry literal commas, and this keeps the knob a simple CSV
// rather than requiring a quoting scheme.
func parseKeyedURLs(in string) map[string]string {
	pairs := splitCSV(in)
	if len(pairs) == 0 {
		return nil
	}
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getIntLenient parses an integer env var, falling back to def on
// unset or malformed input. Use for non-load-bearing knobs where a
// typo should degrade to the safe default rather than fail boot
// (load-bearing numerics use getIntStrict via the strict table).
func getIntLenient(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// getFloatLenient parses a float env var, falling back to def on
// unset or malformed input. Same lenient posture as getIntLenient —
// used for opportunistic enrichment knobs (e.g. the threat-intel
// confidence floor) where a typo should degrade to the default
// rather than fail boot.
func getFloatLenient(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return def
	}
	return f
}

// getBoolLenient parses a boolean env var, falling back to def on
// unset or malformed input. Same lenient posture as getIntLenient.
func getBoolLenient(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

// getStrAllowEmpty is the peer of `getStr` that distinguishes an
// unset environment variable from an explicitly empty one. Unset →
// `def`; set to empty string → empty string. Use this only for
// settings where the empty-string case is a meaningful operator
// signal (e.g. `PG_APP_ROLE=` to disable the SET SESSION ROLE
// hook in dev environments). Every other settings should use
// `getStr`, which treats empty and unset identically and is the
// safer default for fields where empty is never a valid value.
func getStrAllowEmpty(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// getIntStrict is the only int-parsing helper exposed by this
// package: every int-valued setting is critical enough that a typo
// must fail boot rather than silently fall back to a default that
// may differ from the operator's intent.
func getIntStrict(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, v, err)
	}
	return n, nil
}

// getDurationStrict is the duration twin of getIntStrict.
func getDurationStrict(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}

// getFloatStrict is the float64 twin of getIntStrict.
func getFloatStrict(key string, def float64) (float64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid float: %w", key, v, err)
	}
	return f, nil
}

// getBoolStrict is the bool twin of getIntStrict. We deliberately
// do not ship a lenient getBool helper: every boolean field consumed
// by Load() is either security-adjacent (e.g. NATS_TLS_INSECURE) or
// gates a load-bearing middleware (e.g. RATE_LIMIT_ENABLED), so a
// silent fall-back to the default on a typo like
// NATS_TLS_INSECURE=yes could mask the operator's intent in either
// direction. strconv.ParseBool already accepts the documented set
// {1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False} — any
// value outside that set is a config error, not a "be lenient" case.
func getBoolStrict(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s=%q is not a valid boolean (accepted: true/false/1/0): %w", key, v, err)
	}
	return b, nil
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

// getInt64MapStrict parses a comma-separated "key=value" list into a
// map[string]int64. An unset / empty variable yields a nil map (the
// caller's documented "no entries" case). Any malformed pair or
// non-integer value is a config error so a typo fails boot rather than
// silently dropping a budget — the same strictness rule the scalar
// helpers enforce.
func getInt64MapStrict(key string) (map[string]int64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil, nil
	}
	out := make(map[string]int64)
	for _, pair := range strings.Split(v, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, val, found := strings.Cut(pair, "=")
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)
		if !found || name == "" || val == "" {
			return nil, fmt.Errorf("config: %s=%q has an invalid entry %q (want meter=value)", key, v, pair)
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("config: %s entry %q has a non-integer value: %w", key, pair, err)
		}
		out[name] = n
	}
	return out, nil
}

// parseCSV splits a comma-separated list into a trimmed slice. Empty
// fields are dropped so trailing or duplicate commas do not produce
// empty allow-list entries.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadDotEnv parses a minimal .env file and assigns variables that
// aren't already in the process environment. The format mirrors the
// de-facto conventions used by docker-compose / direnv:
//
//   - Lines beginning with `#` and blank lines are ignored.
//   - Lines may optionally start with the shell `export` keyword,
//     which is stripped before parsing.
//   - Values may be optionally quoted with single or double quotes,
//     in which case the quotes are stripped.
//   - In unquoted values, an unescaped `#` introduces a trailing
//     comment that is stripped. Within quoted values `#` is taken
//     literally so passwords containing `#` survive.
//
// This is intentionally tiny: production deployments should source
// the environment from the orchestrator (k8s ConfigMap/Secret, ECS
// env, etc.). The `.env` loader exists only so that local-dev and
// CI scripts can drop their config in one place.
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow `export FOO=bar` for ergonomic copy-paste from a
		// shell session. The "export " prefix is stripped before
		// the key is parsed; "exportFOO=bar" is NOT treated as
		// an export and remains literal.
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimPrefix(line, "export\t")
		line = strings.TrimLeft(line, " \t")

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		switch {
		case len(val) >= 2 && (val[0] == '"' || val[0] == '\''):
			// Quoted-value path: take everything up to the
			// matching closing quote, then discard a trailing
			// `# comment` after the close. Anything inside the
			// quotes — including `#` — is preserved verbatim.
			quote := val[0]
			if end := strings.IndexByte(val[1:], quote); end >= 0 {
				rest := strings.TrimSpace(val[end+2:])
				if rest == "" || strings.HasPrefix(rest, "#") {
					val = val[1 : end+1]
				}
			}
		default:
			// Unquoted-value path: strip trailing `# comment`
			// only when preceded by whitespace, so a value
			// like `secret#1` survives but `secret # note`
			// becomes `secret`.
			if i := strings.IndexByte(val, '#'); i > 0 && (val[i-1] == ' ' || val[i-1] == '\t') {
				val = strings.TrimRight(val[:i], " \t")
			}
		}

		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return nil
}
