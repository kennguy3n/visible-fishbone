// Package metrics holds the ShieldNet Gateway control-plane
// Prometheus instrumentation. A single *Metrics value owns a
// dedicated *prometheus.Registry plus every metric the control
// plane exports; it is constructed once at boot (see
// cmd/sng-control) and threaded into the HTTP middleware, the
// background pool/JetStream collectors, and — for domain-specific
// counters — the services that own each pipeline.
//
// Design notes:
//
//   - A private registry (not the global default) keeps the
//     exposition surface deterministic and test-friendly: a test
//     can construct an isolated *Metrics, exercise it, and gather
//     without colliding with other packages' global registrations.
//   - Every metric carries the operator-configured namespace
//     (default "sng") so the exposition reads e.g.
//     `sng_http_requests_total`.
//   - Label cardinality is deliberately bounded. HTTP `path` is a
//     normalised route template (see middleware.go), never a raw
//     URL, so per-tenant / per-resource IDs cannot explode the
//     series count. Per-tenant gauges (active_devices, …) are an
//     intentional exception the spec calls for; they are gauges
//     (cheap, overwritten in place) rather than histograms.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// Default histogram bucket sets. Kept as package vars (copied on
// use) so the bucket boundaries are documented in one place and
// shared across the latency-style histograms.
var (
	// httpLatencyBuckets spans sub-millisecond control-plane
	// responses up to multi-second slow paths.
	httpLatencyBuckets = []float64{
		0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
	}
	// queryLatencyBuckets is tuned for Postgres query timings.
	queryLatencyBuckets = []float64{
		0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
	}
	// signLatencyBuckets covers Ed25519 bundle signing, which is
	// fast but can spike under key-wrap contention.
	signLatencyBuckets = []float64{
		0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
	}
	// bundleSizeBuckets covers signed policy bundle sizes from a
	// few hundred bytes up to a few MiB.
	bundleSizeBuckets = prometheus.ExponentialBucketsRange(256, 8*1024*1024, 12)
	// llmLatencyBuckets covers LLM round-trips, which run from
	// hundreds of milliseconds to tens of seconds.
	llmLatencyBuckets = []float64{
		0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60,
	}
	// deliveryLatencyBuckets covers outbound webhook / integration
	// delivery round-trips.
	deliveryLatencyBuckets = []float64{
		0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
	}
	// recompileLatencyBuckets covers feed-driven policy recompiles,
	// which fan out across ALL active tenants (per-tenant DB read,
	// graph parse, IOC compilation, Ed25519 bundle signing). A fleet
	// with hundreds of tenants can take minutes, so the buckets run
	// from sub-second (a near-empty deployment) up to 10 minutes,
	// keeping percentile / SLO calculations meaningful instead of
	// collapsing everything past 30s into +Inf.
	recompileLatencyBuckets = []float64{
		0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
	}
)

// Metrics owns the control-plane Prometheus registry and every
// exported metric. It is safe for concurrent use: all underlying
// prometheus collectors are goroutine-safe.
type Metrics struct {
	reg       *prometheus.Registry
	namespace string

	// --- HTTP ----------------------------------------------------
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestsInFlight prometheus.Gauge

	// --- NATS / JetStream ---------------------------------------
	NATSMessagesPublished *prometheus.CounterVec
	NATSMessagesConsumed  *prometheus.CounterVec
	NATSConsumerLag       *prometheus.GaugeVec
	NATSNak               *prometheus.CounterVec
	NATSDLQ               *prometheus.CounterVec

	// --- Postgres ------------------------------------------------
	PGPoolAcquired   prometheus.Counter
	PGPoolIdle       prometheus.Gauge
	PGPoolMax        prometheus.Gauge
	PGQueryDuration  *prometheus.HistogramVec
	PGRLSSetFailures *prometheus.CounterVec

	// --- Telemetry pipeline -------------------------------------
	TelemetryEventsReceived     *prometheus.CounterVec
	TelemetryEventsWrittenHot   *prometheus.CounterVec
	TelemetryEventsWrittenCold  *prometheus.CounterVec
	TelemetryDedupHits          *prometheus.CounterVec
	TelemetryPerTenantRateLimit *prometheus.CounterVec

	// --- Policy --------------------------------------------------
	PolicyCompilations       *prometheus.CounterVec
	PolicyBundleSignDuration prometheus.Histogram
	PolicyBundleSizeBytes    prometheus.Histogram
	PolicyRolloutState       *prometheus.GaugeVec

	// --- Rollout autopilot (WS-5 NoOps auto-promoter) ------------
	// RolloutAutopilotTransitions counts the state transitions the
	// NoOps autopilot drove without operator action, by capability and
	// kind (enrol|promote|demote). It is the proof that operator toil
	// moved: every increment is a posture change a human would otherwise
	// have had to make by hand.
	RolloutAutopilotTransitions *prometheus.CounterVec
	// RolloutAutopilotPromotionsBlocked counts promotions the autopilot
	// withheld this sweep, by capability and reason
	// (dwell|insufficient_samples|guardrail|stale_metrics). It proves the
	// guardrails are doing work — promotions are gated, not rubber-stamped.
	RolloutAutopilotPromotionsBlocked *prometheus.CounterVec

	// --- AI ------------------------------------------------------
	AILLMCalls            *prometheus.CounterVec
	AILLMLatency          *prometheus.HistogramVec
	AILLMTokensUsed       *prometheus.CounterVec
	AIGuardrailRejections *prometheus.CounterVec

	// --- Threat intel / IOC feeds -------------------------------
	ThreatFeedRefreshTotal       *prometheus.CounterVec
	ThreatFeedIngestedTotal      *prometheus.CounterVec
	ThreatFeedLastSuccessTS      *prometheus.GaugeVec
	ThreatFeedStale              *prometheus.GaugeVec
	ThreatIntelStoreIOCs         *prometheus.GaugeVec
	ThreatIntelRecompileTotal    *prometheus.CounterVec
	ThreatIntelRecompileDuration prometheus.Histogram

	// --- Webhook / integration ----------------------------------
	WebhookDeliveries      *prometheus.CounterVec
	WebhookDeliveryLatency *prometheus.HistogramVec
	WebhookQueueDepth      *prometheus.GaugeVec

	// --- Per-tenant gauges --------------------------------------
	TenantActiveDevices *prometheus.GaugeVec
	TenantActiveEdges   *prometheus.GaugeVec
	TenantPolicyVersion *prometheus.GaugeVec
}

// New constructs a Metrics value, registering every collector
// against a fresh private registry. The Go runtime + process
// collectors are registered too so the scrape surface includes
// goroutine counts, GC pauses, RSS, and FD usage out of the box.
//
// New panics on a duplicate registration, which can only happen on
// a programming error (two metrics sharing a fully-qualified name)
// — the same fail-fast contract promauto provides — so the boot
// path surfaces the mistake immediately rather than silently
// dropping a metric.
func New(cfg config.Metrics) *Metrics {
	reg := prometheus.NewRegistry()
	ns := cfg.Namespace
	if ns == "" {
		ns = "sng"
	}
	f := promauto.With(reg)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: ns}),
	)

	m := &Metrics{
		reg:       reg,
		namespace: ns,
	}

	// --- HTTP --------------------------------------------------------
	m.HTTPRequestDuration = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "Latency of control-plane HTTP requests, by method, normalised route, and status class.",
		Buckets:   httpLatencyBuckets,
	}, []string{"method", "path", "status"})
	m.HTTPRequestsTotal = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "http",
		Name:      "requests_total",
		Help:      "Total control-plane HTTP requests, by method, normalised route, and status code.",
	}, []string{"method", "path", "status"})
	m.HTTPRequestsInFlight = f.NewGauge(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "http",
		Name:      "requests_in_flight",
		Help:      "Number of control-plane HTTP requests currently being served.",
	})

	// --- NATS / JetStream -------------------------------------------
	m.NATSMessagesPublished = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "nats",
		Name:      "messages_published_total",
		Help:      "Total messages published to JetStream, by stream.",
	}, []string{"stream"})
	m.NATSMessagesConsumed = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "nats",
		Name:      "messages_consumed_total",
		Help:      "Total messages consumed from JetStream, by stream and consumer.",
	}, []string{"stream", "consumer"})
	m.NATSConsumerLag = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "nats",
		Name:      "consumer_lag",
		Help:      "Pending (unacked + undelivered) messages for a JetStream consumer, by stream and consumer.",
	}, []string{"stream", "consumer"})
	m.NATSNak = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "nats",
		Name:      "nak_total",
		Help:      "Total negative acknowledgements (NAKs) issued, by stream and consumer.",
	}, []string{"stream", "consumer"})
	m.NATSDLQ = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "nats",
		Name:      "dlq_total",
		Help:      "Total messages routed to a dead-letter queue, by stream.",
	}, []string{"stream"})

	// --- Postgres ----------------------------------------------------
	m.PGPoolAcquired = f.NewCounter(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "pg",
		Name:      "pool_acquired_total",
		Help:      "Cumulative count of connections acquired from the pgx pool.",
	})
	m.PGPoolIdle = f.NewGauge(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "pg",
		Name:      "pool_idle",
		Help:      "Idle connections currently in the pgx pool.",
	})
	m.PGPoolMax = f.NewGauge(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "pg",
		Name:      "pool_max",
		Help:      "Maximum size of the pgx pool.",
	})
	m.PGQueryDuration = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "pg",
		Name:      "query_duration_seconds",
		Help:      "Latency of Postgres queries, by logical operation.",
		Buckets:   queryLatencyBuckets,
	}, []string{"operation"})
	m.PGRLSSetFailures = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "pg",
		Name:      "rls_set_failures_total",
		Help:      "Total failures to set the per-request RLS tenant GUC, by reason.",
	}, []string{"reason"})

	// --- Telemetry pipeline -----------------------------------------
	m.TelemetryEventsReceived = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "telemetry",
		Name:      "events_received_total",
		Help:      "Total telemetry events received from the ingest stream, by event kind.",
	}, []string{"kind"})
	m.TelemetryEventsWrittenHot = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "telemetry",
		Name:      "events_written_hot_total",
		Help:      "Total telemetry events written to the hot (ClickHouse) sink, by outcome.",
	}, []string{"outcome"})
	m.TelemetryEventsWrittenCold = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "telemetry",
		Name:      "events_written_cold_total",
		Help:      "Total telemetry events written to the cold (S3) archive, by outcome.",
	}, []string{"outcome"})
	m.TelemetryDedupHits = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "telemetry",
		Name:      "dedup_hits_total",
		Help:      "Total telemetry events suppressed by the dedup window, by event kind.",
	}, []string{"kind"})
	m.TelemetryPerTenantRateLimit = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "telemetry",
		Name:      "per_tenant_rate_limited_total",
		Help:      "Total telemetry events dropped by the per-tenant ingest rate limiter, by tenant.",
	}, []string{"tenant"})

	// --- Policy ------------------------------------------------------
	m.PolicyCompilations = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "policy",
		Name:      "compilations_total",
		Help:      "Total policy-graph compilations, by outcome.",
	}, []string{"outcome"})
	m.PolicyBundleSignDuration = f.NewHistogram(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "policy",
		Name:      "bundle_sign_duration_seconds",
		Help:      "Latency of Ed25519 signed-bundle production.",
		Buckets:   signLatencyBuckets,
	})
	m.PolicyBundleSizeBytes = f.NewHistogram(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "policy",
		Name:      "bundle_size_bytes",
		Help:      "Size in bytes of produced signed policy bundles.",
		Buckets:   bundleSizeBuckets,
	})
	m.PolicyRolloutState = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "policy",
		Name:      "rollout_state",
		Help:      "Current policy rollout state per tenant, encoded as an integer state code.",
	}, []string{"tenant"})
	m.RolloutAutopilotTransitions = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "rollout_autopilot",
		Name:      "transitions_total",
		Help:      "NoOps autopilot state transitions driven without operator action, by capability and kind (enrol|promote|demote).",
	}, []string{"capability", "kind"})
	m.RolloutAutopilotPromotionsBlocked = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "rollout_autopilot",
		Name:      "promotions_blocked_total",
		Help:      "NoOps autopilot promotions withheld this sweep, by capability and reason (dwell|insufficient_samples|guardrail|stale_metrics).",
	}, []string{"capability", "reason"})

	// --- AI ----------------------------------------------------------
	m.AILLMCalls = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "ai",
		Name:      "llm_calls_total",
		Help:      "Total LLM calls, by provider, model, and outcome.",
	}, []string{"provider", "model", "outcome"})
	m.AILLMLatency = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "ai",
		Name:      "llm_latency_seconds",
		Help:      "Latency of LLM calls, by provider and model.",
		Buckets:   llmLatencyBuckets,
	}, []string{"provider", "model"})
	m.AILLMTokensUsed = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "ai",
		Name:      "llm_tokens_used_total",
		Help:      "Total LLM tokens consumed, by provider, model, and token kind (prompt|completion).",
	}, []string{"provider", "model", "kind"})
	m.AIGuardrailRejections = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "ai",
		Name:      "guardrail_rejections_total",
		Help:      "Total AI requests rejected by a guardrail, by reason.",
	}, []string{"reason"})

	// --- Threat intel / IOC feeds -----------------------------------
	m.ThreatFeedRefreshTotal = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "feed_refresh_total",
		Help:      "Total threat-feed refresh attempts, by feed and result (success|error).",
	}, []string{"feed", "result"})
	m.ThreatFeedIngestedTotal = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "feed_ingested_total",
		Help:      "Total indicators added or updated in the IOC store, by feed.",
	}, []string{"feed"})
	m.ThreatFeedLastSuccessTS = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "feed_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful refresh, by feed (0 if never).",
	}, []string{"feed"})
	m.ThreatFeedStale = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "feed_stale",
		Help:      "1 if a feed has not refreshed successfully within its staleness window, else 0, by feed.",
	}, []string{"feed"})
	m.ThreatIntelStoreIOCs = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "store_iocs",
		Help:      "Active (non-expired) indicators in the shared IOC store, by type (domain|ip|url|hash).",
	}, []string{"type"})
	m.ThreatIntelRecompileTotal = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "recompile_total",
		Help:      "Total feed-driven policy recompiles, by outcome (success|error).",
	}, []string{"outcome"})
	m.ThreatIntelRecompileDuration = f.NewHistogram(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "threatintel",
		Name:      "recompile_duration_seconds",
		Help:      "Latency of feed-driven policy recompiles across all tenants.",
		Buckets:   recompileLatencyBuckets,
	})

	// --- Webhook / integration --------------------------------------
	m.WebhookDeliveries = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: "webhook",
		Name:      "deliveries_total",
		Help:      "Total outbound deliveries, by integration kind and status.",
	}, []string{"kind", "status"})
	m.WebhookDeliveryLatency = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: "webhook",
		Name:      "delivery_latency_seconds",
		Help:      "Latency of outbound deliveries, by integration kind.",
		Buckets:   deliveryLatencyBuckets,
	}, []string{"kind"})
	m.WebhookQueueDepth = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "webhook",
		Name:      "queue_depth",
		Help:      "Pending undelivered items in the outbound delivery queue, by integration kind.",
	}, []string{"kind"})

	// --- Per-tenant gauges ------------------------------------------
	m.TenantActiveDevices = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "tenant",
		Name:      "active_devices",
		Help:      "Active enrolled devices per tenant.",
	}, []string{"tenant"})
	m.TenantActiveEdges = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "tenant",
		Name:      "active_edges",
		Help:      "Active edge / site enforcers per tenant.",
	}, []string{"tenant"})
	m.TenantPolicyVersion = f.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: "tenant",
		Name:      "policy_version",
		Help:      "Currently distributed policy version per tenant.",
	}, []string{"tenant"})

	return m
}

// Registry returns the underlying Prometheus registry. Exposed so
// callers (e.g. background collectors that register their own
// collectors, or tests that gather the exposition) can reach it.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.reg
}

// Namespace returns the configured metric namespace prefix.
func (m *Metrics) Namespace() string { return m.namespace }

// Handler returns the HTTP handler that serves the Prometheus
// exposition for this Metrics value's private registry. It is
// mounted on the internal-only metrics listener (see
// cmd/sng-control), never on the public API mux.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		// Surface collection errors to the scraper rather than
		// silently emitting a partial body, so a broken collector
		// is visible as a failed scrape.
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
}
