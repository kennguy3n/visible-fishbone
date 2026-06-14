package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DefaultAIPoolScrapeInterval is how often the shared-inference-pool
// collector samples the pool snapshot. 15s matches the Postgres pool
// collector and a typical Prometheus scrape cadence.
const DefaultAIPoolScrapeInterval = 15 * time.Second

// AIPoolSnapshot is the metrics-package view of the WS-9 shared
// inference pool's counters. It is a plain value type so the metrics
// package stays decoupled from internal/service/ai: the caller adapts
// the pool's own snapshot onto this struct (mirroring the
// metricsFeedObserver adapter pattern), and the pool stays unaware of
// Prometheus.
type AIPoolSnapshot struct {
	Inflight     int64
	PeakInflight int64
	Queued       int64
	PeakQueued   int64
	Admitted     int64
	Completed    int64
	Errors       int64
	Rejected     int64
	WaitTimeouts int64
	Cancelled    int64
	AvgWaitMS    float64
}

// AIPoolSource yields a point-in-time snapshot of the shared inference
// pool. *ai.InferencePool is adapted onto this in cmd/sng-control.
type AIPoolSource interface {
	AIPoolSnapshot() AIPoolSnapshot
}

// AIPoolCollector periodically mirrors an AIPoolSource snapshot onto
// the pool gauges. It exists so operators can watch the fleet-scale
// efficiency curve directly: peak_inflight pinned at the concurrency
// cap (not the tenant count) with fair admission across tenants.
type AIPoolCollector struct {
	metrics  *Metrics
	src      AIPoolSource
	interval time.Duration

	// last-observed cumulative totals, used to convert ai.PoolMetrics'
	// process-cumulative snapshot into monotonic counter increments. A
	// value going backwards (pool recreated) is treated as a fresh
	// baseline rather than a negative delta.
	last AIPoolSnapshot
}

// NewAIPoolCollector builds a shared-inference-pool collector. A
// non-positive interval falls back to DefaultAIPoolScrapeInterval.
func NewAIPoolCollector(m *Metrics, src AIPoolSource, interval time.Duration) *AIPoolCollector {
	if interval <= 0 {
		interval = DefaultAIPoolScrapeInterval
	}
	return &AIPoolCollector{metrics: m, src: src, interval: interval}
}

// Run samples immediately, then every interval until ctx is cancelled.
// It blocks, so callers launch it in its own goroutine. Run is a no-op
// when the collector, its Metrics, or its source is nil so wiring can
// stay unconditional.
func (c *AIPoolCollector) Run(ctx context.Context) {
	if c == nil || c.metrics == nil || c.src == nil {
		return
	}
	c.sample()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sample()
		}
	}
}

// sample reads one snapshot and updates the gauges.
func (c *AIPoolCollector) sample() {
	c.record(c.src.AIPoolSnapshot())
}

// record applies one snapshot to the metrics. Split out from sample so
// the mapping is unit-testable without a live pool. Instantaneous state
// is Set() onto gauges; cumulative lifetime totals are Add()ed onto
// counters as the delta since the previous snapshot (a backwards jump
// re-baselines instead of producing a negative delta).
func (c *AIPoolCollector) record(s AIPoolSnapshot) {
	c.metrics.AIPoolInflight.Set(float64(s.Inflight))
	c.metrics.AIPoolPeakInflight.Set(float64(s.PeakInflight))
	c.metrics.AIPoolQueued.Set(float64(s.Queued))
	c.metrics.AIPoolPeakQueued.Set(float64(s.PeakQueued))
	c.metrics.AIPoolAvgWaitMS.Set(s.AvgWaitMS)

	addDelta(c.metrics.AIPoolAdmitted, s.Admitted, &c.last.Admitted)
	addDelta(c.metrics.AIPoolCompleted, s.Completed, &c.last.Completed)
	addDelta(c.metrics.AIPoolErrors, s.Errors, &c.last.Errors)
	addDelta(c.metrics.AIPoolRejected, s.Rejected, &c.last.Rejected)
	addDelta(c.metrics.AIPoolWaitTimeouts, s.WaitTimeouts, &c.last.WaitTimeouts)
	addDelta(c.metrics.AIPoolCancelled, s.Cancelled, &c.last.Cancelled)
}

// addDelta advances a counter by cur-*last and records cur as the new
// baseline. If cur dropped below the baseline (a process-cumulative
// source reset, e.g. the pool was recreated), it re-baselines without
// emitting a negative delta.
func addDelta(c prometheus.Counter, cur int64, last *int64) {
	if cur > *last {
		c.Add(float64(cur - *last))
	}
	*last = cur
}
