package metrics

import (
	"context"
	"time"
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

// record applies one snapshot to the gauges. Split out from sample so
// the mapping is unit-testable without a live pool.
func (c *AIPoolCollector) record(s AIPoolSnapshot) {
	c.metrics.AIPoolInflight.Set(float64(s.Inflight))
	c.metrics.AIPoolPeakInflight.Set(float64(s.PeakInflight))
	c.metrics.AIPoolQueued.Set(float64(s.Queued))
	c.metrics.AIPoolPeakQueued.Set(float64(s.PeakQueued))
	c.metrics.AIPoolAdmitted.Set(float64(s.Admitted))
	c.metrics.AIPoolCompleted.Set(float64(s.Completed))
	c.metrics.AIPoolErrors.Set(float64(s.Errors))
	c.metrics.AIPoolRejected.Set(float64(s.Rejected))
	c.metrics.AIPoolWaitTimeouts.Set(float64(s.WaitTimeouts))
	c.metrics.AIPoolCancelled.Set(float64(s.Cancelled))
	c.metrics.AIPoolAvgWaitMS.Set(s.AvgWaitMS)
}
