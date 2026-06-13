package metrics

import (
	"context"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/activity"
)

// DefaultActivityScrapeInterval is how often the activity collector
// samples the recorder's stats. It matches DefaultPoolScrapeInterval
// (and a typical Prometheus scrape cadence) so the touch counters are
// never more than one scrape stale.
const DefaultActivityScrapeInterval = 15 * time.Second

// ActivityStatter is the slice of activity.Recorder the collector
// depends on. Declared as an interface so a test can drive the loop
// with a fabricated Stats snapshot rather than a live recorder.
type ActivityStatter interface {
	Stats() activity.Stats
	QueueLen() int
}

// ActivityCollector periodically samples the activity recorder's
// per-source counters and mirrors them onto the Prometheus
// touches_total counter. activity.Recorder exposes its counters as
// process-cumulative totals, so the collector converts them into
// monotonic counter increments by tracking the last observed value per
// (source, outcome); a value going backwards (a fresh recorder) is
// treated as a new baseline rather than a negative delta. The queue
// depth is a point-in-time gauge, set directly.
type ActivityCollector struct {
	metrics  *Metrics
	rec      ActivityStatter
	interval time.Duration

	// last holds the previous cumulative value per (source, outcome) so
	// deltas stay monotonic across scrapes.
	last map[sourceOutcome]uint64
}

// sourceOutcome keys the last-observed-value map by the two label
// dimensions of touches_total.
type sourceOutcome struct {
	source  activity.Source
	outcome string
}

// outcome label values for touches_total.
const (
	outcomeEnqueued  = "enqueued"
	outcomeDebounced = "debounced"
	outcomeDropped   = "dropped"
	outcomeWritten   = "written"
	outcomeFailed    = "failed"
)

// NewActivityCollector builds an activity-recorder collector. A
// non-positive interval falls back to DefaultActivityScrapeInterval.
func NewActivityCollector(m *Metrics, rec ActivityStatter, interval time.Duration) *ActivityCollector {
	if interval <= 0 {
		interval = DefaultActivityScrapeInterval
	}
	return &ActivityCollector{
		metrics:  m,
		rec:      rec,
		interval: interval,
		last:     make(map[sourceOutcome]uint64),
	}
}

// Run samples immediately, then every interval until the context is
// cancelled. It blocks, so callers typically launch it in its own
// goroutine. Run is a no-op when the collector, its Metrics, or its
// recorder is nil so wiring can stay unconditional.
func (c *ActivityCollector) Run(ctx context.Context) {
	if c == nil || c.metrics == nil || c.rec == nil {
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

// sample reads one Stats snapshot + the queue depth and applies them.
func (c *ActivityCollector) sample() {
	c.record(c.rec.Stats(), c.rec.QueueLen())
}

// record applies one Stats snapshot to the metrics. Split out from
// sample so the counter-delta logic is unit-testable with a fabricated
// snapshot. Per-source cumulative totals are converted into monotonic
// counter increments; the queue depth is set as a gauge.
func (c *ActivityCollector) record(s activity.Stats, queueLen int) {
	for src, st := range s.BySource {
		c.add(src, outcomeEnqueued, st.Enqueued)
		c.add(src, outcomeDebounced, st.Debounced)
		c.add(src, outcomeDropped, st.Dropped)
		c.add(src, outcomeWritten, st.Written)
		c.add(src, outcomeFailed, st.Failed)
	}
	c.metrics.ActivityQueueDepth.Set(float64(queueLen))
}

// add converts a cumulative total for one (source, outcome) into a
// monotonic counter increment, tracking the last observed value. A
// total that went backwards (recorder replaced) re-baselines rather
// than emitting a negative delta.
func (c *ActivityCollector) add(src activity.Source, outcome string, total uint64) {
	key := sourceOutcome{source: src, outcome: outcome}
	prev := c.last[key]
	if total >= prev {
		if delta := total - prev; delta > 0 {
			c.metrics.ActivityTouches.WithLabelValues(string(src), outcome).Add(float64(delta))
		}
	}
	c.last[key] = total
}
