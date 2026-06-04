package metrics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultPoolScrapeInterval is how often the Postgres pool
// collector samples pgxpool.Stat(). 15s matches a typical
// Prometheus scrape cadence so the gauges are never more than one
// scrape stale.
const DefaultPoolScrapeInterval = 15 * time.Second

// PoolStatter is the slice of *pgxpool.Pool the collector depends
// on. Declared as an interface so tests can drive the loop with a
// fake Stat() rather than standing up a real pool.
type PoolStatter interface {
	Stat() *pgxpool.Stat
}

// PGCollector periodically samples a pgx pool's statistics and
// mirrors them onto the Prometheus gauges. pgxpool exposes the
// acquire count as a cumulative total; the collector converts it
// into monotonic counter increments by tracking the last observed
// value, so a pool reset (count going backwards) is treated as a
// fresh baseline rather than producing a negative delta.
type PGCollector struct {
	metrics  *Metrics
	pool     PoolStatter
	interval time.Duration

	lastAcquire int64
}

// NewPGCollector builds a Postgres pool collector. A non-positive
// interval falls back to DefaultPoolScrapeInterval.
func NewPGCollector(m *Metrics, pool PoolStatter, interval time.Duration) *PGCollector {
	if interval <= 0 {
		interval = DefaultPoolScrapeInterval
	}
	return &PGCollector{metrics: m, pool: pool, interval: interval}
}

// Run samples the pool immediately, then every interval until the
// context is cancelled. It blocks, so callers typically launch it
// in its own goroutine. Run is a no-op when the collector, its
// Metrics, or its pool is nil so wiring can stay unconditional.
func (c *PGCollector) Run(ctx context.Context) {
	if c == nil || c.metrics == nil || c.pool == nil {
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

// sample reads one pgxpool.Stat snapshot and updates the gauges +
// the acquire counter.
func (c *PGCollector) sample() {
	st := c.pool.Stat()
	if st == nil {
		return
	}
	c.record(st.AcquireCount(), st.IdleConns(), st.MaxConns())
}

// record applies one statistics snapshot to the metrics. Split out
// from sample so the counter-delta logic is unit-testable without
// fabricating an (unconstructable) *pgxpool.Stat. pgxpool reports
// AcquireCount as a process-cumulative total, so it is converted
// into monotonic prometheus.Counter increments by tracking the
// last observed value; a value going backwards (pool recreated) is
// treated as a fresh baseline rather than a negative delta.
func (c *PGCollector) record(acquired int64, idle, maxConns int32) {
	if acquired >= c.lastAcquire {
		if delta := acquired - c.lastAcquire; delta > 0 {
			c.metrics.PGPoolAcquired.Add(float64(delta))
		}
	}
	c.lastAcquire = acquired

	c.metrics.PGPoolIdle.Set(float64(idle))
	c.metrics.PGPoolMax.Set(float64(maxConns))
}
