package metrics

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// DefaultConsumerScrapeInterval is how often the JetStream
// collector polls consumer info for lag. 15s matches the Postgres
// collector and a typical scrape cadence.
const DefaultConsumerScrapeInterval = 15 * time.Second

// streamLister is the subset of jetstream.JetStream the NATS
// collector depends on. Narrowed to an interface so the collector
// is decoupled from the full client surface (and so the lag-math
// helper can be unit-tested without a live server).
type streamLister interface {
	Stream(ctx context.Context, stream string) (jetstream.Stream, error)
}

// NATSCollector periodically queries JetStream consumer info for a
// fixed set of streams and mirrors per-consumer pending/lag onto
// the Prometheus gauges. Streams that do not exist yet (e.g. a
// consumer not provisioned in a given deployment) are skipped
// silently rather than treated as errors, so the collector is
// robust to partial stream sets.
type NATSCollector struct {
	metrics  *Metrics
	js       streamLister
	streams  []string
	interval time.Duration
	logger   *slog.Logger

	// tracked records the (stream, consumer) label pairs currently
	// present on the consumer_lag gauge so that series for consumers
	// that disappear can be deleted, preventing unbounded stale
	// series. Only ever touched from the single Run goroutine, so no
	// synchronisation is required.
	tracked map[[2]string]struct{}
}

// NewNATSCollector builds a JetStream consumer-lag collector for
// the named streams. A non-positive interval falls back to
// DefaultConsumerScrapeInterval; a nil logger falls back to
// slog.Default.
func NewNATSCollector(m *Metrics, js jetstream.JetStream, streams []string, interval time.Duration, logger *slog.Logger) *NATSCollector {
	if interval <= 0 {
		interval = DefaultConsumerScrapeInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &NATSCollector{
		metrics:  m,
		js:       js,
		streams:  streams,
		interval: interval,
		logger:   logger,
		tracked:  make(map[[2]string]struct{}),
	}
}

// Run samples consumer info immediately, then every interval until
// the context is cancelled. Blocks; callers launch it in its own
// goroutine. No-op when the collector, its Metrics, or its
// JetStream handle is nil.
func (c *NATSCollector) Run(ctx context.Context) {
	if c == nil || c.metrics == nil || c.js == nil {
		return
	}
	c.sample(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sample(ctx)
		}
	}
}

// sample walks every configured stream's consumers and updates the
// consumer_lag gauge. Per-stream errors are logged at debug and do
// not abort the sweep so one missing stream cannot blind the rest.
//
// After the sweep it prunes gauge series for consumers that have
// disappeared so removed consumers do not leave a stale lag value
// behind forever. To avoid flapping, a series is only pruned when
// its stream was actually scraped this round: a transient lookup
// or iteration error leaves that stream's series untouched, while a
// stream that no longer exists (ErrStreamNotFound) counts as
// scraped-with-zero-consumers so its orphaned series are removed.
func (c *NATSCollector) sample(ctx context.Context) {
	seen := make(map[[2]string]struct{})
	scraped := make(map[string]struct{})

	for _, name := range c.streams {
		stream, err := c.js.Stream(ctx, name)
		if err != nil {
			if errors.Is(err, jetstream.ErrStreamNotFound) {
				// The stream is genuinely gone; treat it as scraped
				// so any series it used to own are pruned below.
				scraped[name] = struct{}{}
			} else {
				c.logger.Debug("metrics: jetstream stream lookup failed",
					slog.String("stream", name), slog.Any("error", err))
			}
			continue
		}
		lister := stream.ListConsumers(ctx)
		for info := range lister.Info() {
			key := [2]string{info.Stream, info.Name}
			seen[key] = struct{}{}
			c.metrics.NATSConsumerLag.
				WithLabelValues(info.Stream, info.Name).
				Set(float64(consumerLag(info)))
		}
		if err := lister.Err(); err != nil {
			c.logger.Debug("metrics: jetstream consumer iteration error",
				slog.String("stream", name), slog.Any("error", err))
			// Incomplete listing: do not prune this stream's series.
			continue
		}
		scraped[name] = struct{}{}
	}

	c.prune(seen, scraped)
}

// prune deletes consumer_lag series whose (stream, consumer) pair
// was tracked previously but not seen this round, restricted to
// streams that were successfully scraped so transient errors do not
// cause series to flap.
func (c *NATSCollector) prune(seen map[[2]string]struct{}, scraped map[string]struct{}) {
	for key := range c.tracked {
		if _, ok := seen[key]; ok {
			continue
		}
		if _, ok := scraped[key[0]]; !ok {
			continue
		}
		c.metrics.NATSConsumerLag.DeleteLabelValues(key[0], key[1])
		delete(c.tracked, key)
	}
	for key := range seen {
		c.tracked[key] = struct{}{}
	}
}

// consumerLag returns the number of messages a consumer still owes
// work for: messages matched but not yet delivered (NumPending)
// plus messages delivered but not yet acked (NumAckPending). This
// is the operationally meaningful "how far behind" figure an
// operator alerts on.
func consumerLag(info *jetstream.ConsumerInfo) uint64 {
	if info == nil {
		return 0
	}
	return info.NumPending + uint64(info.NumAckPending)
}
