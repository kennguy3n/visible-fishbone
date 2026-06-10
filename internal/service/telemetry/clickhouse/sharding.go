package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/stats"
)

// ShardedWriter fans telemetry writes across N independent
// ClickHouse shards, one per endpoint in the configured endpoint
// list. It is the horizontal-scaling answer to the single-node
// ingest/storage ceiling the platform hits past ~5,000 tenants:
// instead of every row landing on one cluster, each tenant is
// pinned to exactly one shard by a stable hash of its tenant_id, so
// ingest throughput and on-disk footprint scale linearly with shard
// count.
//
// Each shard is a full *Writer with its own batch buffer, flush
// loop, backlog cap, and retention cache — so a slow or briefly
// unavailable shard back-pressures and sheds only its own tenants'
// rows, never the whole fleet's. Per-tenant reads route to the
// owning shard; cross-tenant operator analytics fan out across all
// shards in parallel and merge.
//
// ShardedWriter satisfies telemetry.HotWriter (via Write) and
// handler.TelemetryClassQuerier (via QueryTrafficClassDistribution),
// so it is a drop-in replacement for a single *Writer on those
// paths.
type ShardedWriter struct {
	shards []*Writer
	logger *slog.Logger
}

// NewShardedWriter constructs one *Writer per endpoint in
// cfg.Endpoints, each pinned to that single endpoint (so the
// clickhouse-go driver does not load-balance a shard's writes
// across what are meant to be distinct shards). All other Config
// fields are shared verbatim across shards. If any shard fails to
// come up, the shards already started are stopped before returning
// so the constructor leaks no flush goroutines or connections.
func NewShardedWriter(ctx context.Context, cfg Config, logger *slog.Logger) (*ShardedWriter, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("clickhouse: sharded writer needs at least one endpoint")
	}
	if logger == nil {
		logger = slog.Default()
	}
	shards := make([]*Writer, 0, len(cfg.Endpoints))
	for i, ep := range cfg.Endpoints {
		shardCfg := cfg
		// Pin this shard to a single endpoint — the whole point of
		// sharding is that a tenant's rows always land on the same
		// node, so we must not hand the driver the full endpoint
		// list (which it would treat as interchangeable replicas).
		shardCfg.Endpoints = []string{ep}
		w, err := New(ctx, shardCfg, logger.With(
			slog.Int("shard", i),
			slog.String("shard_endpoint", ep),
		))
		if err != nil {
			stopShards(ctx, shards)
			return nil, fmt.Errorf("clickhouse: open shard %d (%s): %w", i, ep, err)
		}
		shards = append(shards, w)
	}
	return &ShardedWriter{shards: shards, logger: logger}, nil
}

// ShardCount returns the number of shards.
func (s *ShardedWriter) ShardCount() int { return len(s.shards) }

// Shards returns the per-shard writers so the telemetry autotuner
// can tune each shard's batch size independently. Independent
// tuning is required, not optional: "too many parts" is a
// per-shard failure mode (each shard is a distinct ClickHouse
// cluster with its own merge scheduler) and the insert-frequency
// target is per-shard (docs/scaling.md §3.2). A single tuner
// driving an aggregate batch size would misjudge a fleet with
// skewed per-shard row rates. The returned slice is a fresh copy
// so a caller cannot reorder or mutate the shard set; the
// *Writer elements are shared (the tuner needs the live writers).
func (s *ShardedWriter) Shards() []*Writer {
	out := make([]*Writer, len(s.shards))
	copy(out, s.shards)
	return out
}

// ShardFor returns the shard index that owns tenantID.
func (s *ShardedWriter) ShardFor(tenantID uuid.UUID) int {
	return shardIndex(tenantID, len(s.shards))
}

// shardIndex maps a tenant to a shard by FNV-1a hash of the UUID's
// 16 bytes modulo n. tenant_id is a UUID rather than an integer, so
// the spec's "tenant_id % shard_count" is realised as
// hash(tenant_id) % shard_count: deterministic (a tenant always
// hashes to the same shard, which is required for per-tenant reads
// to find their data) and uniform (FNV spreads UUIDs evenly so no
// shard becomes a hot spot).
//
// Note: this hashes the raw 16 UUID bytes, whereas the NATS
// TenantPartitioner hashes the UUID's 36-char string form. The two
// are intentionally independent scaling axes (different counts, hash
// domains), so a tenant on NATS partition i will not generally land
// on ClickHouse shard i — do not assume the assignments correlate
// when correlating logs across the two subsystems.
func shardIndex(tenantID uuid.UUID, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write(tenantID[:])
	return int(h.Sum32() % uint32(n))
}

// Write routes the envelope to the shard that owns its tenant.
func (s *ShardedWriter) Write(ctx context.Context, env schema.Envelope) error {
	return s.shards[s.ShardFor(env.TenantID)].Write(ctx, env)
}

// EnsureSchema runs EnsureSchema on every shard in parallel; each
// shard is a distinct cluster and needs its own table.
func (s *ShardedWriter) EnsureSchema(ctx context.Context) error {
	return s.fanOut(func(w *Writer) error { return w.EnsureSchema(ctx) })
}

// Stop drains and closes every shard in parallel, aggregating any
// errors. Safe to call multiple times (each *Writer.Stop is).
func (s *ShardedWriter) Stop(ctx context.Context) error {
	return s.fanOut(func(w *Writer) error { return w.Stop(ctx) })
}

// Stats returns the fleet-wide writer counters: per-shard Stats
// summed, with Pending summed too so a single number reflects total
// in-memory backlog across shards.
func (s *ShardedWriter) Stats() Stats {
	var agg Stats
	for _, w := range s.shards {
		st := w.Stats()
		agg.Pending += st.Pending
		agg.Flushed += st.Flushed
		agg.Inserts += st.Inserts
		// BatchSize is per-shard; the fleet aggregate sums them so
		// the figure stays meaningful (total buffered-row headroom
		// across shards) and a single-shard deployment reports its
		// own batch size unchanged.
		agg.BatchSize += st.BatchSize
		agg.FlushErrors += st.FlushErrors
		agg.ConsecutiveErrors += st.ConsecutiveErrors
		agg.DroppedRows += st.DroppedRows
		agg.RequeuedBatches += st.RequeuedBatches
		agg.BacklogDrops += st.BacklogDrops
		agg.PartialDropFlushes += st.PartialDropFlushes
	}
	return agg
}

// QueryTrafficClassDistribution serves a per-tenant query from the
// single shard that owns the tenant — no fan-out needed since a
// tenant's rows live on exactly one shard. Implements
// handler.TelemetryClassQuerier.
func (s *ShardedWriter) QueryTrafficClassDistribution(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]stats.TrafficClassCount, error) {
	return s.shards[s.ShardFor(tenantID)].QueryTrafficClassDistribution(ctx, tenantID, since)
}

// QueryTrafficClassDistributionAllTenants serves the operator-wide
// (cross-tenant) distribution by fanning out the per-shard
// all-tenants aggregate across every shard in parallel and merging
// the per-class rows into a single platform-wide total. This is the
// query fan-out the operator dashboard relies on: because tenants
// are partitioned across shards, the only way to get a fleet total
// is to ask every shard and sum.
func (s *ShardedWriter) QueryTrafficClassDistributionAllTenants(ctx context.Context, since time.Time) ([]stats.TrafficClassCount, error) {
	results := make([][]stats.TrafficClassCount, len(s.shards))
	errs := make([]error, len(s.shards))

	var wg sync.WaitGroup
	wg.Add(len(s.shards))
	for i, w := range s.shards {
		go func(i int, w *Writer) {
			defer wg.Done()
			results[i], errs[i] = w.QueryTrafficClassDistributionAllTenants(ctx, since)
		}(i, w)
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("clickhouse: cross-shard traffic_class query: %w", err)
	}
	return mergeTrafficClassCounts(results), nil
}

// fanOut runs fn against every shard in parallel and returns the
// joined error (nil when all succeed).
func (s *ShardedWriter) fanOut(fn func(*Writer) error) error {
	errs := make([]error, len(s.shards))
	var wg sync.WaitGroup
	wg.Add(len(s.shards))
	for i, w := range s.shards {
		go func(i int, w *Writer) {
			defer wg.Done()
			errs[i] = fn(w)
		}(i, w)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// stopShards best-effort stops a partially-constructed shard set
// during a failed NewShardedWriter.
func stopShards(ctx context.Context, shards []*Writer) {
	for _, w := range shards {
		_ = w.Stop(ctx)
	}
}

// mergeTrafficClassCounts sums per-class event/byte counts across
// shard result sets and returns rows ordered by event count
// descending (matching the single-node query's ORDER BY), with the
// class label as a stable tiebreaker so the output is deterministic.
func mergeTrafficClassCounts(perShard [][]stats.TrafficClassCount) []stats.TrafficClassCount {
	byClass := make(map[string]stats.TrafficClassCount)
	for _, rows := range perShard {
		for _, row := range rows {
			agg := byClass[row.Class]
			agg.Class = row.Class
			agg.Events += row.Events
			agg.Bytes += row.Bytes
			byClass[row.Class] = agg
		}
	}
	if len(byClass) == 0 {
		return nil
	}
	out := make([]stats.TrafficClassCount, 0, len(byClass))
	for _, v := range byClass {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// ShardedReader serves per-tenant reads from the shard that owns
// each tenant. It satisfies the simulator's TelemetrySource
// contract (ListFlowEvents / ListEvents), so policy simulation works
// transparently in a sharded deployment. Build one via
// ShardedWriter.NewReader; each per-shard Reader shares that shard's
// Writer connection, so the ShardedReader's lifetime is bound to the
// ShardedWriter's (stopping the writer tears the readers down).
type ShardedReader struct {
	readers []*Reader
}

// NewReader returns a ShardedReader backed by a Reader per shard,
// each sharing its shard Writer's connection.
func (s *ShardedWriter) NewReader() (*ShardedReader, error) {
	readers := make([]*Reader, len(s.shards))
	for i, w := range s.shards {
		r, err := w.NewReader()
		if err != nil {
			return nil, fmt.Errorf("clickhouse: shard %d reader: %w", i, err)
		}
		readers[i] = r
	}
	return &ShardedReader{readers: readers}, nil
}

// readerFor returns the Reader for the shard that owns tenantID.
func (r *ShardedReader) readerFor(tenantID uuid.UUID) *Reader {
	return r.readers[shardIndex(tenantID, len(r.readers))]
}

// ListFlowEvents routes to the owning shard.
func (r *ShardedReader) ListFlowEvents(
	ctx context.Context,
	tenantID uuid.UUID,
	since, until time.Time,
	maxEvents int,
) ([]schema.Envelope, error) {
	return r.readerFor(tenantID).ListFlowEvents(ctx, tenantID, since, until, maxEvents)
}

// ListEvents routes to the owning shard.
func (r *ShardedReader) ListEvents(
	ctx context.Context,
	tenantID uuid.UUID,
	classes []schema.EventClass,
	since, until time.Time,
	maxEvents int,
) ([]schema.Envelope, error) {
	return r.readerFor(tenantID).ListEvents(ctx, tenantID, classes, since, until, maxEvents)
}
