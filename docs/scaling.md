# Scaling ShieldNet Gateway

This document describes how the SNG control plane scales across its three
stateful dependencies — **PostgreSQL** (tenant/config/policy system of
record), **ClickHouse** (hot telemetry analytics), and **NATS JetStream**
(the sole telemetry bus) — and gives concrete sizing for the 1K / 2.5K /
5K tenant tiers.

Every knob referenced here is a real environment variable parsed by
[`internal/config/config.go`](../internal/config/config.go). The sizing
numbers are reproduced by the deterministic capacity-planning model in
[`bench/controlplane`](../bench/controlplane) — regenerate them with:

```bash
go run ./bench/controlplane capacity-plan --tenants 5000 --out /tmp/plan
```

The model is analytical (a pure transform over the config), so it needs
no live dependencies and is safe to run in CI. Treat its output as a
planning aid, not a substitute for load testing a real cluster.

---

## 1. The scaling axes at a glance

| Dependency | Bottleneck at scale | Primary lever | Secondary lever |
|------------|---------------------|---------------|-----------------|
| PostgreSQL | Connection-pool / `max_connections` pressure | `PG_PGBOUNCER_MODE` (transaction pooling) | `PG_READ_REPLICA_HOSTS`, then Citus sharding |
| ClickHouse | "Too many parts" from frequent small inserts | `CLICKHOUSE_BATCH_SIZE` (rows per part) | `CLICKHOUSE_SHARDING` |
| NATS JetStream | Subject cardinality + stream storage | `NATS_PARTITIONS` (1–256) | clustering + `NATS_REPLICAS` |

The platform is designed so each axis scales **independently**: telemetry
volume (ClickHouse + NATS) grows with traffic, while the Postgres system
of record grows with the *number* of tenants and operators, not their
traffic. The telemetry event rate never touches Postgres.

---

## 2. PostgreSQL

### 2.1 Scaling path

```
single primary
   └─ + read replicas         (PG_READ_REPLICA_HOSTS, PG_READ_REPLICA_PORT)
        └─ + PgBouncer        (PG_PGBOUNCER_MODE=true)
             └─ + Citus sharding   (horizontal, for >5K tenants)
```

1. **Single primary.** The default. All reads and writes hit one
   instance. Fine up to the point where either pool pressure or read
   load on analytical endpoints (tenant lists, audit queries) starts to
   compete with write latency.
2. **Read replicas.** Set `PG_READ_REPLICA_HOSTS` to a comma-separated
   list of replica hosts (and `PG_READ_REPLICA_PORT` if they listen on a
   non-primary port; `0` inherits `PG_PORT`). The runtime routes
   read-only transactions to replicas and keeps writes on the primary.
   This offloads dashboard/list/report traffic from the writer.
3. **PgBouncer.** Set `PG_PGBOUNCER_MODE=true` to run against a
   transaction-pooling PgBouncer. The app keeps its own pool
   (`PG_MAX_OPEN_CONNS` per replica) but PgBouncer multiplexes those onto
   a much smaller set of *backend* connections, so the Postgres server's
   `max_connections` is no longer the binding constraint as you add
   `sng-control` replicas. In transaction-pooling mode the runtime
   disables server-side prepared-statement caching (incompatible with
   transaction pooling) — this is handled automatically when the flag is
   set.
4. **Citus sharding.** Beyond ~5K tenants, shard by `tenant_id`. Tenant
   isolation is already enforced by Row-Level Security keyed on the
   `sng.tenant_id` GUC, so the data model is shard-ready: the shard key
   is the same column RLS already filters on.

### 2.2 `PG_MAX_OPEN_CONNS` tuning

`PG_MAX_OPEN_CONNS` (default **20**) is the **per-replica** app pool
ceiling. The pool only needs to cover *concurrent in-flight queries*,
which by Little's law is:

```
peak_concurrent_queries = control_plane_rps × avg_query_seconds
```

The control-plane API rate scales with the fleet (~0.5 req/s per tenant
in the model: operator dashboards, policy edits, agent enrolment/config
polling), and the mean query is a few milliseconds. So the pool you
actually need is small, and over-provisioning it just multiplies backend
connections (`replicas × PG_MAX_OPEN_CONNS`) against `max_connections`.

Rules of thumb:

- Size `PG_MAX_OPEN_CONNS` to **~2× the modelled peak concurrency per
  replica**, not higher. The default of 20 already carries the 5K tier
  with headroom.
- With PgBouncer **off**, `replicas × PG_MAX_OPEN_CONNS` must stay below
  the server's `max_connections`. This is the constraint that pushes you
  to PgBouncer as you add replicas.
- With PgBouncer **on**, backend connections are bounded by the pooler,
  not the app-pool sum — scale `sng-control` replicas freely.
- Keep `PG_MIN_CONNS` (default 2) low; idle warm connections are cheap
  insurance against cold-start latency, not a throughput lever.

### 2.3 Sizing

Derived from `capacity-plan` (3 `sng-control` replicas, `PG_MAX_OPEN_CONNS=20`,
PgBouncer on, `max_connections=200`):

| Tenants | Control-plane RPS | Peak concurrent queries | Recommended pool/replica | Backend conns (PgBouncer) | Within `max_connections`? |
|--------:|------------------:|------------------------:|-------------------------:|--------------------------:|:-------------------------:|
| 1,000   | 500   | 2.0  | 1 | 15 | yes |
| 2,500   | 1,250 | 5.0  | 3 | 15 | yes |
| 5,000   | 2,500 | 10.0 | 5 | 15 | yes |

The headline takeaway: Postgres connection pressure is **not** the
scaling wall for this workload — a single primary with PgBouncer and the
default pool comfortably carries 5K tenants. Read replicas are about
isolating analytical read latency, not raw connection capacity.

---

## 3. ClickHouse

### 3.1 Scaling path

```
single node
   └─ + larger batches      (CLICKHOUSE_BATCH_SIZE)
        └─ + sharding        (CLICKHOUSE_SHARDING)
             └─ + Keeper cluster   (HA coordination for multi-replica shards)
```

The hot path writes one row per telemetry event across the **7 event
classes** (`flow, dns, http, ips, ztna, sdwan, agent`). Rows are buffered
and flushed in batches of `CLICKHOUSE_BATCH_SIZE` (default **1024**) or
every `CLICKHOUSE_FLUSH_INTERVAL` (default **2s**), whichever comes
first.

### 3.2 The real bottleneck: parts, not throughput

ClickHouse ingests millions of rows/sec per node without breaking a
sweat. Its dominant *write-side* failure mode is **"too many parts"**:
every `INSERT` creates a part, and a high part-creation rate starves the
background merge scheduler. The healthy target is **≤ ~1 insert/s/shard**.

The per-shard insert frequency is:

```
inserts_per_sec_per_shard = rows_per_sec_per_shard / CLICKHOUSE_BATCH_SIZE
```

So the **primary lever is a larger `CLICKHOUSE_BATCH_SIZE`** (more rows
per part), *not* more shards. Sharding multiplies hardware cost and is
only the right answer once a single shard would need a batch larger than
is reasonable for insert latency / writer memory (the model caps this at
65,536 rows; beyond that it recommends `CLICKHOUSE_SHARDING`).

`CLICKHOUSE_MAX_BACKLOG_MULTIPLIER` (default 4) bounds how far the writer
may fall behind before shedding; it is a safety valve, not a throughput
knob.

### 3.3 Sizing

Derived from `capacity-plan` (2 shards, 256 B/event uncompressed, 8×
columnar compression):

| Tenants | Rows/s total | Rows/s/shard | Inserts/s/shard @ 1024 | Recommended batch | Hot storage/mo (compressed) |
|--------:|-------------:|-------------:|-----------------------:|------------------:|----------------------------:|
| 1,000   | 5,300  | 2,650  | 2.59  | 2,650  | ~440 GB   |
| 2,500   | 13,250 | 6,625  | 6.47  | 6,625  | ~1,099 GB |
| 5,000   | 26,500 | 13,250 | 12.94 | 13,250 | ~2,198 GB |

At every tier the default 1024-row batch produces an unhealthy insert
frequency; the fix is to raise `CLICKHOUSE_BATCH_SIZE` to roughly the
per-shard row rate (so each shard inserts ~once/second), which all three
tiers can do without adding shards. Add shards (`CLICKHOUSE_SHARDING`)
only when the per-shard row rate would require a batch above ~65K rows.

Hot-storage retention is 30–90 days (see `docs/cost-model.md` for the
cost rollup); older data lands in the S3 cold archive.

---

## 4. NATS JetStream

### 4.1 Scaling path

```
single stream
   └─ + clustering          (NATS_REPLICAS for quorum durability)
        └─ + partitioning    (NATS_PARTITIONS, 1–256)
```

Telemetry is published to subjects of the form
`sng.<partition>.<tenant>.telemetry.<class>`. Tenants are mapped to a
partition by an FNV-1a hash of the tenant ID, so a given tenant's
traffic always lands on the same partition (ordering preserved
per-tenant).

### 4.2 `NATS_PARTITIONS` tuning

`NATS_PARTITIONS` (default **1**, max **256**) fans the telemetry stream
out into N independent streams, each owning a hash-slice of tenants.
This is the lever for:

- **Subject cardinality per stream.** Distinct subjects =
  `tenants × classes`. Spreading them across partitions keeps any single
  stream's subject table (and its consumer fan-out) bounded.
- **Write parallelism.** Each partition is an independent JetStream
  stream with its own storage and consumers.

Because tenant→partition mapping is a hash, the distribution is even but
not perfectly uniform; the model accounts for ~15% skew on the busiest
partition. `NATS_REPLICAS` (default 1) sets the quorum replication factor
per stream for durability — orthogonal to partition count.

### 4.3 Sizing

Derived from `capacity-plan` (16 partitions, 24h hot retention):

| Tenants | Distinct subjects | Subjects/partition (avg) | Busiest partition | Msgs/s | Hot stream storage (24h) |
|--------:|------------------:|-------------------------:|------------------:|-------:|-------------------------:|
| 1,000   | 7,000  | 437.5   | ~504   | 5,300  | ~146 GB |
| 2,500   | 17,500 | 1,093.8 | ~1,258 | 13,250 | ~366 GB |
| 5,000   | 35,000 | 2,187.5 | ~2,516 | 26,500 | ~733 GB |

16 partitions keep per-partition subject cardinality well within a
healthy envelope through 5K tenants. The hot stream storage figure is
the steady-state retention footprint for the chosen window; shrink
`NATS` retention or raise `NATS_PARTITIONS` if a single stream's file
store grows uncomfortably large.

---

## 5. Putting it together: the 5K-tenant reference

| Component | Configuration | Rationale |
|-----------|---------------|-----------|
| `sng-control` | 3+ replicas behind HPA | Stateless; scale on CPU / request rate |
| PostgreSQL | 1 primary + 1–2 read replicas, PgBouncer on, `PG_MAX_OPEN_CONNS=20` | Connection pressure is not the wall; replicas isolate analytical reads |
| ClickHouse | 2 shards, `CLICKHOUSE_BATCH_SIZE≈13000` | Batch sizing (not sharding) keeps the merge tree healthy |
| NATS | clustered, `NATS_PARTITIONS=16`, `NATS_REPLICAS=3` | Bounds subject cardinality and gives quorum durability |

Regenerate any of these numbers for a different tier or knob set with
`go run ./bench/controlplane capacity-plan --tenants N [--ch-shards N]
[--nats-partitions N]`. Cost projections built on the same model live in
[`docs/cost-model.md`](./cost-model.md).
