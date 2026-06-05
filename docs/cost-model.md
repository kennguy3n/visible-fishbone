# Infrastructure Cost Model

This document models the **infrastructure** cost of running the SNG
telemetry and analytics backends at the 1K / 2.5K / 5K tenant tiers and
explains how those costs are tracked per-tenant in the metering service.

It covers the three storage / write-amplification drivers that the
per-request meters (LLM, URL categorisation, malware scans, egress) do
**not** capture:

1. **ClickHouse** — hot telemetry analytics (priced per row written).
2. **NATS JetStream** — the telemetry bus (priced per GB-month retained).
3. **S3 cold archive** — long-term retention (priced per GB-month stored).

All unit prices live in
[`metering.DefaultUnitCosts`](../internal/service/metering/cost.go) and
are configurable — finance can retune them without a code change. The
fleet-wide volumes are reproduced by the
[`capacity-plan`](../bench/controlplane) model
(`go run ./bench/controlplane capacity-plan --tenants N`). Unit economics
targets are sourced from
[`bench/business-report/theoretical.json`](../bench/business-report/theoretical.json).

> All figures are **estimates for internal margin analysis, not billed
> amounts**. They are conservative public-cloud list prices; negotiated
> / committed-use pricing is typically lower.

---

## 1. Unit prices

| Driver | Field | Default | Unit |
|--------|-------|--------:|------|
| ClickHouse rows written | `ClickHousePer1MRowsUSD` | $0.20 | per 1,000,000 rows |
| NATS JetStream storage | `NATSPerGBMonthUSD` | $0.10 | per GB-month (gauge) |
| S3 cold archive | `S3PerGBMonthUSD` | $0.023 | per GB-month (gauge) |

**Why two pricing semantics.** ClickHouse cost is a *flow*: it accrues
with every row written, so it is metered cumulatively and extrapolated
to a month. NATS and S3 are *gauges*: retention bounds them, so a tenant
pays for the volume currently resident, not the lifetime sum of bytes
ever written. Running a gauge through the additive meter pipeline would
double-count every redelivered or re-published message — so
`ProjectInfraMonthlyCost` prices them directly against the sampled size.
NATS is priced higher per GB than S3 because JetStream persistence is
backed by a provisioned block volume (paid for whether or not it is
full), whereas S3 cold archive is object storage billed on actual bytes.

---

## 2. ClickHouse hosting cost

Rows fan out across the 7 telemetry classes. Volumes from the capacity
model (256 B/event uncompressed, 8× columnar compression):

| Tenants | Rows/month | Hot storage (compressed) | Row-write cost/month | Per tenant/month |
|--------:|-----------:|-------------------------:|---------------------:|-----------------:|
| 1,000   | 13.74 B | ~440 GB   | $2,747.52  | $2.75 |
| 2,500   | 34.34 B | ~1,099 GB | $6,868.80  | $2.75 |
| 5,000   | 68.69 B | ~2,198 GB | $13,737.60 | $2.75 |

Row-write cost = `rows_per_month / 1e6 × $0.20`. The per-tenant figure is
flat because the model assumes a uniform per-tenant event rate; in
practice it scales with each tenant's actual traffic, which is exactly
what `MeterClickHouseRowsWritten` records per-tenant.

**Cost levers.** The dominant cost is row volume, not storage. Reduce it
with (a) per-tenant telemetry sampling / rate-limiting (already a
platform feature via the per-tenant token bucket), (b) shorter hot
retention (30 vs 90 days) to shrink resident storage, and (c) larger
`CLICKHOUSE_BATCH_SIZE` to keep the merge tree healthy (see
[`scaling.md`](./scaling.md) — this is a stability lever, not a
$/row lever, but an unhealthy merge tree forces over-provisioned
hardware).

---

## 3. NATS JetStream storage cost

JetStream hot-stream retention is a point-in-time gauge. Steady-state
resident size from the capacity model (24h retention, 16 partitions):

| Tenants | Hot stream storage | Storage cost/month | Per tenant/month |
|--------:|-------------------:|-------------------:|-----------------:|
| 1,000   | ~146 GB | $14.65 | $0.0147 |
| 2,500   | ~366 GB | $36.63 | $0.0147 |
| 5,000   | ~733 GB | $73.27 | $0.0147 |

NATS storage is a rounding error next to ClickHouse — the bus is a
transit buffer, not a store of record. The lever is the retention window
(shrink `NATS` max-age / max-bytes) and `NATS_PARTITIONS` (spreads the
same bytes across more streams without changing the total). `NATS_REPLICAS`
multiplies the resident bytes by the replication factor for durability —
factor that into the gauge if you run quorum streams (the model prices a
single replica's footprint).

---

## 4. S3 cold archive cost

Cold archive holds 1yr+ of compressed telemetry. Sizing for the 5K tier:

- Uncompressed: 68.69 B events/mo × 256 B = **17.6 TB/month**.
- Cold compression (~10×, parquet + zstd): **~1.76 TB/month** added.
- 12-month steady-state resident: **~21.1 TB**.

Cost depends heavily on the S3 **storage class** (`S3_TELEMETRY_STORAGE_CLASS`):

| Storage class | $/GB-month | Cost/month @ 5K (21.1 TB) | Per tenant/month |
|---------------|-----------:|--------------------------:|-----------------:|
| S3 Standard (model default) | $0.023   | $485.30 | $0.097 |
| Glacier Flexible Retrieval  | $0.0036  | $75.96  | $0.0152 |
| Glacier Deep Archive        | $0.00099 | $20.89  | $0.0042 |

The model's `S3PerGBMonthUSD` default is S3 Standard ($0.023) as a
conservative upper bound. For 1yr+ retention of rarely-read telemetry,
Glacier Deep Archive cuts the cold-storage line ~23× — set the storage
class accordingly. Scale the table linearly for the 1K (≈4.2 TB) and
2.5K (≈10.5 TB) tiers.

---

## 5. Fleet infrastructure cost rollup (5K tenants)

Combining the three drivers at S3 Standard pricing:

| Driver | Cost/month | Share | Per tenant/month |
|--------|-----------:|------:|-----------------:|
| ClickHouse rows | $13,737.60 | 96.0% | $2.7475 |
| S3 cold archive | $485.30    | 3.4%  | $0.0971 |
| NATS storage    | $73.27     | 0.5%  | $0.0147 |
| **Total**       | **$14,296.17** | 100% | **$2.859** |

**ClickHouse dominates infrastructure cost.** Optimisation effort should
target telemetry volume (sampling, retention, per-tenant rate limits)
before touching NATS or S3, which are together <4% of the bill.

### Reconciliation with unit economics

`theoretical.json` targets a direct infra cost of **$0.30–$1.20 per user
per month** (envelope across cohorts). The $2.859/tenant/month above is
**per tenant**, not per user — a tenant aggregates many users. At a
representative 50–300 users/tenant the telemetry-infra slice is
**$0.0095–$0.057 per user/month**, comfortably inside the envelope and
leaving the bulk of it for the per-request meters (LLM, URL cat, malware,
egress) tracked separately in `TenantCostReport`.

---

## 6. How it is tracked in code

[`internal/service/metering/cost.go`](../internal/service/metering/cost.go)
exposes the infrastructure projection API consumed by the cost-report
endpoint and the metering dashboard:

- `InfraUsageSample` — per-tenant input: `ClickHouseRowsThisPeriod` (flow
  counter, with its `ClickHousePeriod`), `NATSStreamBytes` (gauge),
  `S3ArchiveBytes` (gauge).
- `CostCalculator.ProjectInfraMonthlyCost(sample)` → `InfraCostProjection`
  — extrapolates the ClickHouse flow to a full month and prices the NATS
  / S3 gauges directly, returning a per-driver breakdown plus total.
- `CostCalculator.AggregateInfraCost(samples)` → `PlatformInfraCost`
  — sums per-tenant projections into a fleet-wide total, preserving the
  per-driver split so a planner can see which backend dominates.
- `CostCalculator.NATSStorageCostUSD(streamBytes)` — the gauge pricing
  primitive.

The ClickHouse row count comes from the tenant's recorded usage; the
NATS and S3 gauges are sampled from the backends (JetStream stream info,
S3 archive object listing) at report time. See
[`docs/metering-dashboard.md`](./metering-dashboard.md) for the UI
specification that renders these figures.
