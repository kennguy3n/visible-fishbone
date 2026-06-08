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

---

## 7. Cost-anomaly detection & the per-user target band

The hard per-tier budgets ([`budget.go`](../internal/service/metering/budget.go))
gate a single meter against a fixed ceiling. Session 2B adds two
read-only cost-control levers on top, in
[`anomaly.go`](../internal/service/metering/anomaly.go), for the SME
cost model.

### Per-meter anomaly detector

`CostAnomalyDetector` compares a tenant's **live projected** monthly
spend for each meter against that meter's own trailing baseline (the
**median** of the complete trailing months, default 6-month lookback),
so a sudden shift in traffic mix is caught even while the tenant is
still under its hard budget. Two rules fire:

- **Ratio**: `projected / baseline ≥ WarnRatio` (default `2.0`) →
  `warning`, `≥ CriticalRatio` (default `4.0`) → `critical`. Suppressed
  unless the **baseline** clears `MinBaselineUSD` ($1) and has
  `MinBaselineMonths` (2) of history, so rounding-level meters and
  cold-start tenants don't generate noise. (With `WarnRatio > 1` a
  baseline ≥ $1 that trips the ratio necessarily projects above $1 too,
  so gating on the baseline also bounds projected spend — no separate
  projected floor is needed.)
- **New-spend**: a meter with no usable baseline (median 0) that
  projects above `NewSpendFloorUSD` ($5) — catches a meter switching on
  mid-month, which the ratio rule cannot (division by zero).

The median (not mean) baseline makes the detector robust to a single
prior spike: one anomalous month cannot inflate the baseline enough to
mask the next one.

### Per-user target band

`CostCalculator.AssessPerUserCost(tenantID, monthlyCostUSD, seats)`
divides a tenant's projected monthly infra cost across its seats and
classifies it against the **$0.30–$1.20 per-user** envelope
(`TargetCostPerUserMin/MaxUSD`): `under`, `within`, or `over`. A
non-positive seat count yields an empty band (per-user cost is undefined
without seats) rather than a divide-by-zero.

### Endpoint

`GET /api/v1/tenants/{tenant_id}/cost-anomalies` returns the tenant's
current anomalies. It is mounted tenant-scoped, so the 2A tenant
middleware enforces that the caller's `tenant_id` JWT claim matches the
path tenant (mismatch / missing-claim → 403); the only cross-tenant
caller is an explicitly-authorized platform admin. No new persistence is
introduced — the detector composes the live cost report and the existing
usage history.

---

<!-- BEGIN WORKSTREAM 9: AI cost model (additive section) -->

## AI cost model: managed API vs. self-hosted inference

> Added by Workstream 9. This section is **additive** — it models the
> AI **inference** cost that the per-request `MeterLLMTokensUsed` /
> `MeterLLMCalls` meters price, and the flat self-hosted alternative.
> All figures are conservative public-cloud estimates for internal
> margin analysis, not billed amounts.

SNG's URL-categorisation and content-inspection paths call an LLM. That
inference can be bought two ways, and the cheaper one flips with volume:

1. **Managed API (per-token).** Pay per token, scales linearly with
   usage. Reference: **OpenAI GPT-4o-mini** at ~**$0.15 / 1M input
   tokens** and ~**$0.60 / 1M output tokens**. At fleet scale —
   **5,000 tenants × 10 AI calls/day × 500 tokens avg** ≈ 25M tokens/day
   ≈ 750M tokens/month — a representative input/output mix lands around
   **$600–$900 / month**, and it keeps climbing with adoption.
2. **Self-hosted (flat monthly).** Run **Ternary-Bonsai-8B** on your own
   hardware for a fixed monthly cost, *independent of usage*:
   - **single A10G GPU**: ~**$300/month** (AWS) or ~**$150/month** (bare
     metal),
   - **CPU only** (8-core, 32 GB RAM): ~**$80/month**, adequate for
     **< 50 concurrent requests**.

Because the self-hosted cost is flat, it wins above a **breakeven**
volume and the managed API wins below it. The crossover for the GPU
option lands inside the fleet-scale band above, which is why the
platform must support **both** models simultaneously (different tenants
/ regions sit on different sides of the line).

### Pricing fields

A new flat-rate unit price sits alongside the existing per-token fields
in [`metering.DefaultUnitCosts`](../internal/service/metering/cost.go):

| Field | Default | Unit | Model |
|-------|--------:|------|-------|
| `LLMPer1KTokensUSD` | $0.002 | per 1,000 tokens | per-token (managed API) |
| `LLMPerCallUSD` | $0 | per call | per-token overhead (optional) |
| `LLMSelfHostedPerMonthUSD` | $300 | flat per month | self-hosted (volume-independent) |

`LLMSelfHostedPerMonthUSD` defaults to the conservative **$300/mo**
public-cloud A10G figure; set it to `150` for bare metal, `80` for
CPU-only, or `0` to declare "no self-hosted deployment". Like every
other unit price it is configurable via `NewCostCalculator` without a
code change.

### CostCalculator API

The calculator supports both models through one dispatch point plus a
comparison helper (see `cost.go`):

- `LLMPerTokenMonthlyUSD(tokens, calls)` — managed-API cost; scales with
  the projected volume (per-1K-token charge plus the optional per-call
  overhead).
- `LLMSelfHostedMonthlyUSD()` — the flat monthly charge; returns `0`
  when no deployment is configured (distinct from "$0 to run").
- `LLMMonthlyCostUSD(model, tokens, calls)` — single entry point that
  selects the model. `LLMPricingSelfHosted` returns the flat cost
  regardless of volume; `LLMPricingPerToken` (and any unknown model, the
  safe default) returns the usage-scaled cost.
- `CompareLLMPricing(tokens, calls) LLMCostComparison` — computes both
  costs at a projected volume, reports the `Cheaper` model, the monthly
  `SavingsUSD`, and the **`BreakevenTokens`** volume where the two meet:

  ```
  breakevenTokens = (selfHostedMonthlyUSD − calls·LLMPerCallUSD) · 1000 / LLMPer1KTokensUSD
  ```

  At the defaults ($300/mo flat, $0.002/1K tokens, $0 per call) the
  breakeven is **150,000,000 tokens/month**: below it the managed API is
  cheaper, above it self-hosting is. Breakeven is reported as `0`
  (undefined) when per-token inference is free or no self-hosted
  deployment is configured. Exact ties resolve to per-token (no infra to
  operate).

<!-- END WORKSTREAM 9: AI cost model -->
