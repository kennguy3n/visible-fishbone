# Metering Dashboard — UI Specification

This is the specification for the **Metering & Cost** dashboard page, for
the Stream A (UI, under `ui/`) team to implement. It describes the data
sources, layout, and interaction model. It does **not** prescribe a
component library — follow the existing UI conventions.

The page surfaces two audiences:

- **Tenant admins** see their own tenant's usage, budgets, and projected
  cost.
- **Platform/MSP admins** additionally see the fleet-wide cost report and
  per-tenant margin.

---

## 1. Data sources (existing REST API)

All endpoints are served by the control plane
([`internal/handler/metering.go`](../internal/handler/metering.go)).

| Endpoint | Scope | Purpose |
|----------|-------|---------|
| `GET /api/v1/tenants/{tenant_id}/usage` | tenant | Current-period usage per meter, with soft/hard limits and exceed flags |
| `GET /api/v1/tenants/{tenant_id}/usage/history?months=N` | tenant | Trailing usage history (default 6 months, max 36) for trend charts |
| `PUT /api/v1/tenants/{tenant_id}/budgets` | tenant admin | Set per-meter soft/hard budgets |
| `GET /api/v1/admin/cost-report` | platform (`metering:read_platform_report`) | Fleet-wide per-tenant cost + margin |

The 7 meters are: LLM tokens, LLM calls, URL-categorisation lookups,
malware scans, bandwidth proxied (egress), ClickHouse rows written, S3
bytes archived. The infrastructure cost drivers (ClickHouse / NATS / S3)
are described in [`cost-model.md`](./cost-model.md).

> **Note for the API/Stream-C team:** the per-tenant *infrastructure*
> projection (`InfraCostProjection`: ClickHouse / NATS / S3 monthly USD)
> computed by `CostCalculator.ProjectInfraMonthlyCost` is not yet exposed
> on a dedicated route. Section 4 below assumes it is surfaced (e.g.
> folded into the cost-report payload or a new
> `GET /api/v1/tenants/{tenant_id}/cost`); the UI should treat the
> infra-breakdown panel as optional until that field is present.

---

## 2. Page layout

```
┌─────────────────────────────────────────────────────────────┐
│  Metering & Cost            [tenant selector ▾]  [period ▾]   │
├───────────────┬───────────────┬───────────────┬─────────────┤
│ Projected      │ Budget health  │ Margin         │ Top driver  │
│ monthly cost   │ (n over soft)  │ (admin only)   │ (ClickHouse)│
│  $X.XX         │  ●●●○○          │  XX%           │  96%        │
├───────────────┴───────────────┴───────────────┴─────────────┤
│  Usage by meter (table) — used / limit / projected / cost     │
│  ...                                                          │
├───────────────────────────────────────────────────────────────┤
│  Usage trend (line chart, last N months, meter toggle)        │
├───────────────────────────────────────────────────────────────┤
│  Infrastructure cost breakdown (ClickHouse / NATS / S3)       │
└───────────────────────────────────────────────────────────────┘
```

---

## 3. Components

### 3.1 Summary cards (top row)

- **Projected monthly cost** — `projected_monthly_cost_usd` for the
  tenant. Format as USD, 2 decimals.
- **Budget health** — count of meters where `soft_exceeded` /
  `hard_exceeded` is true. Green when none, amber on soft, red on hard.
- **Margin** *(platform admin only)* — `margin_pct` from the cost report.
  Red below a configurable floor (e.g. 20%).
- **Top cost driver** — the meter with the largest `cost_usd` share.

### 3.2 Usage-by-meter table

One row per meter from the `usage` endpoint joined with the cost report:

| Column | Source field | Notes |
|--------|--------------|-------|
| Meter | `meter` | Human label (map enum → display name) |
| Period | `period` | `daily` / `monthly` badge |
| Used | `used` | Raw count, thousands-separated |
| Soft / Hard limit | `soft_limit` / `hard_limit` | "—" when 0 (unbounded) |
| Projected | `projected_usage` | Extrapolated to period end |
| Cost | `cost_usd` | USD |
| Budget | `budget_utilization` | Progress bar; amber ≥ soft, red ≥ hard |

Row state: highlight amber when `soft_exceeded`, red when `hard_exceeded`.

### 3.3 Usage trend chart

Line chart from `usage/history`. X = month (`period_start`), Y = `value`.
One series per meter with a toggle legend. Default window 6 months;
expose a control up to 36.

### 3.4 Budget editor

A modal/drawer that `PUT`s `/budgets`. Per meter: soft limit, hard limit
(0 = unbounded). Validate hard ≥ soft when both set. Tenant-admin only.

### 3.5 Infrastructure cost breakdown *(optional, see §1 note)*

Stacked bar or donut over the three infra drivers from
`InfraCostProjection`:

| Segment | Field |
|---------|-------|
| ClickHouse | `clickhouse_monthly_usd` |
| NATS | `nats_monthly_usd` |
| S3 archive | `s3_monthly_usd` |
| Total | `total_monthly_usd` |

Tooltip ClickHouse with `clickhouse_projected_rows` and NATS / S3 with
their resident GB (`nats_stream_bytes` / `s3_archive_bytes` ÷ 1e9). Note
in the UI that NATS/S3 are point-in-time storage gauges while ClickHouse
is a projected write flow.

---

## 4. Platform (MSP) view

When the user holds `metering:read_platform_report`, add a fleet table
from `admin/cost-report`:

| Column | Field |
|--------|-------|
| Tenant | `tenant_id` (resolve to name) |
| Tier | `tier` |
| Projected monthly cost | `projected_monthly_cost_usd` |
| Revenue | `monthly_revenue_usd` |
| Margin | `margin_usd` / `margin_pct` |

Footer totals: `total_cost_usd`, `total_revenue_usd`, `total_margin_usd`.
Sortable by margin so an MSP can spot loss-making tenants. Default sort:
margin ascending (worst first).

---

## 5. States & errors

- **Loading**: skeleton cards + table.
- **Empty**: tenant with no usage this period → zeroed cards, "No usage
  recorded yet this period."
- **Forbidden**: non-platform user must not see the MSP table or the
  margin card (the API 404s the cost-report route for them — treat 404
  on that route as "not authorized", not a hard error).
- **Currency**: all monetary values are USD estimates for margin
  analysis, not invoices — show a one-line disclaimer in the page footer.
