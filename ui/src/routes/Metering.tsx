import { useMemo, useState } from "react";
import { useIntl, type IntlShape, type MessageDescriptor } from "react-intl";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  useUsage,
  useUsageHistory,
  useCost,
  useCostReport,
  usePlatformCostReport,
  useUpdateBudgets,
} from "@/api/manual/hooks";
import type {
  BudgetOverride,
  CostLine,
  InfraCostProjection,
  PlatformCostReport,
  TenantCostReport,
  UsageLine,
} from "@/api/manual/types";
import {
  PageHeader,
  Card,
  Stat,
  Badge,
  AsyncBoundary,
  StatusBadge,
  EmptyState,
  SkeletonCard,
} from "@/components/ui";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import {
  formatNumber,
  formatCompact,
  formatUSD,
  formatPct,
  bytesToGB,
  titleCase,
  type Tone,
} from "@/lib/format";
import { CHART, CHART_TOOLTIP } from "@/lib/chart-theme";
import { LanePage } from "./lane-b5";
import { meteringMsg as M, meterMsg } from "./lane-b5.messages";

const TOOLTIP = CHART_TOOLTIP;

// Display labels for the meter enum (titleCase mangles the LLM/URL/S3
// initialisms). Falls back to titleCase for anything unmapped so a new
// backend meter still renders sensibly without a UI change.
const METER_KEYS: Record<string, MessageDescriptor> = {
  llm_tokens_used: meterMsg.llm_tokens_used,
  llm_calls: meterMsg.llm_calls,
  url_cat_lookups: meterMsg.url_cat_lookups,
  malware_scans: meterMsg.malware_scans,
  clickhouse_rows_written: meterMsg.clickhouse_rows_written,
  s3_bytes_archived: meterMsg.s3_bytes_archived,
  bandwidth_proxied_bytes: meterMsg.bandwidth_proxied_bytes,
  policy_evaluations: meterMsg.policy_evaluations,
};

function meterLabel(intl: IntlShape, meter: string): string {
  const key = METER_KEYS[meter];
  return key ? intl.formatMessage(key) : titleCase(meter);
}

// Margin floor below which a tenant is rendered as loss-risk (red). Per
// the spec this is "configurable"; it lives here as the single UI
// constant so MSP cards and the fleet table agree.
const MARGIN_FLOOR = 0.2;

export function Metering() {
  return (
    <RequireTenant>{(tenantId) => <MeteringInner tenantId={tenantId} />}</RequireTenant>
  );
}

function MeteringInner({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const [months, setMonths] = useState(6);
  const [budgetOpen, setBudgetOpen] = useState(false);

  const usage = useUsage(tenantId);
  const history = useUsageHistory(tenantId, months);
  const cost = useCost(tenantId);
  const costReport = useCostReport(tenantId);
  // Platform/MSP surface. A 404/403 here means "not a platform admin";
  // we treat that as "no MSP view" rather than an error (see hook).
  const platform = usePlatformCostReport();
  const isPlatformAdmin = platform.isSuccess && !!platform.data;

  const usageLines = usage.data?.lines ?? [];

  return (
    <LanePage>
      <PageHeader
        title={intl.formatMessage(M.title)}
        subtitle={intl.formatMessage(M.subtitle)}
        actions={
          <div className="toolbar">
            <button
              className="btn btn--primary btn--sm"
              onClick={() => setBudgetOpen(true)}
              disabled={usageLines.length === 0}
            >
              {intl.formatMessage(M.editBudgets)}
            </button>
          </div>
        }
      />

      <div className="lane-stack">
        <SummaryCards
          usageLines={usageLines}
          usageLoading={usage.isLoading}
          report={costReport.data}
          reportLoading={costReport.isLoading}
          isPlatformAdmin={isPlatformAdmin}
        />

        <UsageByMeterTable
          usage={usageLines}
          report={costReport.data}
          isLoading={usage.isLoading}
          error={usage.error}
          hasData={usage.data !== undefined}
          onRetry={() => usage.refetch()}
        />

        <UsageTrendChart
          tenantId={tenantId}
          months={months}
          onMonthsChange={setMonths}
          history={history.data?.lines ?? []}
          isLoading={history.isLoading}
          error={history.error}
          hasData={history.data !== undefined}
          onRetry={() => history.refetch()}
        />

        <InfraCostBreakdown
          data={cost.data}
          isLoading={cost.isLoading}
          error={cost.error}
          onRetry={() => cost.refetch()}
        />

        {isPlatformAdmin && platform.data && <FleetTable report={platform.data} />}

        <p className="page-footnote">{intl.formatMessage(M.footnote)}</p>
      </div>

      {budgetOpen && (
        <BudgetEditor
          tenantId={tenantId}
          lines={usageLines}
          onClose={() => setBudgetOpen(false)}
        />
      )}
    </LanePage>
  );
}

// --- 3.1 Summary cards -----------------------------------------------------

function SummaryCards({
  usageLines,
  usageLoading,
  report,
  reportLoading,
  isPlatformAdmin,
}: {
  usageLines: UsageLine[];
  usageLoading: boolean;
  report?: TenantCostReport;
  reportLoading: boolean;
  isPlatformAdmin: boolean;
}) {
  const intl = useIntl();

  if (usageLoading || reportLoading) {
    return (
      <div className="grid grid--stats">
        {Array.from({ length: isPlatformAdmin ? 4 : 3 }).map((_, i) => (
          <SkeletonCard key={i} lines={2} />
        ))}
      </div>
    );
  }

  // Budget health: count meters currently over their soft / hard limit.
  const overSoft = usageLines.filter((l) => l.soft_exceeded).length;
  const overHard = usageLines.filter((l) => l.hard_exceeded).length;
  const healthTone: Tone = overHard > 0 ? "danger" : overSoft > 0 ? "warn" : "ok";
  const healthLabel =
    overHard > 0
      ? intl.formatMessage(M.healthOverHard, { count: overHard })
      : overSoft > 0
        ? intl.formatMessage(M.healthOverSoft, { count: overSoft })
        : intl.formatMessage(M.healthAllOk);

  // Top cost driver: the meter with the largest cost share this period.
  const lines = report?.lines ?? [];
  const totalCost = report?.total_cost_usd ?? 0;
  const topDriver = lines.reduce<CostLine | null>(
    (top, l) => (top === null || l.cost_usd > top.cost_usd ? l : top),
    null,
  );
  const topShare = topDriver && totalCost > 0 ? topDriver.cost_usd / totalCost : 0;

  const marginTone: Tone =
    report == null
      ? "neutral"
      : report.margin_pct < MARGIN_FLOOR
        ? "danger"
        : report.margin_pct < MARGIN_FLOOR * 2
          ? "warn"
          : "ok";

  return (
    <div className="grid grid--stats">
      <Card>
        <Stat
          label={intl.formatMessage(M.projectedLabel)}
          value={formatUSD(report?.projected_monthly_cost_usd ?? 0)}
          delta={
            <span className="stat__hint">
              {intl.formatMessage(M.projectedHint, {
                amount: formatUSD(report?.total_cost_usd ?? 0),
              })}
            </span>
          }
        />
      </Card>

      <Card>
        <Stat
          label={intl.formatMessage(M.healthLabel)}
          value={
            <Badge tone={healthTone} dot>
              {healthLabel}
            </Badge>
          }
          delta={
            <span className="stat__hint">
              {intl.formatMessage(M.healthHint, { count: usageLines.length })}
            </span>
          }
        />
      </Card>

      {isPlatformAdmin && (
        <Card>
          <Stat
            label={intl.formatMessage(M.marginLabel)}
            value={<Badge tone={marginTone}>{formatPct(report?.margin_pct, 1)}</Badge>}
            delta={
              <span className="stat__hint">
                {intl.formatMessage(M.marginHint, {
                  amount: formatUSD(report?.margin_usd ?? 0),
                })}
              </span>
            }
          />
        </Card>
      )}

      <Card>
        <Stat
          label={intl.formatMessage(M.topDriverLabel)}
          value={topDriver ? meterLabel(intl, topDriver.meter) : "—"}
          delta={
            <span className="stat__hint">
              {topDriver
                ? intl.formatMessage(M.topDriverHint, {
                    pct: formatPct(topShare),
                    amount: formatUSD(totalCost),
                  })
                : intl.formatMessage(M.topDriverNone)}
            </span>
          }
        />
      </Card>
    </div>
  );
}

// --- 3.2 Usage-by-meter table ----------------------------------------------

function UsageByMeterTable({
  usage,
  report,
  isLoading,
  error,
  hasData,
  onRetry,
}: {
  usage: UsageLine[];
  report?: TenantCostReport;
  isLoading: boolean;
  error: unknown;
  hasData: boolean;
  onRetry: () => void;
}) {
  const intl = useIntl();

  // Join the cost report onto the usage rows by meter so each row can
  // show its projected spend and budget utilisation alongside raw usage.
  const costByMeter = useMemo(() => {
    const m = new Map<string, CostLine>();
    for (const l of report?.lines ?? []) m.set(l.meter, l);
    return m;
  }, [report]);

  return (
    <Card title={intl.formatMessage(M.tableTitle)} subtitle={intl.formatMessage(M.tableSubtitle)}>
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={hasData ? usage : undefined}
        isEmpty={(d) => d.length === 0}
        onRetry={onRetry}
        empty={
          <EmptyState
            title={intl.formatMessage(M.tableEmptyTitle)}
            description={intl.formatMessage(M.tableEmptyBody)}
          />
        }
      >
        {(lines) => (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>{intl.formatMessage(M.colMeter)}</th>
                  <th>{intl.formatMessage(M.colPeriod)}</th>
                  <th>{intl.formatMessage(M.colUsed)}</th>
                  <th>{intl.formatMessage(M.colSoft)}</th>
                  <th>{intl.formatMessage(M.colHard)}</th>
                  <th>{intl.formatMessage(M.colProjected)}</th>
                  <th>{intl.formatMessage(M.colCost)}</th>
                  <th className="lane-col-budget">{intl.formatMessage(M.colBudget)}</th>
                  <th>{intl.formatMessage(M.colStatus)}</th>
                </tr>
              </thead>
              <tbody>
                {lines.map((l) => {
                  const c = costByMeter.get(l.meter);
                  const rowClass = l.hard_exceeded
                    ? "row--danger"
                    : l.soft_exceeded
                      ? "row--warn"
                      : undefined;
                  return (
                    <tr key={l.meter} className={rowClass}>
                      <td>{meterLabel(intl, l.meter)}</td>
                      <td>
                        <Badge tone="neutral">{titleCase(l.period)}</Badge>
                      </td>
                      <td className="mono">{formatNumber(l.used)}</td>
                      <td className="mono">
                        {l.soft_limit ? formatNumber(l.soft_limit) : "—"}
                      </td>
                      <td className="mono">
                        {l.hard_limit ? formatNumber(l.hard_limit) : "—"}
                      </td>
                      <td className="mono">
                        {formatNumber(c?.projected_usage ?? l.projected)}
                      </td>
                      <td className="mono">{formatUSD(c?.cost_usd ?? 0)}</td>
                      <td>
                        <BudgetBar
                          utilization={c?.budget_utilization ?? 0}
                          hasLimit={(l.hard_limit ?? 0) > 0}
                        />
                      </td>
                      <td>
                        <StatusBadge
                          status={
                            l.projected_hard_exceeded
                              ? "exceeded"
                              : l.projected_soft_exceeded
                                ? "warning"
                                : "ok"
                          }
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </AsyncBoundary>
    </Card>
  );
}

// BudgetBar renders budget_utilization (a 0–1+ ratio of hard limit) as a
// progress bar: amber ≥ soft band, red ≥ hard. Meters with no hard limit
// are unbounded cost-drivers with no budget to chart.
function BudgetBar({
  utilization,
  hasLimit,
}: {
  utilization: number;
  hasLimit: boolean;
}) {
  const intl = useIntl();
  if (!hasLimit) return <span className="text-dim">{intl.formatMessage(M.budgetUnbounded)}</span>;
  const pct = Math.max(0, utilization);
  const width = Math.min(100, pct * 100);
  const tone =
    pct >= 1 ? "meter__fill--danger" : pct >= 0.8 ? "meter__fill--warn" : "meter__fill--ok";
  return (
    <div className="meter lane-budgetbar">
      <div className="meter__head">
        <span className="text-dim">{formatPct(pct)}</span>
      </div>
      <div className="meter__track">
        <div className={`meter__fill ${tone}`} style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

// --- 3.3 Usage trend chart -------------------------------------------------

const TREND_PALETTE = [
  CHART.brand,
  CHART.accent,
  CHART.violet,
  CHART.warnAlt,
  CHART.ok,
  CHART.danger,
  CHART.warn,
];

const MONTHS_OPTIONS = [6, 12, 24, 36];

interface HistoryLineLike {
  meter: string;
  period_start: string;
  value: number;
}

function UsageTrendChart({
  months,
  onMonthsChange,
  history,
  isLoading,
  error,
  hasData,
  onRetry,
}: {
  tenantId: string;
  months: number;
  onMonthsChange: (m: number) => void;
  history: HistoryLineLike[];
  isLoading: boolean;
  error: unknown;
  hasData: boolean;
  onRetry: () => void;
}) {
  const intl = useIntl();
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  // Pivot the long-format history (one row per meter per month) into a
  // wide format keyed by month, one column per meter, so a single line
  // chart can render every meter's series sharing the month axis.
  //
  // The backend window includes the current calendar month, whose total
  // is only a partial accumulation and would read as a sharp end-of-series
  // drop. The card trends "Completed-month totals", so drop the in-progress
  // (current UTC) month — and any future row — keeping only finished months.
  // This is precise: when the current month has no usage yet, nothing is
  // dropped (vs. a "skip the latest period" heuristic, which would discard
  // the most recent *completed* month).
  const { rows, meters } = useMemo(() => {
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM (UTC)
    const byPeriod = new Map<string, Record<string, number | string>>();
    const meterSet = new Set<string>();
    for (const l of history) {
      const period = l.period_start.slice(0, 7); // YYYY-MM
      if (period >= currentMonth) continue; // skip in-progress / future month
      meterSet.add(l.meter);
      const row = byPeriod.get(period) ?? { period };
      row[l.meter] = l.value;
      byPeriod.set(period, row);
    }
    const sortedRows = [...byPeriod.values()].sort((a, b) =>
      String(a.period).localeCompare(String(b.period)),
    );
    return { rows: sortedRows, meters: [...meterSet].sort() };
  }, [history]);

  const toggle = (meter: string) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(meter)) next.delete(meter);
      else next.add(meter);
      return next;
    });

  const AXIS = { fill: CHART.axis, fontSize: 11 };

  return (
    <Card
      title={intl.formatMessage(M.trendTitle)}
      subtitle={intl.formatMessage(M.trendSubtitle)}
      actions={
        <label className="field-inline">
          <span>{intl.formatMessage(M.windowLabel)}</span>
          <select value={months} onChange={(e) => onMonthsChange(Number(e.target.value))}>
            {MONTHS_OPTIONS.map((m) => (
              <option key={m} value={m}>
                {intl.formatMessage(M.windowOption, { count: m })}
              </option>
            ))}
          </select>
        </label>
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={hasData ? rows : undefined}
        isEmpty={(d) => d.length === 0 || meters.length === 0}
        onRetry={onRetry}
        empty={
          <EmptyState
            title={intl.formatMessage(M.trendEmptyTitle)}
            description={intl.formatMessage(M.trendEmptyBody)}
          />
        }
      >
        {(data) => (
          <>
            <div className="legend-toggle">
              {meters.map((m, i) => {
                const on = !hidden.has(m);
                const color = TREND_PALETTE[i % TREND_PALETTE.length];
                return (
                  <button
                    key={m}
                    type="button"
                    className={`legend-chip${on ? "" : " legend-chip--off"}`}
                    onClick={() => toggle(m)}
                    aria-pressed={on}
                  >
                    <span className="legend-chip__dot" style={{ background: color }} />
                    {meterLabel(intl, m)}
                  </button>
                );
              })}
            </div>
            <div className="lane-chart-line">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: 4 }}>
                  <CartesianGrid stroke={CHART.border} />
                  <XAxis dataKey="period" tick={AXIS} />
                  <YAxis
                    tick={AXIS}
                    width={56}
                    tickFormatter={(v: number) => formatCompact(v)}
                  />
                  <Tooltip
                    contentStyle={TOOLTIP}
                    formatter={(v: number, name: string) => [
                      formatNumber(v),
                      meterLabel(intl, name),
                    ]}
                  />
                  <Legend
                    formatter={(value: string) => meterLabel(intl, value)}
                    onClick={(e) => toggle(String(e.dataKey ?? e.value))}
                  />
                  {meters.map((m, i) => (
                    <Line
                      key={m}
                      type="monotone"
                      dataKey={m}
                      name={m}
                      stroke={TREND_PALETTE[i % TREND_PALETTE.length]}
                      strokeWidth={2}
                      dot={false}
                      hide={hidden.has(m)}
                      connectNulls
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </>
        )}
      </AsyncBoundary>
    </Card>
  );
}

// --- 3.5 Infrastructure cost breakdown -------------------------------------

function InfraCostBreakdown({
  data,
  isLoading,
  error,
  onRetry,
}: {
  data?: InfraCostProjection;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const intl = useIntl();
  const segments = useMemo(() => {
    if (!data) return [];
    return [
      {
        name: "ClickHouse",
        value: data.clickhouse_monthly_usd,
        color: CHART.brand,
        detail: intl.formatMessage(M.infraRows, {
          rows: formatNumber(data.clickhouse_projected_rows),
        }),
      },
      {
        name: "NATS",
        value: data.nats_monthly_usd,
        color: CHART.accent,
        // JetStream has no per-tenant stream-size primitive, so the backend
        // reports 0 unless a deployment-specific sizer is wired (see
        // metering.NATSStreamSizer). Distinguish "unmeasured" from a measured
        // zero so the always-$0 slice isn't read as a real cost of zero.
        detail:
          data.nats_stream_bytes > 0
            ? intl.formatMessage(M.infraResident, {
                gb: formatNumber(Math.round(bytesToGB(data.nats_stream_bytes))),
              })
            : intl.formatMessage(M.infraUnattributed),
      },
      {
        name: "S3 archive",
        value: data.s3_monthly_usd,
        color: CHART.violet,
        detail: intl.formatMessage(M.infraResident, {
          gb: formatNumber(Math.round(bytesToGB(data.s3_archive_bytes))),
        }),
      },
    ];
  }, [data, intl]);

  return (
    <Card title={intl.formatMessage(M.infraTitle)} subtitle={intl.formatMessage(M.infraSubtitle)}>
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        isEmpty={(d) => d.total_monthly_usd <= 0}
        onRetry={onRetry}
        loading={<SkeletonCard lines={4} />}
        empty={
          <EmptyState
            title={intl.formatMessage(M.infraEmptyTitle)}
            description={intl.formatMessage(M.infraEmptyBody)}
          />
        }
      >
        {(proj) => (
          <div className="infra-breakdown">
            {/* The donut is a visual aid only; the adjacent legend list below
                conveys every segment's name, cost and detail as text, so hide
                the decorative SVG from assistive tech. */}
            <div className="lane-chart-pie" aria-hidden="true">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={segments}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={60}
                    outerRadius={95}
                    paddingAngle={2}
                    rootTabIndex={-1}
                  >
                    {segments.map((s) => (
                      <Cell key={s.name} fill={s.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={TOOLTIP}
                    formatter={(v: number, name: string) => {
                      const seg = segments.find((s) => s.name === name);
                      return [`${formatUSD(v)} — ${seg?.detail ?? ""}`, name];
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="infra-breakdown__legend">
              <div className="infra-breakdown__total">
                <span className="stat__label">{intl.formatMessage(M.infraTotal)}</span>
                <span className="cost-amount">{formatUSD(proj.total_monthly_usd)}</span>
              </div>
              <ul>
                {segments.map((s) => (
                  <li key={s.name}>
                    <span className="legend-chip__dot" style={{ background: s.color }} />
                    <span className="infra-breakdown__name">{s.name}</span>
                    <span className="mono">{formatUSD(s.value)}</span>
                    <span className="infra-breakdown__detail">{s.detail}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </AsyncBoundary>
    </Card>
  );
}

// --- 3.4 Budget editor -----------------------------------------------------

interface BudgetRow {
  meter: string;
  period: string;
  soft: string;
  hard: string;
}

function BudgetEditor({
  tenantId,
  lines,
  onClose,
}: {
  tenantId: string;
  lines: UsageLine[];
  onClose: () => void;
}) {
  const intl = useIntl();
  const mutation = useUpdateBudgets(tenantId);
  const [rows, setRows] = useState<BudgetRow[]>(() =>
    lines.map((l) => ({
      meter: l.meter,
      period: l.period,
      soft: l.soft_limit ? String(l.soft_limit) : "",
      hard: l.hard_limit ? String(l.hard_limit) : "",
    })),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const update = (meter: string, field: "soft" | "hard", value: string) => {
    // Keep digits only; empty string means "0 / unbounded".
    const cleaned = value.replace(/[^\d]/g, "");
    setRows((prev) =>
      prev.map((r) => (r.meter === meter ? { ...r, [field]: cleaned } : r)),
    );
  };

  const validate = (): BudgetOverride[] | null => {
    const next: Record<string, string> = {};
    const overrides: BudgetOverride[] = [];
    for (const r of rows) {
      const soft = r.soft === "" ? 0 : Number(r.soft);
      const hard = r.hard === "" ? 0 : Number(r.hard);
      if (hard > 0 && soft > 0 && soft > hard) {
        next[r.meter] = intl.formatMessage(M.budgetSoftHardError);
      }
      overrides.push({
        meter: r.meter,
        soft_limit: soft,
        hard_limit: hard,
        period: r.period || undefined,
      });
    }
    setErrors(next);
    return Object.keys(next).length === 0 ? overrides : null;
  };

  const onSave = () => {
    const overrides = validate();
    if (!overrides) return;
    mutation.mutate(overrides, { onSuccess: onClose });
  };

  return (
    <Modal
      title={intl.formatMessage(M.budgetTitle)}
      onClose={onClose}
      footer={
        <>
          {mutation.isError && (
            <span className="form-error lane-mr-auto" role="alert">
              {intl.formatMessage(M.budgetSaveError)}
            </span>
          )}
          <button className="btn btn--ghost" onClick={onClose} disabled={mutation.isPending}>
            {intl.formatMessage(M.budgetCancel)}
          </button>
          <button className="btn btn--primary" onClick={onSave} disabled={mutation.isPending}>
            {mutation.isPending
              ? intl.formatMessage(M.budgetSaving)
              : intl.formatMessage(M.budgetSave)}
          </button>
        </>
      }
    >
      <p className="lane-prose">{intl.formatMessage(M.budgetIntro)}</p>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>{intl.formatMessage(M.budgetColMeter)}</th>
              <th>{intl.formatMessage(M.budgetColPeriod)}</th>
              <th>{intl.formatMessage(M.budgetColSoft)}</th>
              <th>{intl.formatMessage(M.budgetColHard)}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.meter}>
                <td>{meterLabel(intl, r.meter)}</td>
                <td>
                  <Badge tone="neutral">{titleCase(r.period)}</Badge>
                </td>
                <td>
                  <input
                    className="input input--sm mono"
                    inputMode="numeric"
                    value={r.soft}
                    placeholder="0"
                    onChange={(e) => update(r.meter, "soft", e.target.value)}
                    aria-label={intl.formatMessage(M.budgetSoftAria, {
                      meter: meterLabel(intl, r.meter),
                    })}
                  />
                </td>
                <td>
                  <input
                    className="input input--sm mono"
                    inputMode="numeric"
                    value={r.hard}
                    placeholder="0"
                    onChange={(e) => update(r.meter, "hard", e.target.value)}
                    aria-label={intl.formatMessage(M.budgetHardAria, {
                      meter: meterLabel(intl, r.meter),
                    })}
                  />
                  {errors[r.meter] && (
                    <div className="form-error" role="alert">
                      {errors[r.meter]}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Modal>
  );
}

// --- 4. Platform (MSP) fleet table -----------------------------------------

type SortDir = "asc" | "desc";

function FleetTable({ report }: { report: PlatformCostReport }) {
  const intl = useIntl();
  // Default sort: margin ascending (worst-first) so an MSP spots
  // loss-making tenants immediately.
  const [dir, setDir] = useState<SortDir>("asc");

  const tenants = useMemo(() => {
    const list = [...report.tenants];
    list.sort((a, b) =>
      dir === "asc" ? a.margin_pct - b.margin_pct : b.margin_pct - a.margin_pct,
    );
    return list;
  }, [report.tenants, dir]);

  if (report.tenants.length === 0) {
    return (
      <Card
        title={intl.formatMessage(M.fleetTitle)}
        subtitle={intl.formatMessage(M.fleetSubtitle, { count: report.tenant_count })}
      >
        <EmptyState
          title={intl.formatMessage(M.fleetEmptyTitle)}
          description={intl.formatMessage(M.fleetEmptyBody)}
        />
      </Card>
    );
  }

  return (
    <Card
      title={intl.formatMessage(M.fleetTitle)}
      subtitle={intl.formatMessage(M.fleetSubtitle, { count: report.tenant_count })}
    >
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>{intl.formatMessage(M.fleetColTenant)}</th>
              <th>{intl.formatMessage(M.fleetColTier)}</th>
              <th>{intl.formatMessage(M.fleetColCost)}</th>
              <th>{intl.formatMessage(M.fleetColRevenue)}</th>
              <th>{intl.formatMessage(M.fleetColMargin)}</th>
              <th
                className="th-sortable"
                onClick={() => setDir((d) => (d === "asc" ? "desc" : "asc"))}
                role="button"
                aria-label={intl.formatMessage(M.fleetSortMargin, {
                  dir:
                    dir === "asc"
                      ? intl.formatMessage(M.sortDescending)
                      : intl.formatMessage(M.sortAscending),
                })}
              >
                {intl.formatMessage(M.fleetColMarginPct)} {dir === "asc" ? "▲" : "▼"}
              </th>
            </tr>
          </thead>
          <tbody>
            {tenants.map((t) => {
              const tone: Tone =
                t.margin_pct < MARGIN_FLOOR
                  ? "danger"
                  : t.margin_pct < MARGIN_FLOOR * 2
                    ? "warn"
                    : "ok";
              return (
                <tr key={t.tenant_id}>
                  <td className="mono">{t.tenant_id}</td>
                  <td>
                    <Badge tone="info">{titleCase(t.tier)}</Badge>
                  </td>
                  <td className="mono">{formatUSD(t.projected_monthly_cost_usd)}</td>
                  <td className="mono">{formatUSD(t.monthly_revenue_usd)}</td>
                  <td className="mono">{formatUSD(t.margin_usd)}</td>
                  <td>
                    <Badge tone={tone}>{formatPct(t.margin_pct, 1)}</Badge>
                  </td>
                </tr>
              );
            })}
          </tbody>
          <tfoot>
            <tr>
              <td colSpan={2}>
                <b>{intl.formatMessage(M.fleetTotal)}</b>
              </td>
              <td className="mono">
                <b>{formatUSD(report.projected_monthly_cost_usd)}</b>
              </td>
              <td className="mono">
                <b>{formatUSD(report.total_revenue_usd)}</b>
              </td>
              <td className="mono">
                <b>{formatUSD(report.total_margin_usd)}</b>
              </td>
              <td />
            </tr>
          </tfoot>
        </table>
      </div>
    </Card>
  );
}
