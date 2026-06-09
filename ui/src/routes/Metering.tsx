import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
} from "recharts";
import { useUsage, useUsageHistory } from "@/api/manual/hooks";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  EmptyState,
} from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";
import { formatNumber, formatCompact, titleCase } from "@/lib/format";
import { CHART, CHART_TOOLTIP } from "@/lib/chart-theme";

const TOOLTIP = CHART_TOOLTIP;

export function Metering() {
  return (
    <RequireTenant>{(tenantId) => <MeteringInner tenantId={tenantId} />}</RequireTenant>
  );
}

function MeteringInner({ tenantId }: { tenantId: string }) {
  // Read axis color at render so it tracks the active theme (CHART.axis is a
  // live token getter; capturing it at module load would freeze it).
  const AXIS = { fill: CHART.axis, fontSize: 11 };
  const usage = useUsage(tenantId);
  const history = useUsageHistory(tenantId);

  const lines = usage.data?.lines ?? [];
  // The budget chart plots utilisation as a percentage of each meter's
  // hard limit, so meters of wildly different magnitudes (LLM calls vs.
  // proxied bytes) share one readable 0–100% axis. Meters without a
  // hard limit are pure cost-drivers with no budget to chart, so we omit
  // them here (they still appear in the table below).
  const pct = (v: number, hard: number) =>
    hard > 0 ? Math.round((v / hard) * 1000) / 10 : 0;
  const utilData = lines
    .filter((l) => (l.hard_limit ?? 0) > 0)
    .map((l) => ({
      meter: titleCase(l.meter),
      current: pct(l.used, l.hard_limit ?? 0),
      projected: pct(l.projected, l.hard_limit ?? 0),
    }));

  // Historical usage is a monthly total per meter. Magnitudes differ by
  // orders of magnitude (LLM calls vs. proxied bytes), so a single shared
  // axis is unreadable — render one auto-scaled sparkline per meter instead.
  // The latest period is the in-progress month (a partial total), which would
  // read as a sharp drop next to completed months, so we trend completed
  // months only. The current month's run rate lives in the budget chart above.
  type HistoryPoint = { period: string; value: number };
  const historyLines = history.data?.lines ?? [];
  const inProgressPeriod = historyLines
    .map((l) => l.period_start.slice(0, 7))
    .sort()
    .at(-1);
  const seriesByMeter: Record<string, HistoryPoint[]> = {};
  for (const l of historyLines) {
    const period = l.period_start.slice(0, 7); // YYYY-MM
    if (period === inProgressPeriod) continue;
    (seriesByMeter[l.meter] ??= []).push({ period, value: l.value });
  }
  for (const m of Object.keys(seriesByMeter)) {
    seriesByMeter[m].sort((a, b) => a.period.localeCompare(b.period));
  }
  const historyMeters = Object.keys(seriesByMeter).sort();
  const palette = [
    CHART.brand,
    CHART.accent,
    CHART.violet,
    CHART.warnAlt,
    CHART.ok,
  ];

  return (
    <>
      <PageHeader
        title="Metering & usage"
        subtitle="Consumption against soft/hard limits and historical trend."
      />

      <Card
        title="Budget utilisation — current vs projected"
        subtitle="Percent of each meter's hard limit. Projected extrapolates the current run rate to the end of the period; the 100% line is the hard limit."
      >
        <AsyncBoundary
          isLoading={usage.isLoading}
          error={usage.error}
          data={usage.data}
          isEmpty={() => utilData.length === 0}
          empty={
            <EmptyState
              title="No budgeted meters"
              description="Set a hard limit on a meter to track its budget utilisation here."
            />
          }
        >
          {() => (
            <div style={{ height: 280 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={utilData}>
                  <CartesianGrid stroke={CHART.border} />
                  <XAxis dataKey="meter" tick={AXIS} />
                  <YAxis
                    tick={AXIS}
                    width={44}
                    domain={[0, (max: number) => Math.max(100, Math.ceil(max / 10) * 10)]}
                    tickFormatter={(v: number) => `${v}%`}
                  />
                  <Tooltip contentStyle={TOOLTIP} formatter={(v: number) => `${v}%`} />
                  <Legend />
                  <ReferenceLine
                    y={100}
                    stroke={CHART.danger}
                    strokeDasharray="4 4"
                    ifOverflow="extendDomain"
                    label={{ value: "Hard limit", position: "right", fill: CHART.danger, fontSize: 10 }}
                  />
                  <Bar dataKey="current" fill={CHART.brand} name="Current %" />
                  <Bar dataKey="projected" fill={CHART.accent} name="Projected %" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </AsyncBoundary>
      </Card>

      <div style={{ marginTop: 16 }}>
        <Card title="Meters">
          {lines.length === 0 ? (
            <EmptyState title="No meters" description="No metered dimensions for this period yet." />
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Meter</th>
                  <th>Used</th>
                  <th>Projected</th>
                  <th>Soft</th>
                  <th>Hard</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {lines.map((l) => (
                  <tr key={l.meter}>
                    <td>{titleCase(l.meter)}</td>
                    <td className="mono">{formatNumber(l.used)}</td>
                    <td className="mono">{formatNumber(l.projected)}</td>
                    <td className="mono">{l.soft_limit ? formatNumber(l.soft_limit) : "—"}</td>
                    <td className="mono">{l.hard_limit ? formatNumber(l.hard_limit) : "—"}</td>
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
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div style={{ marginTop: 16 }}>
        <Card
          title="Historical usage"
          subtitle="Completed-month totals per meter. Each sparkline is scaled to its own range; the in-progress month is shown in the budget chart above."
        >
          {historyMeters.length === 0 ? (
            <EmptyState title="No history available" description="Historical usage appears after the first billing period." />
          ) : (
            <div className="sparkgrid">
              {historyMeters.map((m, i) => {
                const data = seriesByMeter[m];
                const latest = data[data.length - 1]?.value ?? 0;
                const color = palette[i % palette.length];
                return (
                  <div className="sparktile" key={m}>
                    <div className="sparktile__head">
                      <span className="sparktile__name">{titleCase(m)}</span>
                      <span className="sparktile__val mono">{formatCompact(latest)}</span>
                    </div>
                    <div style={{ height: 44 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={data} margin={{ top: 4, right: 2, bottom: 0, left: 2 }}>
                          <Tooltip
                            contentStyle={TOOLTIP}
                            formatter={(v: number) => [formatNumber(v), titleCase(m)]}
                          />
                          <Line
                            type="monotone"
                            dataKey="value"
                            stroke={color}
                            strokeWidth={2}
                            dot={false}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
