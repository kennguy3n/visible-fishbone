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
  ResponsiveContainer,
} from "recharts";
import { useUsage, useUsageHistory } from "@/api/manual/hooks";
import { PageHeader, Card, AsyncBoundary, StatusBadge } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";
import { formatNumber, titleCase } from "@/lib/format";

const AXIS = { fill: "#9fb0cc", fontSize: 11 };
const TOOLTIP = {
  background: "#111a2e",
  border: "1px solid #243352",
  borderRadius: 8,
};

export function Metering() {
  return (
    <RequireTenant>{(tenantId) => <MeteringInner tenantId={tenantId} />}</RequireTenant>
  );
}

function MeteringInner({ tenantId }: { tenantId: string }) {
  const usage = useUsage(tenantId);
  const history = useUsageHistory(tenantId);

  const lines = usage.data?.lines ?? [];
  const usageData = lines.map((l) => ({
    meter: titleCase(l.meter),
    used: l.used,
    soft: l.soft_limit ?? 0,
    hard: l.hard_limit ?? 0,
  }));

  const byPeriod: Record<string, Record<string, number | string>> = {};
  for (const l of history.data?.lines ?? []) {
    byPeriod[l.period] ??= { period: l.period };
    byPeriod[l.period][l.meter] = l.used;
  }
  const historyData = Object.values(byPeriod).sort((a, b) =>
    String(a.period).localeCompare(String(b.period)),
  );
  const meters = [...new Set((history.data?.lines ?? []).map((l) => l.meter))];
  const palette = ["#3b82f6", "#22d3ee", "#a78bfa", "#f59e0b", "#34d399"];

  return (
    <>
      <PageHeader
        title="Metering & usage"
        subtitle="Consumption against soft/hard limits and historical trend."
      />

      <Card title="Current period — usage vs limits">
        <AsyncBoundary
          isLoading={usage.isLoading}
          error={usage.error}
          data={usage.data}
          isEmpty={() => usageData.length === 0}
          empty={<p className="muted">No usage recorded.</p>}
        >
          {() => (
            <div style={{ height: 280 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={usageData}>
                  <CartesianGrid stroke="#243352" />
                  <XAxis dataKey="meter" tick={AXIS} />
                  <YAxis tick={AXIS} />
                  <Tooltip contentStyle={TOOLTIP} />
                  <Legend />
                  <Bar dataKey="used" fill="#3b82f6" name="Used" />
                  <Bar dataKey="soft" fill="#f59e0b" name="Soft limit" fillOpacity={0.5} />
                  <Bar dataKey="hard" fill="#f87171" name="Hard limit" fillOpacity={0.4} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </AsyncBoundary>
      </Card>

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card title="Meters">
          {lines.length === 0 ? (
            <p className="muted">No meters.</p>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Meter</th>
                  <th>Used</th>
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
                    <td className="mono">{l.soft_limit ? formatNumber(l.soft_limit) : "—"}</td>
                    <td className="mono">{l.hard_limit ? formatNumber(l.hard_limit) : "—"}</td>
                    <td>
                      <StatusBadge
                        status={
                          l.hard_exceeded
                            ? "exceeded"
                            : l.soft_exceeded
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

        <Card title="Historical usage">
          {historyData.length === 0 ? (
            <p className="muted">No history available.</p>
          ) : (
            <div style={{ height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={historyData}>
                  <CartesianGrid stroke="#243352" />
                  <XAxis dataKey="period" tick={AXIS} />
                  <YAxis tick={AXIS} />
                  <Tooltip contentStyle={TOOLTIP} />
                  <Legend />
                  {meters.map((m, i) => (
                    <Line
                      key={m}
                      type="monotone"
                      dataKey={m}
                      stroke={palette[i % palette.length]}
                      dot={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
