import { useState } from "react";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import {
  useListAlerts,
  useAcknowledgeAlert,
  useResolveAlert,
} from "@/api/generated/endpoints/alert/alert";
import { useListBaselineModels } from "@/api/generated/endpoints/baseline/baseline";
import type { Alert } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative } from "@/lib/format";

export function Alerts() {
  return (
    <RequireTenant>{(tenantId) => <AlertsInner tenantId={tenantId} />}</RequireTenant>
  );
}

function AlertsInner({ tenantId }: { tenantId: string }) {
  const list = useListAlerts(tenantId, undefined);
  const baselines = useListBaselineModels(tenantId, undefined);
  const ack = useAcknowledgeAlert();
  const resolve = useResolveAlert();
  const [severity, setSeverity] = useState<string>("all");

  const all = list.data?.items ?? [];
  const filtered = severity === "all" ? all : all.filter((a) => a.severity === severity);

  const scatterData = all.map((a) => ({
    x: new Date(a.created_at).getTime(),
    y: a.z_score,
    z: Math.abs(a.z_score),
    kind: a.kind,
  }));

  const columns: Column<Alert>[] = [
    { header: "Severity", cell: (a) => <StatusBadge status={a.severity} /> },
    { header: "Kind", cell: (a) => <span className="mono">{a.kind}</span> },
    { header: "Dimension", cell: (a) => a.dimension },
    {
      header: "Observed / baseline",
      cell: (a) => (
        <span className="mono">
          {a.observed_value?.toFixed(1)} vs {a.baseline_mean?.toFixed(1)}±
          {a.baseline_stddev?.toFixed(1)}
        </span>
      ),
    },
    {
      header: "Z",
      cell: (a) => (
        <b style={{ color: Math.abs(a.z_score) > 3 ? "var(--danger)" : "var(--warn)" }}>
          {a.z_score?.toFixed(2)}
        </b>
      ),
    },
    { header: "State", cell: (a) => <StatusBadge status={a.state} /> },
    { header: "When", cell: (a) => formatRelative(a.created_at) },
    {
      header: "",
      cell: (a) => (
        <div style={{ display: "flex", gap: 6 }}>
          <button
            className="btn btn--sm"
            disabled={a.state !== "open" || ack.isPending}
            onClick={() => ack.mutate({ tenantId, alertId: a.id })}
          >
            Ack
          </button>
          <button
            className="btn btn--sm"
            disabled={a.state === "resolved" || resolve.isPending}
            onClick={() => resolve.mutate({ tenantId, alertId: a.id })}
          >
            Resolve
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle="Baseline anomaly detections with statistical context."
      />

      <Card title="Anomaly scatter — deviation (z-score) over time" className="">
        {scatterData.length === 0 ? (
          <p className="muted">No anomalies recorded.</p>
        ) : (
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid stroke="#243352" />
                <XAxis
                  type="number"
                  dataKey="x"
                  domain={["dataMin", "dataMax"]}
                  tickFormatter={(v) => new Date(v).toLocaleDateString()}
                  tick={{ fill: "#9fb0cc", fontSize: 11 }}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  tick={{ fill: "#9fb0cc", fontSize: 11 }}
                  label={{ value: "z-score", angle: -90, fill: "#9fb0cc", fontSize: 11 }}
                />
                <ZAxis type="number" dataKey="z" range={[40, 400]} />
                <ReferenceLine y={3} stroke="#f87171" strokeDasharray="4 4" />
                <ReferenceLine y={-3} stroke="#f87171" strokeDasharray="4 4" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  contentStyle={{
                    background: "#111a2e",
                    border: "1px solid #243352",
                    borderRadius: 8,
                  }}
                  labelFormatter={(v) => new Date(v).toLocaleString()}
                />
                <Scatter data={scatterData} fill="#22d3ee" fillOpacity={0.7} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <div className="toolbar" style={{ marginTop: 16 }}>
        <label className="muted" style={{ fontSize: 12 }}>
          Severity
        </label>
        <select
          style={{ width: 160 }}
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          {["all", "critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <div className="toolbar__spacer" />
        <span className="muted">
          {baselines.data?.items?.length ?? 0} baseline models trained
        </span>
      </div>

      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={() => filtered.length === 0}
          empty={<p className="muted" style={{ padding: 12 }}>No alerts match the filter.</p>}
        >
          {() => <DataTable columns={columns} rows={filtered} rowKey={(a) => a.id} />}
        </AsyncBoundary>
      </Card>
    </>
  );
}
