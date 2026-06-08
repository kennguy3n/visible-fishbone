import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
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
  getListAlertsQueryKey,
} from "@/api/generated/endpoints/alert/alert";
import { useAiListCorrelations } from "@/api/generated/endpoints/ai/ai";
import { useListBaselineModels } from "@/api/generated/endpoints/baseline/baseline";
import {
  AlertSeverity,
  AlertState,
  type Alert,
  type ListAlerts200,
} from "@/api/generated/model";
import {
  PageHeader,
  Card,
  StatusBadge,
  Badge,
  EmptyState,
  EmptyIllustration,
  SkeletonCard,
  ErrorState,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { formatRelative, titleCase } from "@/lib/format";

export function Alerts() {
  return (
    <RequireTenant>{(tenantId) => <AlertsInner tenantId={tenantId} />}</RequireTenant>
  );
}

const RECOMMENDED: Record<string, string> = {
  critical: "Investigate now and consider auto-remediation — this deviates far from the learned baseline.",
  warning: "Review the affected resource and acknowledge once you've triaged it.",
  info: "Informational. No action is usually required, but you can resolve it to clear the queue.",
};

function AlertsInner({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const list = useListAlerts(tenantId, undefined);
  const correlations = useAiListCorrelations(tenantId, undefined, {
    query: { retry: false },
  });
  const baselines = useListBaselineModels(tenantId, undefined);
  const toast = useToast();

  const [severity, setSeverity] = useState<string>("all");
  const [state, setState] = useState<string>("all");

  // Optimistic state transition shared by acknowledge + resolve: patch the
  // cached list immediately, roll back on error. Rollback is scoped to the one
  // alert that failed (by restoring its prior `state`) rather than restoring a
  // whole-list snapshot, so a failed action can't clobber other alerts'
  // in-flight optimistic updates when several are actioned in quick succession.
  //
  // The cache key is derived from each callback's own `tenantId` variable
  // rather than a render-closure constant: hook-level mutation callbacks run
  // with the latest render's closure, so if the operator switched tenant while
  // an action was in flight, a closure key would patch/roll back/invalidate the
  // wrong tenant's cache. Keying off the variable the mutation was fired with
  // keeps every step pinned to the tenant the action actually targeted.
  const optimistic = (next: typeof AlertState[keyof typeof AlertState]) => ({
    onMutate: async ({
      tenantId,
      alertId,
    }: {
      tenantId: string;
      alertId: string;
    }) => {
      const key = getListAlertsQueryKey(tenantId, undefined);
      await qc.cancelQueries({ queryKey: key });
      const prevState = qc
        .getQueryData<ListAlerts200>(key)
        ?.items?.find((a) => a.id === alertId)?.state;
      qc.setQueryData<ListAlerts200>(key, (old) =>
        old
          ? {
              ...old,
              items: (old.items ?? []).map((a) =>
                a.id === alertId ? { ...a, state: next } : a,
              ),
            }
          : old,
      );
      return { prevState };
    },
    onError: (
      _e: unknown,
      { tenantId, alertId }: { tenantId: string; alertId: string },
      ctx: { prevState?: Alert["state"] } | undefined,
    ) => {
      if (ctx?.prevState !== undefined) {
        const key = getListAlertsQueryKey(tenantId, undefined);
        qc.setQueryData<ListAlerts200>(key, (old) =>
          old
            ? {
                ...old,
                items: (old.items ?? []).map((a) =>
                  a.id === alertId ? { ...a, state: ctx.prevState! } : a,
                ),
              }
            : old,
        );
      }
      toast.error("Action failed", "The alert could not be updated.");
    },
    onSettled: (
      _d: unknown,
      _e: unknown,
      { tenantId }: { tenantId: string; alertId: string },
    ) =>
      qc.invalidateQueries({
        queryKey: getListAlertsQueryKey(tenantId, undefined),
      }),
  });

  const ack = useAcknowledgeAlert({
    mutation: {
      ...optimistic(AlertState.acknowledged),
      onSuccess: () => toast.success("Acknowledged", "Alert marked as acknowledged."),
    },
  });
  const resolve = useResolveAlert({
    mutation: {
      ...optimistic(AlertState.resolved),
      onSuccess: () => toast.success("Resolved", "Alert marked as resolved."),
    },
  });

  const all = list.data?.items ?? [];
  const filtered = all.filter(
    (a) =>
      (severity === "all" || a.severity === severity) &&
      (state === "all" || a.state === state),
  );

  // Group filtered alerts by AI-correlated incident.
  const clusters = correlations.data?.items ?? [];
  const alertToCluster = new Map<string, string>();
  for (const c of clusters) {
    for (const id of c.alert_ids ?? []) alertToCluster.set(id, c.id);
  }
  const incidents = clusters
    .map((c) => ({
      cluster: c,
      alerts: filtered.filter((a) => (c.alert_ids ?? []).includes(a.id)),
    }))
    .filter((g) => g.alerts.length > 0);
  const ungrouped = filtered.filter((a) => !alertToCluster.has(a.id));

  const scatterData = all.map((a) => ({
    x: new Date(a.created_at).getTime(),
    y: a.z_score,
    z: Math.abs(a.z_score),
    kind: a.kind,
  }));

  const severityOptions = ["all", ...Object.values(AlertSeverity)];
  const stateOptions = ["all", ...Object.values(AlertState)];

  const renderCard = (a: Alert) => (
    <div key={a.id} className={`alert-card alert-card--${a.severity}`}>
      <div className="alert-card__head">
        <StatusBadge status={a.severity} />
        <span className="mono alert-card__kind">{a.kind}</span>
        <StatusBadge status={a.state} />
        <span className="alert-card__when muted">{formatRelative(a.created_at)}</span>
      </div>
      <div className="alert-card__desc">
        {a.summary || `Anomaly on ${a.dimension}.`}
      </div>
      <div className="alert-card__meta">
        <span>
          <span className="muted">Affected:</span> {a.dimension}
        </span>
        <span className="mono">
          {a.observed_value?.toFixed(1)} vs {a.baseline_mean?.toFixed(1)}±
          {a.baseline_stddev?.toFixed(1)} (z {a.z_score?.toFixed(2)})
        </span>
      </div>
      <div className="alert-card__rec">
        <span className="muted">Recommended:</span>{" "}
        {RECOMMENDED[a.severity] ?? RECOMMENDED.info}
      </div>
      <div className="alert-card__actions">
        <button
          className="btn btn--sm"
          disabled={a.state !== "open" || ack.isPending}
          onClick={() => ack.mutate({ tenantId, alertId: a.id })}
        >
          Acknowledge
        </button>
        <button
          className="btn btn--sm btn--primary"
          disabled={a.state === "resolved" || resolve.isPending}
          onClick={() => resolve.mutate({ tenantId, alertId: a.id })}
        >
          Resolve
        </button>
        <Link
          to="/troubleshoot"
          className="btn btn--sm"
          title="Open troubleshooting tools"
        >
          Investigate
        </Link>
        <Link
          to="/playbooks"
          className="btn btn--sm"
          title="Trigger an automated response playbook"
        >
          Auto-remediate
        </Link>
      </div>
    </div>
  );

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle="Baseline anomaly detections, grouped into incidents with recommended actions."
        actions={
          <HelpTooltip title="How alerts work" align="right">
            ShieldNet learns what's normal for your traffic, then flags
            statistically significant deviations (z-score). Related anomalies
            are grouped into a single incident by the AI correlation engine.
          </HelpTooltip>
        }
      />

      <Card title="Anomaly scatter — deviation (z-score) over time">
        {scatterData.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="alert" />}
            title="No anomalies recorded"
            description="Deviation telemetry will plot here once anomalies are detected."
          />
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

      <div className="filter-bar" style={{ marginTop: 16 }}>
        <div className="pill-tabs">
          {severityOptions.map((s) => (
            <button
              key={s}
              className={severity === s ? "active" : ""}
              onClick={() => setSeverity(s)}
            >
              {titleCase(s)}
            </button>
          ))}
        </div>
        <div className="pill-tabs">
          {stateOptions.map((s) => (
            <button
              key={s}
              className={state === s ? "active" : ""}
              onClick={() => setState(s)}
            >
              {titleCase(s)}
            </button>
          ))}
        </div>
        <div className="toolbar__spacer" />
        <span className="muted">
          {baselines.data?.items?.length ?? 0} baseline models trained
        </span>
      </div>

      {list.isLoading ? (
        <SkeletonCard lines={4} />
      ) : list.error ? (
        <Card>
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <EmptyState
            illustration={<EmptyIllustration kind="alert" />}
            title="No matching alerts"
            description="Nothing matches the current filters. Try widening severity or state."
          />
        </Card>
      ) : (
        <>
          {correlations.isError && (
            <p className="muted" style={{ marginTop: 0 }}>
              Incident grouping is temporarily unavailable — alerts are shown
              individually below.
            </p>
          )}
          {incidents.map(({ cluster, alerts }) => (
            <Card
              key={cluster.id || cluster.summary}
              title={`Incident · ${alerts.length} correlated alert${alerts.length === 1 ? "" : "s"}`}
              actions={
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  {cluster.severity && <StatusBadge status={cluster.severity} />}
                  {cluster.status && <Badge tone="info">{titleCase(cluster.status)}</Badge>}
                </div>
              }
            >
              {cluster.summary && (
                <p className="muted" style={{ marginTop: 0 }}>
                  {cluster.summary}
                </p>
              )}
              <div className="alert-cards">{alerts.map(renderCard)}</div>
            </Card>
          ))}

          <Card title={incidents.length > 0 ? "Other alerts" : "Alerts"}>
            {ungrouped.length === 0 ? (
              <p className="muted">All matching alerts are part of an incident above.</p>
            ) : (
              <div className="alert-cards">{ungrouped.map(renderCard)}</div>
            )}
          </Card>
        </>
      )}
    </>
  );
}
