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
import { CHART, CHART_TOOLTIP } from "@/lib/chart-theme";
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
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { isForbidden, PermissionDenied } from "./lane-b4-ui";
import type { LaneKey } from "./lane-b4-messages";

export function Alerts() {
  return (
    <LaneB4Screen>
      <RequireTenant>{(tenantId) => <AlertsInner tenantId={tenantId} />}</RequireTenant>
    </LaneB4Screen>
  );
}

const SEVERITY_LABEL = new Map<string, LaneKey>([
  ["all", "alerts.filter.all"],
  ["info", "alerts.severity.info"],
  ["warning", "alerts.severity.warning"],
  ["critical", "alerts.severity.critical"],
]);
const STATE_LABEL = new Map<string, LaneKey>([
  ["all", "alerts.filter.all"],
  ["open", "alerts.state.open"],
  ["acknowledged", "alerts.state.acknowledged"],
  ["resolved", "alerts.state.resolved"],
  ["suppressed", "alerts.state.suppressed"],
]);

function recKey(severity: string): LaneKey {
  if (severity === AlertSeverity.critical) return "alerts.rec.critical";
  if (severity === AlertSeverity.warning) return "alerts.rec.warning";
  return "alerts.rec.info";
}

function AlertsInner({ tenantId }: { tenantId: string }) {
  const t = useT();
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
      toast.error(t("alerts.toast.failTitle"), t("alerts.toast.failBody"));
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
      onSuccess: () => toast.success(t("alerts.toast.ackTitle"), t("alerts.toast.ackBody")),
    },
  });
  const resolve = useResolveAlert({
    mutation: {
      ...optimistic(AlertState.resolved),
      onSuccess: () => toast.success(t("alerts.toast.resolveTitle"), t("alerts.toast.resolveBody")),
    },
  });

  if (isForbidden(list.error)) return <PermissionDenied />;

  const all = list.data?.items ?? [];
  const filtered = all.filter(
    (a) =>
      (severity === "all" || a.severity === severity) &&
      (state === "all" || a.state === state),
  );

  // Group filtered alerts by AI-correlated incident. The list endpoint returns
  // the correlations under `items` (each an AICorrelation with id + alert_ids).
  const clusters = correlations.data?.items ?? [];
  const groupedAlertIds = new Set<string>();
  for (const c of clusters) {
    for (const id of c.alert_ids ?? []) groupedAlertIds.add(id);
  }
  const incidents = clusters
    .map((c) => ({
      cluster: c,
      alerts: filtered.filter((a) => (c.alert_ids ?? []).includes(a.id)),
    }))
    .filter((g) => g.alerts.length > 0);
  const ungrouped = filtered.filter((a) => !groupedAlertIds.has(a.id));

  const scatterData = all.map((a) => ({
    x: new Date(a.created_at).getTime(),
    y: a.z_score,
    z: Math.abs(a.z_score),
    kind: a.kind,
  }));
  const beyondThreshold = scatterData.filter((d) => Math.abs(d.y) >= 3).length;
  const chartSummary = t("alerts.chart.summary", {
    count: scatterData.length,
    beyond: beyondThreshold,
  });

  const severityOptions = ["all", ...Object.values(AlertSeverity)];
  const stateOptions = ["all", ...Object.values(AlertState)];
  const sevLabel = (s: string) =>
    SEVERITY_LABEL.has(s) ? t(SEVERITY_LABEL.get(s)!) : titleCase(s);
  const stateLabel = (s: string) =>
    STATE_LABEL.has(s) ? t(STATE_LABEL.get(s)!) : titleCase(s);

  const renderCard = (a: Alert) => (
    <div key={a.id} className={`alert-card alert-card--${a.severity}`}>
      <div className="alert-card__head">
        <StatusBadge status={a.severity} />
        <span className="mono alert-card__kind">{a.kind}</span>
        <StatusBadge status={a.state} />
        <span className="alert-card__when muted">{formatRelative(a.created_at)}</span>
      </div>
      <div className="alert-card__desc">
        {a.summary || t("alerts.card.fallbackSummary", { dimension: a.dimension })}
      </div>
      <div className="alert-card__meta">
        <span>
          <span className="muted">{t("alerts.card.affected")}</span> {a.dimension}
        </span>
        <span className="mono">
          {t("alerts.card.metric", {
            observed: a.observed_value?.toFixed(1) ?? "—",
            baseline: a.baseline_mean?.toFixed(1) ?? "—",
            stddev: a.baseline_stddev?.toFixed(1) ?? "—",
            z: a.z_score?.toFixed(2) ?? "—",
          })}
        </span>
      </div>
      <div className="alert-card__rec">
        <span className="muted">{t("alerts.card.recommended")}</span> {t(recKey(a.severity))}
      </div>
      <div className="alert-card__actions">
        <button
          className="btn btn--sm"
          disabled={a.state !== "open" || ack.isPending}
          onClick={() => ack.mutate({ tenantId, alertId: a.id })}
        >
          {t("alerts.action.acknowledge")}
        </button>
        <button
          className="btn btn--sm btn--primary"
          disabled={a.state === "resolved" || resolve.isPending}
          onClick={() => resolve.mutate({ tenantId, alertId: a.id })}
        >
          {t("alerts.action.resolve")}
        </button>
        <Link to="/troubleshoot" className="btn btn--sm" title={t("alerts.action.investigate.hint")}>
          {t("alerts.action.investigate")}
        </Link>
        <Link to="/playbooks" className="btn btn--sm" title={t("alerts.action.remediate.hint")}>
          {t("alerts.action.remediate")}
        </Link>
      </div>
    </div>
  );

  return (
    <>
      <PageHeader
        title={t("alerts.title")}
        subtitle={t("alerts.subtitle")}
        actions={
          <HelpTooltip title={t("alerts.help.title")} align="right">
            {t("alerts.help.body")}
          </HelpTooltip>
        }
      />

      <Card title={t("alerts.chart.title")}>
        {scatterData.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="alert" />}
            title={t("alerts.chart.empty.title")}
            description={t("alerts.chart.empty.desc")}
          />
        ) : (
          <div style={{ height: 260 }} role="img" aria-label={chartSummary}>
            <div aria-hidden="true" style={{ height: "100%" }}>
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                  <CartesianGrid stroke={CHART.border} />
                  <XAxis
                    type="number"
                    dataKey="x"
                    domain={["dataMin", "dataMax"]}
                    tickFormatter={(v) => new Date(v).toLocaleDateString()}
                    tick={{ fill: CHART.axis, fontSize: 11 }}
                  />
                  <YAxis
                    type="number"
                    dataKey="y"
                    tick={{ fill: CHART.axis, fontSize: 11 }}
                    label={{ value: t("alerts.chart.yLabel"), angle: -90, fill: CHART.axis, fontSize: 11 }}
                  />
                  <ZAxis type="number" dataKey="z" range={[40, 400]} />
                  <ReferenceLine y={3} stroke={CHART.danger} strokeDasharray="4 4" />
                  <ReferenceLine y={-3} stroke={CHART.danger} strokeDasharray="4 4" />
                  <Tooltip
                    cursor={{ strokeDasharray: "3 3" }}
                    contentStyle={CHART_TOOLTIP}
                    labelFormatter={(v) => new Date(v).toLocaleString()}
                  />
                  <Scatter data={scatterData} fill={CHART.accent} fillOpacity={0.7} />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </Card>

      <div className="filter-bar" style={{ marginTop: 16 }}>
        <div className="pill-tabs" role="group" aria-label={t("alerts.filter.severity")}>
          {severityOptions.map((s) => (
            <button
              key={s}
              className={severity === s ? "active" : ""}
              aria-pressed={severity === s}
              onClick={() => setSeverity(s)}
            >
              {sevLabel(s)}
            </button>
          ))}
        </div>
        <div className="pill-tabs" role="group" aria-label={t("alerts.filter.state")}>
          {stateOptions.map((s) => (
            <button
              key={s}
              className={state === s ? "active" : ""}
              aria-pressed={state === s}
              onClick={() => setState(s)}
            >
              {stateLabel(s)}
            </button>
          ))}
        </div>
        <div className="toolbar__spacer" />
        <span className="muted">
          {t("alerts.baselines", { count: baselines.data?.items?.length ?? 0 })}
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
            title={t("alerts.empty.title")}
            description={t("alerts.empty.desc")}
          />
        </Card>
      ) : (
        <>
          {correlations.isError && (
            <p className="muted" style={{ marginTop: 0 }}>
              {t("alerts.incident.unavailable")}
            </p>
          )}
          {incidents.map(({ cluster, alerts }) => (
            <Card
              key={cluster.id || cluster.summary}
              title={t("alerts.incident.title", { count: alerts.length })}
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

          <Card title={incidents.length > 0 ? t("alerts.other.title") : t("alerts.list.title")}>
            {ungrouped.length === 0 ? (
              <p className="muted">{t("alerts.other.allGrouped")}</p>
            ) : (
              <div className="alert-cards">{ungrouped.map(renderCard)}</div>
            )}
          </Card>
        </>
      )}
    </>
  );
}
