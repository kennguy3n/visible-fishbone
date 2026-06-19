import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { FormattedMessage, useIntl } from "react-intl";
import { Icon } from "@/components/Icon";
import { CHART, CHART_TOOLTIP } from "@/lib/chart-theme";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useTenant } from "@/lib/tenant-context";
import { useListSites } from "@/api/generated/endpoints/sites/sites";
import { useListDevices } from "@/api/generated/endpoints/devices/devices";
import { useListAlerts } from "@/api/generated/endpoints/alert/alert";
import { useGetOpsHealthLatest } from "@/api/generated/endpoints/ops-health/ops-health";
import { useAiGetPostureReport } from "@/api/generated/endpoints/ai/ai";
import { useUsage, useUsageHistory } from "@/api/manual/hooks";
import {
  PageHeader,
  Stat,
  Card,
  StatusBadge,
  Badge,
  SkeletonCard,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { CircularScore } from "@/components/CircularScore";
import { HelpTooltip } from "@/components/HelpTooltip";
import { ThreatMap } from "@/components/ThreatMap";
import { REGION_COORDS, type ThreatPoint } from "@/components/threat-regions";
import { DataTable, type Column } from "@/components/DataTable";
import { formatNumber, formatRelative, titleCase } from "@/lib/format";
import type { Alert } from "@/api/generated/model";
import { LaneB1Intl } from "./lane-b1-intl";
import "./lane-b1.css";

// Midpoint of ShieldNet's published $5–12 / user list pricing. Used only for
// the at-a-glance cost projection; the disclaimer + tooltip make the
// assumption explicit (there is no billing-rate endpoint to read an exact
// contracted price from).
const PRICE_PER_SEAT = 7;

const TONE_COLOR: Record<string, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  danger: "var(--danger)",
  info: "var(--brand)",
};

interface QuickAction {
  id: string;
  title: string;
  desc?: string;
  to: string;
  tone: "ok" | "warn" | "danger" | "info";
  cta: string;
}

export function Dashboard() {
  return (
    <LaneB1Intl>
      <DashboardInner />
    </LaneB1Intl>
  );
}

function DashboardInner() {
  const intl = useIntl();
  const { tenants, selectedTenantId, selectedTenant } = useTenant();
  const tenantId = selectedTenantId ?? "";
  const enabled = { query: { enabled: !!tenantId } };

  const sites = useListSites(tenantId, enabled);
  const devices = useListDevices(tenantId, undefined, enabled);
  const alerts = useListAlerts(tenantId, undefined, enabled);
  const ops = useGetOpsHealthLatest(tenantId, {
    query: { enabled: !!tenantId, retry: false },
  });
  const posture = useAiGetPostureReport(tenantId, {
    query: { enabled: !!tenantId, retry: false },
  });
  const usage = useUsage(tenantId);
  const usageHistory = useUsageHistory(tenantId);

  const allAlerts = alerts.data?.items ?? [];
  const openAlerts = allAlerts.filter(
    (a) => a.state === "open" || a.state === "acknowledged",
  );
  const openCritical = openAlerts.filter((a) => a.severity === "critical");
  const recentAlerts = allAlerts.slice(0, 8);

  const sitesCount = sites.data?.items?.length ?? 0;
  const devicesCount = devices.data?.items?.length ?? 0;
  const baseDataReady = !sites.isLoading && !devices.isLoading;
  const isEmptyTenant =
    !!tenantId && baseDataReady && sitesCount === 0 && devicesCount === 0;

  const healthScore = ops.data?.health_score ?? null;
  const componentScores = Object.entries(ops.data?.component_scores ?? {})
    .map(([k, v]) => ({ key: k, label: titleCase(k), score: Number(v) || 0 }))
    .sort((a, b) => a.score - b.score);

  // --- Quick actions: concrete, derived-from-real-state actions first, then
  // any AI posture recommendations to fill the top-3.
  const derived: QuickAction[] = [];
  if (sitesCount === 0)
    derived.push({
      id: "add-site",
      title: intl.formatMessage({ id: "b1.dash.qa.addSite.title" }),
      desc: intl.formatMessage({ id: "b1.dash.qa.addSite.desc" }),
      to: "/onboarding",
      tone: "warn",
      cta: intl.formatMessage({ id: "b1.dash.qa.addSite.cta" }),
    });
  if (devicesCount === 0)
    derived.push({
      id: "enroll-device",
      title: intl.formatMessage({ id: "b1.dash.qa.enrolDevice.title" }),
      desc: intl.formatMessage({ id: "b1.dash.qa.enrolDevice.desc" }),
      to: "/onboarding",
      tone: "warn",
      cta: intl.formatMessage({ id: "b1.dash.qa.enrolDevice.cta" }),
    });
  if (openCritical.length > 0)
    derived.push({
      id: "critical-alerts",
      title: intl.formatMessage(
        { id: "b1.dash.qa.critical.title" },
        { count: openCritical.length },
      ),
      desc: intl.formatMessage({ id: "b1.dash.qa.critical.desc" }),
      to: "/alerts",
      tone: "danger",
      cta: intl.formatMessage({ id: "b1.dash.qa.critical.cta" }),
    });
  const hardExceeded = (usage.data?.lines ?? []).filter((l) => l.hard_exceeded);
  if (hardExceeded.length > 0)
    derived.push({
      id: "usage-limit",
      title: intl.formatMessage({ id: "b1.dash.qa.usage.title" }),
      desc: intl.formatMessage(
        { id: "b1.dash.qa.usage.desc" },
        { meters: hardExceeded.map((l) => titleCase(l.meter)).join(", ") },
      ),
      to: "/metering",
      tone: "danger",
      cta: intl.formatMessage({ id: "b1.dash.qa.usage.cta" }),
    });
  const weakest = componentScores.find((c) => c.score < 70);
  if (weakest)
    derived.push({
      id: `weak-${weakest.key}`,
      title: intl.formatMessage(
        { id: "b1.dash.qa.weak.title" },
        { label: weakest.label, score: weakest.score },
      ),
      desc: intl.formatMessage({ id: "b1.dash.qa.weak.desc" }),
      to: "/policy",
      tone: weakest.score < 50 ? "danger" : "warn",
      cta: intl.formatMessage({ id: "b1.dash.qa.weak.cta" }),
    });

  const recommendations = posture.data?.recommendations ?? [];
  const recActions: QuickAction[] = recommendations.map((r, i) => ({
    id: `rec-${i}`,
    title: r,
    to: "/policy",
    tone: "info",
    cta: intl.formatMessage({ id: "b1.dash.qa.review" }),
  }));
  const quickActions = [...derived, ...recActions].slice(0, 3);

  // --- Threat map: we have no per-flow geo-IP telemetry endpoint, so the only
  // factual location is the tenant's deployment region. Size the marker by the
  // count of open critical alerts (a proxy for currently-blocked threats).
  const region = selectedTenant?.region;
  const regionCoord = region ? REGION_COORDS[region.toLowerCase()] : undefined;
  const threatPoints: ThreatPoint[] =
    regionCoord && (openCritical.length > 0 || openAlerts.length > 0)
      ? [
          {
            id: region as string,
            label: regionCoord.label,
            lat: regionCoord.lat,
            lng: regionCoord.lng,
            count: openCritical.length || openAlerts.length,
          },
        ]
      : [];

  // --- Activity (last 24h): bucket the real alert stream into hourly slots by
  // severity for a stacked area chart. Memoized on the alert list and `now`
  // rounded to the minute, so unrelated re-renders don't recompute the buckets
  // (or shift alerts across hour boundaries) on every render.
  const { buckets, activityTotal } = useMemo(() => {
    const HOUR = 3_600_000;
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    const slots = Array.from({ length: 24 }, (_, i) => {
      const start = now - (23 - i) * HOUR;
      return {
        label: new Date(start).toLocaleTimeString(undefined, { hour: "2-digit" }),
        info: 0,
        warning: 0,
        critical: 0,
      };
    });
    for (const a of allAlerts) {
      const t = new Date(a.created_at).getTime();
      const idx = 23 - Math.floor((now - t) / HOUR);
      if (idx >= 0 && idx < 24) {
        const sev = a.severity as "info" | "warning" | "critical";
        if (sev in slots[idx]) slots[idx][sev] += 1;
      }
    }
    const total = slots.reduce((s, b) => s + b.info + b.warning + b.critical, 0);
    return { buckets: slots, activityTotal: total };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts.data?.items]);

  // --- Policy coverage: real coverage % from the posture report, plus the
  // per-component operational scores from ops-health rendered as meters.
  const coveragePct = posture.data?.policy_health?.coverage_pct ?? null;
  const activePolicies = posture.data?.policy_health?.active_policies;
  const totalPolicies = posture.data?.policy_health?.total_policies;

  // --- Cost estimate.
  const seats = devicesCount;
  const monthlyCost = seats * PRICE_PER_SEAT;
  const periodTotals = new Map<string, number>();
  for (const l of usageHistory.data?.lines ?? []) {
    const period = l.period_start.slice(0, 7); // YYYY-MM
    periodTotals.set(period, (periodTotals.get(period) ?? 0) + l.value);
  }
  const sortedPeriods = [...periodTotals.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  );
  // The latest period is the in-progress month (a partial total) that would
  // always read as a drop, so trend the completed months only.
  const completedPeriods = sortedPeriods.slice(0, -1);
  const last = completedPeriods.at(-1)?.[1];
  const prev = completedPeriods.at(-2)?.[1];
  const trend: "up" | "down" | "flat" =
    last != null && prev != null
      ? last > prev * 1.02
        ? "up"
        : last < prev * 0.98
          ? "down"
          : "flat"
      : "flat";

  const alertColumns: Column<Alert>[] = [
    {
      header: intl.formatMessage({ id: "b1.dash.col.severity" }),
      cell: (a) => <StatusBadge status={a.severity} />,
    },
    {
      header: intl.formatMessage({ id: "b1.dash.col.kind" }),
      cell: (a) => <span className="mono">{a.kind}</span>,
    },
    { header: intl.formatMessage({ id: "b1.dash.col.dimension" }), cell: (a) => a.dimension },
    { header: intl.formatMessage({ id: "b1.dash.col.zscore" }), cell: (a) => a.z_score?.toFixed(2) },
    {
      header: intl.formatMessage({ id: "b1.dash.col.state" }),
      cell: (a) => <StatusBadge status={a.state} />,
    },
    { header: intl.formatMessage({ id: "b1.dash.col.when" }), cell: (a) => formatRelative(a.created_at) },
  ];

  return (
    <div className="lane-b1">
      <PageHeader
        title={intl.formatMessage({ id: "b1.dash.title" })}
        subtitle={
          selectedTenant
            ? intl.formatMessage({ id: "b1.dash.subtitle.tenant" }, { name: selectedTenant.name })
            : intl.formatMessage({ id: "b1.dash.subtitle.default" })
        }
      />

      {isEmptyTenant && (
        <div className="banner">
          <div className="score-ring" style={{ ["--ring-size" as string]: "56px" }}>
            <Icon name="rocket" size={26} />
          </div>
          <div className="banner__body">
            <div className="banner__title">
              <FormattedMessage id="b1.dash.banner.title" />
            </div>
            <div className="banner__sub">
              <FormattedMessage id="b1.dash.banner.sub" />
            </div>
          </div>
          <Link to="/onboarding" className="btn btn--primary">
            <FormattedMessage id="b1.dash.banner.cta" />
          </Link>
        </div>
      )}

      <div className="grid grid--stats" style={{ marginBottom: 16 }}>
        <Stat label={intl.formatMessage({ id: "b1.dash.stat.tenants" })} value={tenants.length} />
        <Stat
          label={intl.formatMessage({ id: "b1.dash.stat.sites" })}
          value={sites.isLoading ? "—" : sitesCount}
          delta={
            selectedTenant
              ? intl.formatMessage(
                  { id: "b1.dash.stat.sites.tier" },
                  { tier: titleCase(selectedTenant.tier) },
                )
              : undefined
          }
        />
        <Stat
          label={intl.formatMessage({ id: "b1.dash.stat.devices" })}
          value={devices.isLoading ? "—" : devicesCount}
        />
        <Stat
          label={intl.formatMessage({ id: "b1.dash.stat.openAlerts" })}
          value={alerts.isLoading ? "—" : openAlerts.length}
          delta={
            openAlerts.length > 0 ? (
              <span style={{ color: "var(--warn)" }}>
                <FormattedMessage id="b1.dash.stat.attention" />
              </span>
            ) : (
              <span style={{ color: "var(--ok)" }}>
                <FormattedMessage id="b1.dash.stat.clear" />
              </span>
            )
          }
        />
      </div>

      <div className="grid grid--dash" style={{ marginBottom: 16 }}>
        {/* Security score hero */}
        {ops.isLoading ? (
          <SkeletonCard lines={4} />
        ) : (
          <Card title={intl.formatMessage({ id: "b1.dash.score.title" })}>
            <div className="hero">
              <CircularScore value={healthScore} />
              <div className="hero__body">
                {healthScore == null ? (
                  <p className="muted">
                    <FormattedMessage id="b1.dash.score.none" />
                  </p>
                ) : (
                  <>
                    <p className="hero__sub">
                      <FormattedMessage
                        id="b1.dash.score.composite"
                        values={{ count: componentScores.length }}
                      />
                    </p>
                    <div className="hero__chips">
                      {componentScores.slice(0, 4).map((c) => (
                        <Badge
                          key={c.key}
                          tone={
                            c.score > 80 ? "ok" : c.score > 50 ? "warn" : "danger"
                          }
                        >
                          {c.label} {c.score}
                        </Badge>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>
          </Card>
        )}

        {/* Quick actions */}
        <Card
          title={intl.formatMessage({ id: "b1.dash.qa.title" })}
          actions={
            <HelpTooltip title={intl.formatMessage({ id: "b1.dash.qa.title" })} align="right">
              <FormattedMessage id="b1.dash.qa.help" />
            </HelpTooltip>
          }
        >
          {quickActions.length === 0 ? (
            <p className="muted">
              <FormattedMessage id="b1.dash.qa.none" />
            </p>
          ) : (
            <div className="qa-list">
              {quickActions.map((a) => (
                <div className="qa-item" key={a.id}>
                  <span
                    className="qa-item__dot"
                    style={{ background: TONE_COLOR[a.tone] }}
                  />
                  <div className="qa-item__body">
                    <div className="qa-item__title">{a.title}</div>
                    {a.desc && <div className="qa-item__desc">{a.desc}</div>}
                  </div>
                  <Link to={a.to} className="btn btn--sm">
                    {a.cta}
                  </Link>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Cost estimate */}
        <Card
          title={intl.formatMessage({ id: "b1.dash.cost.title" })}
          actions={
            <HelpTooltip title={intl.formatMessage({ id: "b1.dash.cost.title" })} align="right">
              <FormattedMessage
                id="b1.dash.cost.help"
                values={{ count: seats, price: PRICE_PER_SEAT }}
              />
            </HelpTooltip>
          }
        >
          <div className="cost-amount">
            {seats > 0 ? `$${formatNumber(monthlyCost)}` : "—"}
            <span className="muted" style={{ fontSize: 14, fontWeight: 400 }}>
              {" "}
              <FormattedMessage id="b1.dash.cost.perMo" />
            </span>
          </div>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
            {seats > 0 ? (
              <FormattedMessage
                id="b1.dash.cost.basis"
                values={{ count: seats, price: PRICE_PER_SEAT }}
              />
            ) : (
              <FormattedMessage id="b1.dash.cost.enrol" />
            )}
          </div>
          <div style={{ marginTop: 12 }}>
            <span className={`trend trend--${trend}`}>
              <svg
                width="11"
                height="11"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                {trend === "up" ? (
                  <path d="M2 9l4-5 4 5" />
                ) : trend === "down" ? (
                  <path d="M2 3l4 5 4-5" />
                ) : (
                  <path d="M2 6h8" />
                )}
              </svg>{" "}
              <FormattedMessage
                id={
                  trend === "up"
                    ? "b1.dash.cost.trend.up"
                    : trend === "down"
                      ? "b1.dash.cost.trend.down"
                      : "b1.dash.cost.trend.stable"
                }
              />
            </span>
          </div>
        </Card>

        {/* Policy coverage */}
        <Card
          title={intl.formatMessage({ id: "b1.dash.coverage.title" })}
          actions={
            <HelpTooltip title={intl.formatMessage({ id: "b1.dash.coverage.title" })} align="right">
              <FormattedMessage id="b1.dash.coverage.help" />
            </HelpTooltip>
          }
        >
          {coveragePct == null && componentScores.length === 0 ? (
            <p className="muted">
              <FormattedMessage id="b1.dash.coverage.none" />
            </p>
          ) : (
            <>
              {coveragePct != null && (
                <div className="meter">
                  <div className="meter__head">
                    <span>
                      <FormattedMessage id="b1.dash.coverage.overall" />
                      {activePolicies != null && totalPolicies != null && (
                        <span className="muted">
                          {" "}
                          <FormattedMessage
                            id="b1.dash.coverage.policies"
                            values={{ active: activePolicies, total: totalPolicies }}
                          />
                        </span>
                      )}
                    </span>
                    <b>{Math.round(coveragePct)}%</b>
                  </div>
                  <div className="meter__track">
                    <div
                      className={`meter__fill ${coveragePct > 80 ? "meter__fill--ok" : coveragePct > 50 ? "meter__fill--warn" : "meter__fill--danger"}`}
                      style={{ width: `${Math.min(100, coveragePct)}%` }}
                    />
                  </div>
                </div>
              )}
              {componentScores.slice(0, 6).map((c) => (
                <div className="meter" key={c.key}>
                  <div className="meter__head">
                    <span>{c.label}</span>
                    <b>{c.score}</b>
                  </div>
                  <div className="meter__track">
                    <div
                      className={`meter__fill ${c.score > 80 ? "meter__fill--ok" : c.score > 50 ? "meter__fill--warn" : "meter__fill--danger"}`}
                      style={{ width: `${Math.min(100, c.score)}%` }}
                    />
                  </div>
                </div>
              ))}
            </>
          )}
        </Card>

        {/* Threat map */}
        <Card
          title={intl.formatMessage({ id: "b1.dash.threat.title" })}
          className="span-2"
          actions={
            <HelpTooltip title={intl.formatMessage({ id: "b1.dash.threat.title" })} align="right">
              <FormattedMessage id="b1.dash.threat.help" />
            </HelpTooltip>
          }
        >
          <ThreatMap points={threatPoints} />
        </Card>
      </div>

      {/* Activity over the last 24h */}
      <Card
        title={intl.formatMessage({ id: "b1.dash.activity.title" })}
        actions={
          <HelpTooltip title={intl.formatMessage({ id: "b1.dash.activity.title" })} align="right">
            <FormattedMessage id="b1.dash.activity.help" />
          </HelpTooltip>
        }
      >
        {alerts.isLoading ? (
          <div className="skeleton" style={{ height: 220 }} />
        ) : activityTotal === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title={intl.formatMessage({ id: "b1.dash.activity.clear.title" })}
            description={intl.formatMessage({ id: "b1.dash.activity.clear.desc" })}
          />
        ) : (
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={buckets} margin={{ top: 8, right: 12, bottom: 0, left: -16 }}>
                <defs>
                  <linearGradient id="gInfo" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART.brand} stopOpacity={0.6} />
                    <stop offset="100%" stopColor={CHART.brand} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gWarn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART.warn} stopOpacity={0.6} />
                    <stop offset="100%" stopColor={CHART.warn} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART.danger} stopOpacity={0.6} />
                    <stop offset="100%" stopColor={CHART.danger} stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={CHART.border} vertical={false} />
                <XAxis
                  dataKey="label"
                  tick={{ fill: CHART.axis, fontSize: 10 }}
                  interval={3}
                />
                <YAxis allowDecimals={false} tick={{ fill: CHART.axis, fontSize: 11 }} />
                <Tooltip contentStyle={CHART_TOOLTIP} />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  stroke={CHART.danger}
                  fill="url(#gCrit)"
                />
                <Area
                  type="monotone"
                  dataKey="warning"
                  stackId="1"
                  stroke={CHART.warn}
                  fill="url(#gWarn)"
                />
                <Area
                  type="monotone"
                  dataKey="info"
                  stackId="1"
                  stroke={CHART.brand}
                  fill="url(#gInfo)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <Card title={intl.formatMessage({ id: "b1.dash.alerts.title" })}>
        {alerts.isLoading ? (
          <div className="skeleton" style={{ height: 120 }} />
        ) : recentAlerts.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title={intl.formatMessage({ id: "b1.dash.alerts.none.title" })}
            description={intl.formatMessage({ id: "b1.dash.alerts.none.desc" })}
          />
        ) : (
          <>
            <DataTable columns={alertColumns} rows={recentAlerts} rowKey={(a) => a.id} />
            <div style={{ marginTop: 12 }}>
              <Link to="/alerts" className="btn btn--sm">
                <FormattedMessage id="b1.dash.alerts.viewAll" />
              </Link>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
