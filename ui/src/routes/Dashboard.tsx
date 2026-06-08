import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
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
      title: "Add your first site",
      desc: "Connect a location so traffic starts flowing through the gateway.",
      to: "/onboarding",
      tone: "warn",
      cta: "Set up",
    });
  if (devicesCount === 0)
    derived.push({
      id: "enroll-device",
      title: "Enrol your first device",
      desc: "Install the agent and claim a device to begin protection.",
      to: "/onboarding",
      tone: "warn",
      cta: "Enrol",
    });
  if (openCritical.length > 0)
    derived.push({
      id: "critical-alerts",
      title: `Resolve ${openCritical.length} critical alert${openCritical.length > 1 ? "s" : ""}`,
      desc: "Critical anomalies are open and need triage.",
      to: "/alerts",
      tone: "danger",
      cta: "Review",
    });
  const hardExceeded = (usage.data?.lines ?? []).filter((l) => l.hard_exceeded);
  if (hardExceeded.length > 0)
    derived.push({
      id: "usage-limit",
      title: "Usage over a hard limit",
      desc: `${hardExceeded.map((l) => titleCase(l.meter)).join(", ")} exceeded its cap.`,
      to: "/metering",
      tone: "danger",
      cta: "Open",
    });
  const weakest = componentScores.find((c) => c.score < 70);
  if (weakest)
    derived.push({
      id: `weak-${weakest.key}`,
      title: `Improve ${weakest.label} (${weakest.score}/100)`,
      desc: "This operational component is dragging your security score down.",
      to: "/policy",
      tone: weakest.score < 50 ? "danger" : "warn",
      cta: "Tune",
    });

  const recommendations = posture.data?.recommendations ?? [];
  const recActions: QuickAction[] = recommendations.map((r, i) => ({
    id: `rec-${i}`,
    title: r,
    to: "/policy",
    tone: "info",
    cta: "Review",
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
    periodTotals.set(l.period, (periodTotals.get(l.period) ?? 0) + l.used);
  }
  const sortedPeriods = [...periodTotals.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  );
  const last = sortedPeriods.at(-1)?.[1];
  const prev = sortedPeriods.at(-2)?.[1];
  const trend: "up" | "down" | "flat" =
    last != null && prev != null
      ? last > prev * 1.02
        ? "up"
        : last < prev * 0.98
          ? "down"
          : "flat"
      : "flat";

  const alertColumns: Column<Alert>[] = [
    { header: "Severity", cell: (a) => <StatusBadge status={a.severity} /> },
    { header: "Kind", cell: (a) => <span className="mono">{a.kind}</span> },
    { header: "Dimension", cell: (a) => a.dimension },
    { header: "Z-score", cell: (a) => a.z_score?.toFixed(2) },
    { header: "State", cell: (a) => <StatusBadge status={a.state} /> },
    { header: "When", cell: (a) => formatRelative(a.created_at) },
  ];

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={
          selectedTenant
            ? `Security posture for ${selectedTenant.name}`
            : "Security posture at a glance"
        }
      />

      {isEmptyTenant && (
        <div className="banner">
          <div className="score-ring" style={{ ["--ring-size" as string]: "56px" }}>
            <span style={{ fontSize: 28 }}>🚀</span>
          </div>
          <div className="banner__body">
            <div className="banner__title">Let's get you protected</div>
            <div className="banner__sub">
              This tenant has no sites or devices yet. The guided setup walks
              you through protection in about 5 minutes.
            </div>
          </div>
          <Link to="/onboarding" className="btn btn--primary">
            Get started →
          </Link>
        </div>
      )}

      <div className="grid grid--stats" style={{ marginBottom: 16 }}>
        <Stat label="Tenants" value={tenants.length} />
        <Stat
          label="Sites"
          value={sites.isLoading ? "—" : sitesCount}
          delta={selectedTenant ? `tier: ${selectedTenant.tier}` : undefined}
        />
        <Stat
          label="Devices"
          value={devices.isLoading ? "—" : devicesCount}
        />
        <Stat
          label="Open alerts"
          value={alerts.isLoading ? "—" : openAlerts.length}
          delta={
            openAlerts.length > 0 ? (
              <span style={{ color: "var(--warn)" }}>needs attention</span>
            ) : (
              <span style={{ color: "var(--ok)" }}>all clear</span>
            )
          }
        />
      </div>

      <div className="grid grid--dash" style={{ marginBottom: 16 }}>
        {/* Security score hero */}
        {ops.isLoading ? (
          <SkeletonCard lines={4} />
        ) : (
          <Card title="Security score">
            <div className="hero">
              <CircularScore value={healthScore} />
              <div className="hero__body">
                {healthScore == null ? (
                  <p className="muted">
                    No operational health snapshot has been recorded for this
                    tenant yet.
                  </p>
                ) : (
                  <>
                    <p className="hero__sub">
                      Composite of {componentScores.length || "your"}{" "}
                      operational components.
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
          title="Quick actions"
          actions={
            <HelpTooltip title="Quick actions" align="right">
              The most impactful next steps, derived from your live posture —
              open alerts, weak components, setup gaps and AI recommendations.
            </HelpTooltip>
          }
        >
          {quickActions.length === 0 ? (
            <p className="muted">
              Nothing needs your attention right now. Nicely done.
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
          title="Estimated monthly cost"
          actions={
            <HelpTooltip title="How this is estimated" align="right">
              Based on {seats} enrolled device{seats === 1 ? "" : "s"} at the
              ${PRICE_PER_SEAT}/user list price (published range $5–12). This is
              an estimate — connect billing for exact, contracted figures.
            </HelpTooltip>
          }
        >
          <div className="cost-amount">
            {seats > 0 ? `$${formatNumber(monthlyCost)}` : "—"}
            <span className="muted" style={{ fontSize: 14, fontWeight: 400 }}>
              {" "}
              / mo
            </span>
          </div>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
            {seats > 0
              ? `${seats} user${seats === 1 ? "" : "s"} × $${PRICE_PER_SEAT}/mo`
              : "Enrol devices to project a cost."}
          </div>
          <div style={{ marginTop: 12 }}>
            <span className={`trend trend--${trend}`}>
              {trend === "up" ? "▲" : trend === "down" ? "▼" : "▬"}{" "}
              {trend === "up"
                ? "Usage trending up"
                : trend === "down"
                  ? "Usage trending down"
                  : "Usage stable"}
            </span>
          </div>
        </Card>

        {/* Policy coverage */}
        <Card
          title="Policy coverage"
          actions={
            <HelpTooltip title="Policy coverage" align="right">
              How much of your operational surface is actively governed by
              policy. Component scores come from the latest ops-health snapshot;
              overall coverage comes from the AI posture report.
            </HelpTooltip>
          }
        >
          {coveragePct == null && componentScores.length === 0 ? (
            <p className="muted">
              Coverage data appears once a posture report or ops-health snapshot
              exists.
            </p>
          ) : (
            <>
              {coveragePct != null && (
                <div className="meter">
                  <div className="meter__head">
                    <span>
                      Overall coverage
                      {activePolicies != null && totalPolicies != null && (
                        <span className="muted">
                          {" "}
                          · {activePolicies}/{totalPolicies} policies active
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
          title="Threat activity by region"
          className="span-2"
          actions={
            <HelpTooltip title="Threat activity" align="right">
              Plots the tenant's deployment region, sized by currently-open
              threats. Per-origin geo-IP attribution isn't available from the
              control plane, so this reflects where your protected traffic is
              served from.
            </HelpTooltip>
          }
        >
          <ThreatMap points={threatPoints} />
        </Card>
      </div>

      {/* Activity over the last 24h */}
      <Card
        title="Security activity (last 24h)"
        actions={
          <HelpTooltip title="Security activity" align="right">
            Hourly count of detected anomalies over the last 24 hours, stacked
            by severity. Sourced from the live alert stream.
          </HelpTooltip>
        }
      >
        {alerts.isLoading ? (
          <div className="skeleton" style={{ height: 220 }} />
        ) : activityTotal === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title="All clear"
            description="No anomalies detected in the last 24 hours."
          />
        ) : (
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={buckets} margin={{ top: 8, right: 12, bottom: 0, left: -16 }}>
                <defs>
                  <linearGradient id="gInfo" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gWarn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#fbbf24" stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f87171" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#f87171" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#243352" vertical={false} />
                <XAxis
                  dataKey="label"
                  tick={{ fill: "#9fb0cc", fontSize: 10 }}
                  interval={3}
                />
                <YAxis allowDecimals={false} tick={{ fill: "#9fb0cc", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    background: "#111a2e",
                    border: "1px solid #243352",
                    borderRadius: 8,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  stroke="#f87171"
                  fill="url(#gCrit)"
                />
                <Area
                  type="monotone"
                  dataKey="warning"
                  stackId="1"
                  stroke="#fbbf24"
                  fill="url(#gWarn)"
                />
                <Area
                  type="monotone"
                  dataKey="info"
                  stackId="1"
                  stroke="#3b82f6"
                  fill="url(#gInfo)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <Card title="Recent alerts" className="" >
        {alerts.isLoading ? (
          <div className="skeleton" style={{ height: 120 }} />
        ) : recentAlerts.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title="No alerts"
            description="Nothing needs your attention right now."
          />
        ) : (
          <>
            <DataTable columns={alertColumns} rows={recentAlerts} rowKey={(a) => a.id} />
            <div style={{ marginTop: 12 }}>
              <Link to="/alerts" className="btn btn--sm">
                View all alerts →
              </Link>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
