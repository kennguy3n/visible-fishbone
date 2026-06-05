import { Link } from "@tanstack/react-router";
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";
import { useTenant } from "@/lib/tenant-context";
import { useListSites } from "@/api/generated/endpoints/sites/sites";
import { useListDevices } from "@/api/generated/endpoints/devices/devices";
import { useListAlerts } from "@/api/generated/endpoints/alert/alert";
import { useGetOpsHealthLatest } from "@/api/generated/endpoints/ops-health/ops-health";
import { PageHeader, Stat, Card, StatusBadge, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { formatRelative, titleCase } from "@/lib/format";
import type { Alert } from "@/api/generated/model";

export function Dashboard() {
  const { tenants, selectedTenantId, selectedTenant } = useTenant();
  const tenantId = selectedTenantId ?? "";

  const sites = useListSites(tenantId, { query: { enabled: !!tenantId } });
  const devices = useListDevices(tenantId, undefined, {
    query: { enabled: !!tenantId },
  });
  const alerts = useListAlerts(tenantId, undefined, {
    query: { enabled: !!tenantId },
  });
  const ops = useGetOpsHealthLatest(tenantId, {
    query: { enabled: !!tenantId, retry: false },
  });

  const openAlerts = (alerts.data?.items ?? []).filter(
    (a) => a.state === "open" || a.state === "acknowledged",
  );
  const recentAlerts = (alerts.data?.items ?? []).slice(0, 8);

  const componentScores = ops.data?.component_scores ?? {};
  const radarData = Object.entries(componentScores).map(([k, v]) => ({
    component: titleCase(k),
    score: typeof v === "number" ? v : 0,
  }));

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
            ? `Operational overview for ${selectedTenant.name}`
            : "Operational overview"
        }
      />

      <div className="grid grid--stats" style={{ marginBottom: 16 }}>
        <Stat label="Tenants" value={tenants.length} />
        <Stat
          label="Sites"
          value={sites.data?.items?.length ?? "—"}
          delta={selectedTenant ? `tier: ${selectedTenant.tier}` : undefined}
        />
        <Stat label="Devices" value={devices.data?.items?.length ?? "—"} />
        <Stat
          label="Open alerts"
          value={openAlerts.length}
          delta={
            openAlerts.length > 0 ? (
              <span style={{ color: "var(--warn)" }}>needs attention</span>
            ) : (
              <span style={{ color: "var(--ok)" }}>all clear</span>
            )
          }
        />
      </div>

      <div className="grid grid--2" style={{ marginBottom: 16 }}>
        <Card title="Operational health">
          {ops.isError ? (
            <p className="muted">
              No ops-health snapshot recorded for this tenant yet.
            </p>
          ) : radarData.length > 0 ? (
            <>
              <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
                <span style={{ fontSize: 34, fontWeight: 800 }}>
                  {ops.data?.health_score ?? "—"}
                </span>
                <span className="muted">/ 100 composite score</span>
              </div>
              <div style={{ height: 240 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#243352" />
                    <PolarAngleAxis
                      dataKey="component"
                      tick={{ fill: "#9fb0cc", fontSize: 11 }}
                    />
                    <Radar
                      dataKey="score"
                      stroke="#3b82f6"
                      fill="#3b82f6"
                      fillOpacity={0.35}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <p className="muted">Loading health snapshot…</p>
          )}
        </Card>

        <Card title="Tenant">
          {selectedTenant ? (
            <dl className="kv">
              <dt>Name</dt>
              <dd>{selectedTenant.name}</dd>
              <dt>Slug</dt>
              <dd className="mono">{selectedTenant.slug}</dd>
              <dt>Status</dt>
              <dd>
                <StatusBadge status={selectedTenant.status} />
              </dd>
              <dt>Tier</dt>
              <dd>
                <Badge tone="info">{titleCase(selectedTenant.tier)}</Badge>
              </dd>
              <dt>Region</dt>
              <dd>{selectedTenant.region ?? "—"}</dd>
              <dt>MSP owned</dt>
              <dd>{selectedTenant.msp_id ? "Yes" : "No"}</dd>
            </dl>
          ) : (
            <p className="muted">No tenant selected.</p>
          )}
        </Card>
      </div>

      <Card title="Recent alerts">
        {recentAlerts.length === 0 ? (
          <p className="muted">No alerts for this tenant.</p>
        ) : (
          <>
            <DataTable
              columns={alertColumns}
              rows={recentAlerts}
              rowKey={(a) => a.id}
            />
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
