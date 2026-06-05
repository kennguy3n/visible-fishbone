import {
  useListTenantAppRegistry,
  useGetTenantAppRegistryStats,
} from "@/api/generated/endpoints/app-registry/app-registry";
import type { EffectiveApp } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, Badge, Stat } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { titleCase } from "@/lib/format";

export function AppRegistry() {
  return (
    <RequireTenant>
      {(tenantId) => <AppRegistryInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function classTone(cls: string) {
  if (cls === "sanctioned" || cls === "allow") return "ok" as const;
  if (cls === "blocked" || cls === "deny") return "danger" as const;
  if (cls === "unsanctioned") return "warn" as const;
  return "neutral" as const;
}

function AppRegistryInner({ tenantId }: { tenantId: string }) {
  const list = useListTenantAppRegistry(tenantId);
  const stats = useGetTenantAppRegistryStats(tenantId, undefined);

  const s = stats.data as
    | { total?: number; overrides?: number; by_class?: Record<string, number> }
    | undefined;

  const cols: Column<EffectiveApp>[] = [
    { header: "Application", cell: (e) => e.app?.name ?? e.app?.id ?? "—" },
    { header: "Category", cell: (e) => <Badge tone="neutral">{titleCase(e.app?.category ?? "")}</Badge> },
    {
      header: "Effective class",
      cell: (e) => <Badge tone={classTone(e.effective_class)}>{titleCase(e.effective_class)}</Badge>,
    },
    {
      header: "Source",
      cell: (e) => (
        <Badge tone={e.source === "override" ? "info" : "neutral"}>{titleCase(e.source)}</Badge>
      ),
    },
    {
      header: "Override reason",
      cell: (e) => e.override_reason ?? "—",
    },
  ];

  return (
    <>
      <PageHeader
        title="App registry"
        subtitle="Effective application classifications: global catalog with per-tenant overrides."
      />
      <div className="grid grid--stats">
        <Stat label="Apps" value={s?.total ?? "—"} />
        <Stat label="Overrides" value={s?.overrides ?? "—"} />
        <Stat label="Sanctioned" value={s?.by_class?.sanctioned ?? "—"} />
        <Stat label="Blocked" value={s?.by_class?.blocked ?? "—"} />
      </div>
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">App catalog is empty.</p>}
        >
          {(d) => (
            <DataTable
              columns={cols}
              rows={d.items ?? []}
              rowKey={(e) => e.app?.id ?? e.override_id ?? Math.random().toString()}
            />
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}
