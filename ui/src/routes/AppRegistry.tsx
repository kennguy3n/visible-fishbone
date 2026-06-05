import { useListTenantAppRegistry } from "@/api/generated/endpoints/app-registry/app-registry";
import type { EffectiveApp } from "@/api/generated/model";
import {
  EffectiveAppEffectiveClass,
  EffectiveAppSource,
} from "@/api/generated/model";
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

// effective_class is a traffic class (see EffectiveAppEffectiveClass), not a
// sanction verdict. The previous allow/deny/sanctioned strings matched none of
// the real enum values, so every badge rendered neutral.
function classTone(cls: string) {
  if (cls === EffectiveAppEffectiveClass.block) return "danger" as const;
  if (
    cls === EffectiveAppEffectiveClass.inspect_full ||
    cls === EffectiveAppEffectiveClass.inspect_lite
  )
    return "warn" as const;
  if (
    cls === EffectiveAppEffectiveClass.trusted_direct ||
    cls === EffectiveAppEffectiveClass.trusted_media_bypass
  )
    return "ok" as const;
  return "neutral" as const;
}

function AppRegistryInner({ tenantId }: { tenantId: string }) {
  const list = useListTenantAppRegistry(tenantId);

  // Summary cards are derived from the effective-app list itself. The separate
  // /app-registry/stats endpoint returns per-class *traffic* volume
  // (events/bytes), not catalog counts, so it can't back these cards — the old
  // code cast it to an invented {total,overrides,by_class} shape that never
  // existed, leaving every card stuck on "—".
  const items = list.data?.items ?? [];
  const overrideCount = items.filter(
    (e) => e.source === EffectiveAppSource.override,
  ).length;
  const blockedCount = items.filter(
    (e) => e.effective_class === EffectiveAppEffectiveClass.block,
  ).length;
  const inspectedCount = items.filter(
    (e) =>
      e.effective_class === EffectiveAppEffectiveClass.inspect_full ||
      e.effective_class === EffectiveAppEffectiveClass.inspect_lite,
  ).length;
  const hasData = list.data !== undefined;

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
        <Stat label="Apps" value={hasData ? items.length : "—"} />
        <Stat label="Overrides" value={hasData ? overrideCount : "—"} />
        <Stat label="Inspected" value={hasData ? inspectedCount : "—"} />
        <Stat label="Blocked" value={hasData ? blockedCount : "—"} />
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
