import { useListTenantAppRegistry } from "@/api/generated/endpoints/app-registry/app-registry";
import type { EffectiveApp } from "@/api/generated/model";
import {
  EffectiveAppEffectiveClass,
  EffectiveAppSource,
} from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  Stat,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { HelpTooltip } from "@/components/HelpTooltip";
import { titleCase } from "@/lib/format";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { isForbidden, PermissionDenied } from "./lane-b4-ui";
import type { LaneKey } from "./lane-b4-messages";

const CLASS_LABEL = new Map<string, LaneKey>([
  ["trusted_direct", "appReg.class.trusted_direct"],
  ["trusted_media_bypass", "appReg.class.trusted_media_bypass"],
  ["inspect_lite", "appReg.class.inspect_lite"],
  ["inspect_full", "appReg.class.inspect_full"],
  ["tunnel_private", "appReg.class.tunnel_private"],
  ["block", "appReg.class.block"],
]);

const SOURCE_LABEL = new Map<string, LaneKey>([
  ["global", "appReg.source.global"],
  ["override", "appReg.source.override"],
]);

export function AppRegistry() {
  return (
    <LaneB4Screen>
      <RequireTenant>
        {(tenantId) => <AppRegistryInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB4Screen>
  );
}

// effective_class is a traffic class (see EffectiveAppEffectiveClass), not a
// sanction verdict — the colour signals how strictly traffic is handled.
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
  const t = useT();
  const list = useListTenantAppRegistry(tenantId);

  if (isForbidden(list.error)) return <PermissionDenied />;

  // Summary cards are derived from the effective-app list itself; the separate
  // /app-registry/stats endpoint returns per-class traffic volume, not catalog
  // counts, so it can't back these cards.
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

  const classLabel = (cls: string) =>
    CLASS_LABEL.has(cls) ? t(CLASS_LABEL.get(cls)!) : titleCase(cls);
  const sourceLabel = (src: string) =>
    SOURCE_LABEL.has(src) ? t(SOURCE_LABEL.get(src)!) : titleCase(src);

  const cols: Column<EffectiveApp>[] = [
    { header: t("appReg.col.application"), cell: (e) => e.app?.name ?? e.app?.id ?? "—" },
    {
      header: t("appReg.col.category"),
      cell: (e) => <Badge tone="neutral">{titleCase(e.app?.category ?? "")}</Badge>,
    },
    {
      header: t("appReg.col.class"),
      cell: (e) => (
        <Badge tone={classTone(e.effective_class)}>{classLabel(e.effective_class)}</Badge>
      ),
    },
    {
      header: t("appReg.col.source"),
      cell: (e) => (
        <Badge tone={e.source === "override" ? "info" : "neutral"}>
          {sourceLabel(e.source)}
        </Badge>
      ),
    },
    {
      header: t("appReg.col.reason"),
      cell: (e) => e.override_reason ?? "—",
    },
  ];

  return (
    <>
      <PageHeader
        title={t("appReg.title")}
        subtitle={t("appReg.subtitle")}
        actions={
          <HelpTooltip title={t("appReg.help.title")} align="right">
            {t("appReg.help.body")}
          </HelpTooltip>
        }
      />
      <div className="grid grid--stats">
        <Stat label={t("appReg.stat.apps")} value={hasData ? items.length : "—"} />
        <Stat label={t("appReg.stat.overrides")} value={hasData ? overrideCount : "—"} />
        <Stat label={t("appReg.stat.inspected")} value={hasData ? inspectedCount : "—"} />
        <Stat label={t("appReg.stat.blocked")} value={hasData ? blockedCount : "—"} />
      </div>
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          onRetry={() => list.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title={t("appReg.empty.title")}
              description={t("appReg.empty.desc")}
            />
          }
        >
          {(d) => (
            <DataTable
              columns={cols}
              rows={d.items ?? []}
              rowKey={(e, i) => e.app?.id ?? e.override_id ?? `row-${i}`}
            />
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}
