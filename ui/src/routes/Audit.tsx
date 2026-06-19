import { useState } from "react";
import { useListAuditLog } from "@/api/generated/endpoints/audit/audit";
import type { AuditEntry } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { HelpTooltip } from "@/components/HelpTooltip";
import { formatDateTime } from "@/lib/format";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { isForbidden, PermissionDenied } from "./lane-b4-ui";

export function Audit() {
  return (
    <LaneB4Screen>
      <RequireTenant>{(tenantId) => <AuditInner tenantId={tenantId} />}</RequireTenant>
    </LaneB4Screen>
  );
}

function AuditInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const list = useListAuditLog(tenantId, {
    action: action || undefined,
    resource_type: resourceType || undefined,
    limit: 100,
  });

  if (isForbidden(list.error)) return <PermissionDenied />;

  const hasFilters = action !== "" || resourceType !== "";
  const clearFilters = () => {
    setAction("");
    setResourceType("");
  };

  const cols: Column<AuditEntry>[] = [
    { header: t("audit.col.when"), cell: (e) => formatDateTime(e.created_at) },
    {
      header: t("audit.col.actor"),
      cell: (e) => <span className="mono">{e.actor_id ?? t("audit.actor.system")}</span>,
    },
    { header: t("audit.col.action"), cell: (e) => <Badge tone="info">{e.action}</Badge> },
    { header: t("audit.col.resource"), cell: (e) => <span className="mono">{e.resource_type}</span> },
    {
      header: t("audit.col.resourceId"),
      cell: (e) => (
        <span className="mono">{e.resource_id ? e.resource_id.slice(0, 12) : "—"}</span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t("audit.title")}
        subtitle={t("audit.subtitle")}
        actions={
          <HelpTooltip title={t("audit.help.title")} align="right">
            {t("audit.help.body")}
          </HelpTooltip>
        }
      />
      <div className="toolbar" role="search">
        <label className="field-inline">
          <span className="sr-only">{t("audit.filter.action.label")}</span>
          <input
            placeholder={t("audit.filter.action.placeholder")}
            value={action}
            onChange={(e) => setAction(e.target.value)}
            style={{ maxWidth: 240 }}
          />
        </label>
        <label className="field-inline">
          <span className="sr-only">{t("audit.filter.resource.label")}</span>
          <input
            placeholder={t("audit.filter.resource.placeholder")}
            value={resourceType}
            onChange={(e) => setResourceType(e.target.value)}
            style={{ maxWidth: 240 }}
          />
        </label>
        {hasFilters && (
          <button className="btn btn--sm" onClick={clearFilters}>
            {t("audit.filter.clear")}
          </button>
        )}
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
              title={hasFilters ? t("audit.empty.filtered.title") : t("audit.empty.title")}
              description={
                hasFilters ? t("audit.empty.filtered.desc") : t("audit.empty.desc")
              }
              action={
                hasFilters ? (
                  <button className="btn btn--sm" onClick={clearFilters}>
                    {t("audit.filter.clear")}
                  </button>
                ) : undefined
              }
            />
          }
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(e) => e.id} />}
        </AsyncBoundary>
      </Card>
    </>
  );
}
