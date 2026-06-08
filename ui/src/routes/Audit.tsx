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
import { formatDateTime } from "@/lib/format";

export function Audit() {
  return <RequireTenant>{(tenantId) => <AuditInner tenantId={tenantId} />}</RequireTenant>;
}

function AuditInner({ tenantId }: { tenantId: string }) {
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const list = useListAuditLog(tenantId, {
    action: action || undefined,
    resource_type: resourceType || undefined,
    limit: 100,
  });

  const cols: Column<AuditEntry>[] = [
    { header: "When", cell: (e) => formatDateTime(e.created_at) },
    { header: "Actor", cell: (e) => <span className="mono">{e.actor_id ?? "system"}</span> },
    { header: "Action", cell: (e) => <Badge tone="info">{e.action}</Badge> },
    { header: "Resource", cell: (e) => <span className="mono">{e.resource_type}</span> },
    {
      header: "Resource ID",
      cell: (e) => <span className="mono">{e.resource_id ? e.resource_id.slice(0, 12) : "—"}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Immutable record of administrative actions."
      />
      <div className="toolbar">
        <input
          placeholder="Filter action (e.g. tenant.update)"
          value={action}
          onChange={(e) => setAction(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <input
          placeholder="Filter resource type"
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
          style={{ maxWidth: 240 }}
        />
      </div>
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title="No matching audit entries"
              description="Try widening the filter or clearing it to see all activity."
            />
          }
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(e) => e.id} />}
        </AsyncBoundary>
      </Card>
    </>
  );
}
