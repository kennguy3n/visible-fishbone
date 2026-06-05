import { useState } from "react";
import {
  useListIntegrationConnectors,
  useCreateIntegrationConnector,
  useTestIntegrationConnector,
  useDeleteIntegrationConnector,
} from "@/api/generated/endpoints/integration/integration";
import { IntegrationConnectorType } from "@/api/generated/model";
import type { IntegrationConnector } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative, titleCase } from "@/lib/format";

export function Integrations() {
  return (
    <RequireTenant>
      {(tenantId) => <IntegrationsInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function IntegrationsInner({ tenantId }: { tenantId: string }) {
  const list = useListIntegrationConnectors(tenantId, undefined);
  const test = useTestIntegrationConnector();
  const del = useDeleteIntegrationConnector();
  const [showCreate, setShowCreate] = useState(false);

  const cols: Column<IntegrationConnector>[] = [
    { header: "Name", cell: (c) => c.name },
    { header: "Type", cell: (c) => <Badge tone="info">{titleCase(c.type)}</Badge> },
    { header: "Status", cell: (c) => <StatusBadge status={c.status} /> },
    {
      header: "Last test",
      cell: (c) => (
        <span title={c.last_test_error ?? ""}>
          <StatusBadge status={c.last_test_result} />{" "}
          {c.last_test_at ? formatRelative(c.last_test_at) : ""}
        </span>
      ),
    },
    {
      header: "",
      cell: (c) => (
        <div style={{ display: "flex", gap: 6 }}>
          <button
            className="btn btn--sm"
            disabled={test.isPending}
            onClick={() => test.mutate({ tenantId, id: c.id })}
          >
            Test
          </button>
          <button
            className="btn btn--danger btn--sm"
            disabled={del.isPending}
            onClick={() => {
              if (confirm(`Delete connector "${c.name}"?`))
                del.mutate({ tenantId, id: c.id });
            }}
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Integrations"
        subtitle="Outbound SIEM, ticketing and notification connectors."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Connector
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">No connectors configured.</p>}
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(c) => c.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && (
        <CreateConnector tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </>
  );
}

function CreateConnector({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateIntegrationConnector<Error>();
  const [name, setName] = useState("");
  const [type, setType] = useState<IntegrationConnectorType>(
    Object.values(IntegrationConnectorType)[0] as IntegrationConnectorType,
  );

  return (
    <Modal
      title="New integration connector"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            disabled={!name || create.isPending}
            onClick={() =>
              create.mutate(
                { tenantId, data: { name, type } },
                { onSuccess: onClose },
              )
            }
          >
            {create.isPending ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="soc-pagerduty" />
      </label>
      <label className="field">
        <span>Type</span>
        <select
          value={type}
          onChange={(e) => setType(e.target.value as IntegrationConnectorType)}
        >
          {Object.values(IntegrationConnectorType).map((t) => (
            <option key={t} value={t}>
              {titleCase(t)}
            </option>
          ))}
        </select>
      </label>
      {create.isError && (
        <p className="error-text">
          {create.error instanceof Error ? create.error.message : "Failed"}
        </p>
      )}
    </Modal>
  );
}
