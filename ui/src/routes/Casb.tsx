import { useState } from "react";
import {
  useCasbConnectors,
  useCasbApps,
  useCreateCasbConnector,
  useSyncCasbConnector,
} from "@/api/manual/hooks";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative } from "@/lib/format";
import type { CasbApp, CasbConnector } from "@/api/manual/types";

export function Casb() {
  return <RequireTenant>{(tenantId) => <CasbInner tenantId={tenantId} />}</RequireTenant>;
}

function riskTone(score: number) {
  if (score >= 70) return "danger" as const;
  if (score >= 40) return "warn" as const;
  return "ok" as const;
}

function CasbInner({ tenantId }: { tenantId: string }) {
  const connectors = useCasbConnectors(tenantId);
  const apps = useCasbApps(tenantId);
  const sync = useSyncCasbConnector(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  const appCols: Column<CasbApp>[] = [
    { header: "Application", cell: (a) => a.name },
    { header: "Vendor", cell: (a) => a.vendor },
    { header: "Category", cell: (a) => <Badge tone="neutral">{a.category}</Badge> },
    { header: "Risk", cell: (a) => <Badge tone={riskTone(a.risk_score)}>{a.risk_score}</Badge> },
    { header: "Users", cell: (a) => a.users_count },
    { header: "Last seen", cell: (a) => formatRelative(a.last_seen) },
  ];

  const connCols: Column<CasbConnector>[] = [
    { header: "Name", cell: (c) => c.name },
    { header: "Type", cell: (c) => <Badge tone="info">{c.type}</Badge> },
    { header: "Status", cell: (c) => <StatusBadge status={c.status} /> },
    { header: "Last sync", cell: (c) => formatRelative(c.last_sync_at ?? null) },
    {
      header: "",
      cell: (c) => (
        <button
          className="btn btn--sm"
          disabled={sync.isPending}
          onClick={() => sync.mutate(c.id)}
        >
          Sync now
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="CASB"
        subtitle="Discovered SaaS applications and the connectors that inventory them."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Connector
          </button>
        }
      />

      <Card
        title="Shadow IT — discovered applications"
        actions={
          <HelpTooltip title="What is Shadow IT?" align="right">
            Shadow IT is SaaS apps your staff use that haven't been formally
            approved. We discover them from traffic and connector inventory so
            you can sanction or block them.
          </HelpTooltip>
        }
      >
        <AsyncBoundary
          isLoading={apps.isLoading}
          error={apps.error}
          data={apps.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title="No applications discovered yet"
              description="Connect a CASB source and we'll start inventorying the SaaS apps in use."
            />
          }
        >
          {(d) => <DataTable columns={appCols} rows={d.items ?? []} rowKey={(a) => a.id} />}
        </AsyncBoundary>
      </Card>

      <Card title="Inline connectors">
        <AsyncBoundary
          isLoading={connectors.isLoading}
          error={connectors.error}
          data={connectors.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="inbox" />}
              title="No connectors configured"
              description="Add an inline CASB connector to inspect SaaS uploads, shares and downloads in real time."
            />
          }
        >
          {(d) => <DataTable columns={connCols} rows={d.items ?? []} rowKey={(c) => c.id} />}
        </AsyncBoundary>
      </Card>

      {showCreate && (
        <CreateConnector tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </>
  );
}

function CreateConnector({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const create = useCreateCasbConnector(tenantId);
  const [name, setName] = useState("");
  const [type, setType] = useState("google_workspace");

  return (
    <Modal
      title="New CASB connector"
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
              create.mutate({ name, type }, { onSuccess: onClose })
            }
          >
            {create.isPending ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="field">
        <span>Type</span>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {["google_workspace", "microsoft365", "okta", "salesforce", "box"].map((t) => (
            <option key={t} value={t}>
              {t}
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
