import { useState } from "react";
import {
  useListBrowserPolicies,
  useCreateBrowserPolicy,
  useDeleteBrowserPolicy,
} from "@/api/generated/endpoints/browser/browser";
import {
  BrowserPolicyCreateAction,
  BrowserPolicyCreateScope,
} from "@/api/generated/model";
import type { BrowserPolicy } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { titleCase } from "@/lib/format";

export function Browser() {
  return (
    <RequireTenant>{(tenantId) => <BrowserInner tenantId={tenantId} />}</RequireTenant>
  );
}

function BrowserInner({ tenantId }: { tenantId: string }) {
  const list = useListBrowserPolicies(tenantId);
  const del = useDeleteBrowserPolicy();
  const [showCreate, setShowCreate] = useState(false);

  const cols: Column<BrowserPolicy>[] = [
    { header: "Name", cell: (p) => p.name },
    { header: "Scope", cell: (p) => <Badge tone="neutral">{titleCase(p.scope)}</Badge> },
    { header: "Action", cell: (p) => <Badge tone={p.action === "block" ? "danger" : "info"}>{titleCase(p.action)}</Badge> },
    { header: "Rules", cell: (p) => p.rules?.length ?? 0 },
    { header: "Enabled", cell: (p) => <StatusBadge status={p.enabled ? "enabled" : "disabled"} /> },
    {
      header: "",
      cell: (p) => (
        <button
          className="btn btn--danger btn--sm"
          disabled={del.isPending}
          onClick={() => {
            if (confirm(`Delete browser policy "${p.name}"?`))
              del.mutate({ tenantId, id: p.id });
          }}
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Browser protection"
        subtitle="Managed-browser isolation, download and clipboard policies."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Policy
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">No browser policies defined.</p>}
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(p) => p.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && (
        <CreatePolicy tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </>
  );
}

function CreatePolicy({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateBrowserPolicy();
  const [name, setName] = useState("");
  const [action, setAction] = useState<BrowserPolicyCreateAction>(
    Object.values(BrowserPolicyCreateAction)[0] as BrowserPolicyCreateAction,
  );
  const [scope, setScope] = useState<BrowserPolicyCreateScope>(
    Object.values(BrowserPolicyCreateScope)[0] as BrowserPolicyCreateScope,
  );

  return (
    <Modal
      title="New browser policy"
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
                { tenantId, data: { name, action, scope, enabled: true } },
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
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <div className="field-row">
        <label className="field">
          <span>Action</span>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as BrowserPolicyCreateAction)}
          >
            {Object.values(BrowserPolicyCreateAction).map((a) => (
              <option key={a} value={a}>
                {titleCase(a)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Scope</span>
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value as BrowserPolicyCreateScope)}
          >
            {Object.values(BrowserPolicyCreateScope).map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </select>
        </label>
      </div>
      {create.isError && (
        <p className="error-text">
          {create.error instanceof Error ? create.error.message : "Failed"}
        </p>
      )}
    </Modal>
  );
}
