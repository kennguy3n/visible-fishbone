import { useState } from "react";
import {
  useListApiKeys,
  useCreateApiKey,
  useDeleteApiKey,
} from "@/api/generated/endpoints/api-keys/api-keys";
import type { APIKey } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime, formatRelative } from "@/lib/format";

export function ApiKeys() {
  return (
    <RequireTenant>{(tenantId) => <ApiKeysInner tenantId={tenantId} />}</RequireTenant>
  );
}

function ApiKeysInner({ tenantId }: { tenantId: string }) {
  const list = useListApiKeys(tenantId);
  const del = useDeleteApiKey();
  const [showCreate, setShowCreate] = useState(false);

  const cols: Column<APIKey>[] = [
    { header: "Name", cell: (k) => k.name },
    { header: "Subject", cell: (k) => <span className="mono">{k.subject}</span> },
    { header: "Status", cell: (k) => <StatusBadge status={k.status} /> },
    { header: "Expires", cell: (k) => (k.expires_at ? formatDateTime(k.expires_at) : "never") },
    { header: "Last used", cell: (k) => (k.last_used_at ? formatRelative(k.last_used_at) : "—") },
    {
      header: "",
      cell: (k) => (
        <button
          className="btn btn--danger btn--sm"
          disabled={del.isPending || k.status !== "active"}
          onClick={() => {
            if (confirm(`Revoke API key "${k.name}"?`))
              del.mutate({ tenantId, id: k.id });
          }}
        >
          Revoke
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="API keys"
        subtitle="Machine-to-machine credentials presented via the X-SNG-API-Key header."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + API key
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">No API keys issued.</p>}
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(k) => k.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateKey tenantId={tenantId} onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateKey({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateApiKey();
  const [name, setName] = useState("");
  const [subject, setSubject] = useState("");
  const [plaintext, setPlaintext] = useState<string | null>(null);

  return (
    <Modal
      title="Create API key"
      onClose={onClose}
      footer={
        plaintext ? (
          <button className="btn btn--primary" onClick={onClose}>
            Done
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn--primary"
              disabled={!name || !subject || create.isPending}
              onClick={() =>
                create.mutate(
                  { tenantId, data: { name, subject } },
                  { onSuccess: (k) => setPlaintext(k.plaintext ?? "(not returned)") },
                )
              }
            >
              {create.isPending ? "Creating…" : "Create"}
            </button>
          </>
        )
      }
    >
      {plaintext ? (
        <>
          <p className="muted">Copy this key now — it is shown only once.</p>
          <pre className="code-block">{plaintext}</pre>
        </>
      ) : (
        <>
          <label className="field">
            <span>Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-prod" />
          </label>
          <label className="field">
            <span>Subject</span>
            <input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="bot:ci"
            />
          </label>
          {create.isError && (
            <p className="error-text">
              {create.error instanceof Error ? create.error.message : "Failed"}
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
