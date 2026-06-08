import { useState } from "react";
import {
  useListWebhooks,
  useCreateWebhook,
  useDeleteWebhook,
} from "@/api/generated/endpoints/webhooks/webhooks";
import type { WebhookEndpoint } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime } from "@/lib/format";

const EVENTS = [
  "alert.created",
  "alert.acknowledged",
  "alert.resolved",
  "device.enrolled",
  "device.revoked",
  "policy.updated",
  "compliance.report.generated",
];

export function Webhooks() {
  return (
    <RequireTenant>{(tenantId) => <WebhooksInner tenantId={tenantId} />}</RequireTenant>
  );
}

function WebhooksInner({ tenantId }: { tenantId: string }) {
  const list = useListWebhooks(tenantId);
  const del = useDeleteWebhook();
  const [showCreate, setShowCreate] = useState(false);

  const cols: Column<WebhookEndpoint>[] = [
    { header: "URL", cell: (w) => <span className="mono">{w.url}</span> },
    {
      header: "Events",
      cell: (w) => (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {w.events.map((e) => (
            <Badge key={e} tone="neutral">
              {e}
            </Badge>
          ))}
        </div>
      ),
    },
    { header: "Status", cell: (w) => <StatusBadge status={w.status} /> },
    { header: "Created", cell: (w) => formatDateTime(w.created_at) },
    {
      header: "",
      cell: (w) => (
        <button
          className="btn btn--danger btn--sm"
          disabled={del.isPending}
          onClick={() => {
            if (confirm("Delete this webhook?")) del.mutate({ tenantId, id: w.id });
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
        title="Webhooks"
        subtitle="HMAC-signed event delivery endpoints."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Webhook
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="inbox" />}
              title="No webhooks configured"
              description="Add a webhook to push events to your own endpoints in real time."
            />
          }
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(w) => w.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateWebhook tenantId={tenantId} onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateWebhook({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateWebhook();
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<Set<string>>(new Set(["alert.created"]));
  const [secret, setSecret] = useState<string | null>(null);

  const toggle = (e: string) =>
    setEvents((prev) => {
      const next = new Set(prev);
      if (next.has(e)) next.delete(e);
      else next.add(e);
      return next;
    });

  return (
    <Modal
      title="New webhook"
      onClose={onClose}
      footer={
        secret ? (
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
              disabled={!url || events.size === 0 || create.isPending}
              onClick={() =>
                create.mutate(
                  { tenantId, data: { url, events: [...events] } },
                  { onSuccess: (w) => setSecret(w.secret ?? "(no secret returned)") },
                )
              }
            >
              {create.isPending ? "Creating…" : "Create"}
            </button>
          </>
        )
      }
    >
      {secret ? (
        <>
          <p className="muted">Signing secret — shown once. Verify the HMAC on delivery.</p>
          <pre className="code-block">{secret}</pre>
        </>
      ) : (
        <>
          <label className="field">
            <span>Endpoint URL</span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://soc.example.com/hooks/sng"
            />
          </label>
          <span style={{ color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>
            Events
          </span>
          <div style={{ marginTop: 8 }}>
            {EVENTS.map((e) => (
              <label
                key={e}
                style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}
              >
                <input
                  type="checkbox"
                  style={{ width: 16 }}
                  checked={events.has(e)}
                  onChange={() => toggle(e)}
                />
                <span className="mono">{e}</span>
              </label>
            ))}
          </div>
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
