import { useState } from "react";
import { useIntl } from "react-intl";
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
import { LanePage, ConfirmDialog } from "./lane-b5";
import { webhooksMsg as M } from "./lane-b5.messages";

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
  const intl = useIntl();
  const list = useListWebhooks(tenantId);
  const del = useDeleteWebhook();
  const [showCreate, setShowCreate] = useState(false);
  const [toDelete, setToDelete] = useState<WebhookEndpoint | null>(null);

  const cols: Column<WebhookEndpoint>[] = [
    { header: intl.formatMessage(M.colUrl), cell: (w) => <span className="mono">{w.url}</span> },
    {
      header: intl.formatMessage(M.colEvents),
      cell: (w) => (
        <div className="lane-tags">
          {w.events.map((e) => (
            <Badge key={e} tone="neutral">
              {e}
            </Badge>
          ))}
        </div>
      ),
    },
    { header: intl.formatMessage(M.colStatus), cell: (w) => <StatusBadge status={w.status} /> },
    { header: intl.formatMessage(M.colCreated), cell: (w) => formatDateTime(w.created_at) },
    {
      header: intl.formatMessage(M.colActions),
      cell: (w) => (
        <button
          className="btn btn--danger btn--sm"
          onClick={() => setToDelete(w)}
          aria-label={intl.formatMessage(M.removeAria, { url: w.url })}
        >
          {intl.formatMessage(M.remove)}
        </button>
      ),
    },
  ];

  const addButton = (
    <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
      {intl.formatMessage(M.add)}
    </button>
  );

  return (
    <LanePage>
      <PageHeader
        title={intl.formatMessage(M.title)}
        subtitle={intl.formatMessage(M.subtitle)}
        actions={addButton}
      />
      <div className="lane-stack">
        <Card>
          <AsyncBoundary
            isLoading={list.isLoading}
            error={list.error}
            data={list.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            onRetry={() => list.refetch()}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="inbox" />}
                title={intl.formatMessage(M.emptyTitle)}
                description={intl.formatMessage(M.emptyBody)}
                action={addButton}
              />
            }
          >
            {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(w) => w.id} />}
          </AsyncBoundary>
        </Card>
      </div>

      {showCreate && <CreateWebhook tenantId={tenantId} onClose={() => setShowCreate(false)} />}

      {toDelete && (
        <ConfirmDialog
          title={intl.formatMessage(M.deleteTitle)}
          body={intl.formatMessage(M.deleteBody)}
          error={del.isError ? intl.formatMessage(M.deleteError) : undefined}
          confirmLabel={intl.formatMessage(M.deleteConfirm)}
          cancelLabel={intl.formatMessage(M.cancel)}
          busyLabel={intl.formatMessage(M.removing)}
          tone="danger"
          busy={del.isPending}
          onConfirm={() => {
            const id = toDelete.id;
            del.mutate(
              { tenantId, id },
              {
                onSuccess: () =>
                  setToDelete((cur) => (cur?.id === id ? null : cur)),
              },
            );
          }}
          onClose={() => {
            del.reset();
            setToDelete(null);
          }}
        />
      )}
    </LanePage>
  );
}

function CreateWebhook({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const intl = useIntl();
  const create = useCreateWebhook();
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<Set<string>>(new Set(["alert.created"]));
  const [created, setCreated] = useState(false);
  const [secret, setSecret] = useState("");
  const [copied, setCopied] = useState(false);

  const toggle = (e: string) =>
    setEvents((prev) => {
      const next = new Set(prev);
      if (next.has(e)) next.delete(e);
      else next.add(e);
      return next;
    });

  const copySecret = async () => {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Modal
      title={
        created
          ? intl.formatMessage(secret ? M.secretTitle : M.createdTitle)
          : intl.formatMessage(M.createTitle)
      }
      onClose={onClose}
      footer={
        created ? (
          <button className="btn btn--primary" onClick={onClose} autoFocus>
            {intl.formatMessage(M.done)}
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose} disabled={create.isPending}>
              {intl.formatMessage(M.cancel)}
            </button>
            <button
              className="btn btn--primary"
              disabled={!url || events.size === 0 || create.isPending}
              onClick={() =>
                create.mutate(
                  { tenantId, data: { url, events: [...events] } },
                  {
                    onSuccess: (w) => {
                      setSecret(w.secret ?? "");
                      setCreated(true);
                    },
                  },
                )
              }
            >
              {create.isPending
                ? intl.formatMessage(M.creating)
                : intl.formatMessage(M.create)}
            </button>
          </>
        )
      }
    >
      {created ? (
        secret ? (
          <>
            <p className="lane-prose">{intl.formatMessage(M.secretBody)}</p>
            <div className="lane-secret">
              <code>{secret}</code>
              <button className="btn btn--sm" onClick={copySecret}>
                {copied ? intl.formatMessage(M.copied) : intl.formatMessage(M.copy)}
              </button>
            </div>
          </>
        ) : (
          <p className="lane-prose">{intl.formatMessage(M.createdBody)}</p>
        )
      ) : (
        <>
          <label className="field">
            <span>{intl.formatMessage(M.urlLabel)}</span>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={intl.formatMessage(M.urlPlaceholder)}
              autoFocus
            />
          </label>
          <p className="lane-help">{intl.formatMessage(M.urlHelp)}</p>

          <fieldset className="lane-fieldset">
            <legend>{intl.formatMessage(M.eventsLegend)}</legend>
            <p className="lane-help">{intl.formatMessage(M.eventsHelp)}</p>
            <div className="lane-checklist">
              {EVENTS.map((e) => (
                <label key={e} className="lane-check">
                  <input
                    type="checkbox"
                    checked={events.has(e)}
                    onChange={() => toggle(e)}
                  />
                  <span className="mono">{e}</span>
                </label>
              ))}
            </div>
          </fieldset>

          {create.isError && (
            <p className="error-text" role="alert">
              {intl.formatMessage(M.createError)}
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
