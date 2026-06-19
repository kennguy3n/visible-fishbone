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
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { titleCase } from "@/lib/format";
import { LaneB2Intl, useT } from "./lane-b2/i18n";
import { ConfirmDialog } from "./lane-b2/ConfirmDialog";

export function Browser() {
  return (
    <LaneB2Intl>
      <RequireTenant>
        {(tenantId) => <BrowserInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB2Intl>
  );
}

function BrowserInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const list = useListBrowserPolicies(tenantId);
  const del = useDeleteBrowserPolicy();
  const [showCreate, setShowCreate] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<BrowserPolicy | null>(null);

  const cols: Column<BrowserPolicy>[] = [
    { header: t("browser.col.name"), cell: (p) => p.name },
    {
      header: t("browser.col.scope"),
      cell: (p) => <Badge tone="neutral">{titleCase(p.scope)}</Badge>,
    },
    {
      header: t("browser.col.action"),
      cell: (p) => (
        <Badge tone={p.action === "block" ? "danger" : "info"}>
          {titleCase(p.action)}
        </Badge>
      ),
    },
    { header: t("browser.col.rules"), cell: (p) => p.rules?.length ?? 0 },
    {
      header: t("browser.col.status"),
      cell: (p) => <StatusBadge status={p.enabled ? "enabled" : "disabled"} />,
    },
    {
      header: t("browser.col.actions"),
      cell: (p) => (
        <button
          className="btn btn--danger btn--sm"
          aria-label={t("browser.delete.aria", { name: p.name })}
          disabled={del.isPending}
          onClick={() => setPendingDelete(p)}
        >
          {t("browser.delete")}
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t("browser.title")}
        subtitle={t("browser.subtitle")}
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            {t("browser.new")}
          </button>
        }
      />
      <Card
        title={t("browser.title")}
        actions={
          <HelpTooltip title={t("browser.help.title")} align="right">
            {t("browser.help.body")}
          </HelpTooltip>
        }
      >
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          onRetry={() => list.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("browser.empty.title")}
              description={t("browser.empty.body")}
              action={
                <button
                  className="btn btn--primary"
                  onClick={() => setShowCreate(true)}
                >
                  {t("browser.new")}
                </button>
              }
            />
          }
        >
          {(d) => (
            <DataTable columns={cols} rows={d.items ?? []} rowKey={(p) => p.id} />
          )}
        </AsyncBoundary>
      </Card>
      {showCreate && (
        <CreatePolicy tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
      {pendingDelete && (
        <ConfirmDialog
          title={t("browser.delete.title")}
          message={t("browser.delete.confirm", { name: pendingDelete.name })}
          confirmLabel={t("browser.delete.cta")}
          cancelLabel={t("common.cancel")}
          busy={del.isPending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() =>
            del.mutate(
              { tenantId, id: pendingDelete.id },
              { onSuccess: () => setPendingDelete(null) },
            )
          }
        />
      )}
    </>
  );
}

function CreatePolicy({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const t = useT();
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
      title={t("browser.modal.title")}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {t("common.cancel")}
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
            {create.isPending
              ? t("browser.modal.creating")
              : t("browser.modal.create")}
          </button>
        </>
      }
    >
      <label className="field">
        <span>{t("browser.modal.name.label")}</span>
        <input
          value={name}
          autoFocus
          onChange={(e) => setName(e.target.value)}
          placeholder={t("browser.modal.name.placeholder")}
        />
      </label>
      <div className="field-row">
        <label className="field">
          <span>{t("browser.modal.action.label")}</span>
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
          <span>{t("browser.modal.scope.label")}</span>
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
        <p className="error-text" role="alert">
          {t("browser.modal.error")}
        </p>
      )}
    </Modal>
  );
}
