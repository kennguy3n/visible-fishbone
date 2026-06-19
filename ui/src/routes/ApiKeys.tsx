import { useId, useState } from "react";
import {
  useListApiKeys,
  useCreateApiKey,
  useDeleteApiKey,
} from "@/api/generated/endpoints/api-keys/api-keys";
import type { APIKey } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { HelpTooltip } from "@/components/HelpTooltip";
import { formatDateTime, formatRelative } from "@/lib/format";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { CopyField, isForbidden, PermissionDenied } from "./lane-b4-ui";

export function ApiKeys() {
  return (
    <LaneB4Screen>
      <RequireTenant>{(tenantId) => <ApiKeysInner tenantId={tenantId} />}</RequireTenant>
    </LaneB4Screen>
  );
}

function ApiKeysInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const list = useListApiKeys(tenantId);
  const del = useDeleteApiKey();
  const [showCreate, setShowCreate] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<APIKey | null>(null);

  if (isForbidden(list.error)) return <PermissionDenied />;

  const cols: Column<APIKey>[] = [
    { header: t("apiKeys.col.name"), cell: (k) => k.name },
    { header: t("apiKeys.col.subject"), cell: (k) => <span className="mono">{k.subject}</span> },
    { header: t("apiKeys.col.status"), cell: (k) => <StatusBadge status={k.status} /> },
    {
      header: t("apiKeys.col.expires"),
      cell: (k) => (k.expires_at ? formatDateTime(k.expires_at) : t("apiKeys.never")),
    },
    {
      header: t("apiKeys.col.lastUsed"),
      cell: (k) => (k.last_used_at ? formatRelative(k.last_used_at) : "—"),
    },
    {
      header: "",
      cell: (k) => (
        <button
          className="btn btn--danger btn--sm"
          disabled={del.isPending || k.status !== "active"}
          onClick={() => setRevokeTarget(k)}
        >
          {t("apiKeys.revoke")}
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t("apiKeys.title")}
        subtitle={t("apiKeys.subtitle")}
        actions={
          <>
            <HelpTooltip title={t("apiKeys.help.title")}>{t("apiKeys.help.body")}</HelpTooltip>
            <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
              {t("apiKeys.new")}
            </button>
          </>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          onRetry={() => list.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("apiKeys.empty.title")}
              description={t("apiKeys.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setShowCreate(true)}>
                  {t("apiKeys.empty.action")}
                </button>
              }
            />
          }
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(k) => k.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateKey tenantId={tenantId} onClose={() => setShowCreate(false)} />}
      {revokeTarget && (
        <RevokeKey
          apiKey={revokeTarget}
          pending={del.isPending}
          onConfirm={() =>
            del.mutate(
              { tenantId, id: revokeTarget.id },
              { onSettled: () => setRevokeTarget(null) },
            )
          }
          onClose={() => setRevokeTarget(null)}
        />
      )}
    </>
  );
}

function RevokeKey({
  apiKey,
  pending,
  onConfirm,
  onClose,
}: {
  apiKey: APIKey;
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const t = useT();
  return (
    <Modal
      title={t("apiKeys.revoke.title")}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {t("b4.action.cancel")}
          </button>
          <button className="btn btn--danger" onClick={onConfirm} disabled={pending}>
            {pending ? t("apiKeys.revoking") : t("apiKeys.revoke.cta")}
          </button>
        </>
      }
    >
      <p>{t("apiKeys.revoke.body", { name: apiKey.name })}</p>
    </Modal>
  );
}

function CreateKey({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const t = useT();
  const create = useCreateApiKey();
  const formId = useId();
  const nameId = useId();
  const nameHelpId = useId();
  const subjectId = useId();
  const subjectHelpId = useId();

  const [name, setName] = useState("");
  const [subject, setSubject] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [plaintext, setPlaintext] = useState<string | null>(null);

  const nameInvalid = submitted && name.trim() === "";
  const subjectInvalid = submitted && subject.trim() === "";

  const submit = () => {
    setSubmitted(true);
    if (name.trim() === "" || subject.trim() === "") return;
    create.mutate(
      { tenantId, data: { name: name.trim(), subject: subject.trim() } },
      { onSuccess: (k) => setPlaintext(k.plaintext ?? "") },
    );
  };

  return (
    <Modal
      title={t("apiKeys.create.title")}
      onClose={onClose}
      footer={
        plaintext != null ? (
          <button className="btn btn--primary" onClick={onClose}>
            {t("b4.action.done")}
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {t("b4.action.cancel")}
            </button>
            <button
              className="btn btn--primary"
              type="submit"
              form={formId}
              disabled={create.isPending}
            >
              {create.isPending ? t("apiKeys.creating") : t("apiKeys.create.cta")}
            </button>
          </>
        )
      }
    >
      {plaintext != null ? (
        <div className="secret-reveal">
          <p className="secret-reveal__title">{t("apiKeys.reveal.title")}</p>
          <p className="secret-reveal__warning">{t("apiKeys.reveal.warning")}</p>
          <CopyField
            value={plaintext}
            label={t("apiKeys.reveal.label")}
            copyLabel={t("apiKeys.reveal.copy")}
          />
        </div>
      ) : (
        <form
          id={formId}
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <label className="field" htmlFor={nameId}>
            <span>{t("apiKeys.field.name")}</span>
            <input
              id={nameId}
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("apiKeys.field.name.placeholder")}
              aria-invalid={nameInvalid}
              aria-describedby={nameHelpId}
            />
            <span
              id={nameHelpId}
              className={`field-help${nameInvalid ? " field-help--error" : ""}`}
              role={nameInvalid ? "alert" : undefined}
            >
              {nameInvalid ? t("apiKeys.error.nameRequired") : t("apiKeys.field.name.help")}
            </span>
          </label>
          <label className="field" htmlFor={subjectId}>
            <span>{t("apiKeys.field.subject")}</span>
            <input
              id={subjectId}
              className="mono"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder={t("apiKeys.field.subject.placeholder")}
              aria-invalid={subjectInvalid}
              aria-describedby={subjectHelpId}
            />
            <span
              id={subjectHelpId}
              className={`field-help${subjectInvalid ? " field-help--error" : ""}`}
              role={subjectInvalid ? "alert" : undefined}
            >
              {subjectInvalid ? t("apiKeys.error.subjectRequired") : t("apiKeys.field.subject.help")}
            </span>
          </label>
          {create.isError && (
            <p className="error-text" role="alert">
              {t("apiKeys.error.create")}
            </p>
          )}
        </form>
      )}
    </Modal>
  );
}
