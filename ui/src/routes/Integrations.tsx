import { useState } from "react";
import { useIntl, type IntlShape, type MessageDescriptor } from "react-intl";
import {
  useListIntegrationConnectors,
  useCreateIntegrationConnector,
  useTestIntegrationConnector,
  useDeleteIntegrationConnector,
} from "@/api/generated/endpoints/integration/integration";
import { IntegrationConnectorType } from "@/api/generated/model";
import type { IntegrationConnector } from "@/api/generated/model";
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
import { formatRelative, titleCase } from "@/lib/format";
import { LanePage, ConfirmDialog } from "./lane-b5";
import { integrationsMsg as M } from "./lane-b5.messages";

const TYPE_LABELS: Partial<Record<IntegrationConnectorType, MessageDescriptor>> = {
  [IntegrationConnectorType.syslog]: M.typeSyslog,
  [IntegrationConnectorType.siem_webhook]: M.typeSiem,
  [IntegrationConnectorType.jira]: M.typeJira,
  [IntegrationConnectorType.servicenow]: M.typeServicenow,
};

function typeLabel(intl: IntlShape, type: string): string {
  const msg = TYPE_LABELS[type as IntegrationConnectorType];
  return msg ? intl.formatMessage(msg) : titleCase(type);
}

export function Integrations() {
  return (
    <RequireTenant>
      {(tenantId) => <IntegrationsInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function IntegrationsInner({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const list = useListIntegrationConnectors(tenantId, undefined);
  const test = useTestIntegrationConnector();
  const del = useDeleteIntegrationConnector();
  const [showCreate, setShowCreate] = useState(false);
  const [toDelete, setToDelete] = useState<IntegrationConnector | null>(null);

  const cols: Column<IntegrationConnector>[] = [
    { header: intl.formatMessage(M.colName), cell: (c) => c.name },
    {
      header: intl.formatMessage(M.colType),
      cell: (c) => <Badge tone="info">{typeLabel(intl, c.type)}</Badge>,
    },
    { header: intl.formatMessage(M.colStatus), cell: (c) => <StatusBadge status={c.status} /> },
    {
      header: intl.formatMessage(M.colLastTest),
      cell: (c) =>
        c.last_test_result ? (
          <span title={c.last_test_error ?? undefined}>
            <StatusBadge status={c.last_test_result} />{" "}
            {c.last_test_at ? formatRelative(c.last_test_at) : ""}
          </span>
        ) : (
          <span className="text-dim">{intl.formatMessage(M.neverTested)}</span>
        ),
    },
    {
      header: intl.formatMessage(M.colActions),
      cell: (c) => (
        <div className="lane-actions">
          <button
            className="btn btn--sm"
            disabled={test.isPending}
            onClick={() => test.mutate({ tenantId, id: c.id })}
            aria-label={intl.formatMessage(M.testAria, { name: c.name })}
          >
            {intl.formatMessage(M.test)}
          </button>
          <button
            className="btn btn--danger btn--sm"
            onClick={() => setToDelete(c)}
            aria-label={intl.formatMessage(M.removeAria, { name: c.name })}
          >
            {intl.formatMessage(M.remove)}
          </button>
        </div>
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
            {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(c) => c.id} />}
          </AsyncBoundary>
        </Card>
      </div>

      {showCreate && (
        <CreateConnector tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}

      {toDelete && (
        <ConfirmDialog
          title={intl.formatMessage(M.deleteTitle)}
          body={intl.formatMessage(M.deleteBody, { name: toDelete.name })}
          confirmLabel={intl.formatMessage(M.deleteConfirm)}
          cancelLabel={intl.formatMessage(M.cancel)}
          busyLabel={intl.formatMessage(M.removing)}
          tone="danger"
          busy={del.isPending}
          onConfirm={() =>
            del.mutate(
              { tenantId, id: toDelete.id },
              { onSuccess: () => setToDelete(null) },
            )
          }
          onClose={() => setToDelete(null)}
        />
      )}
    </LanePage>
  );
}

function CreateConnector({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const intl = useIntl();
  const create = useCreateIntegrationConnector<Error>();
  const [name, setName] = useState("");
  const [type, setType] = useState<IntegrationConnectorType>(
    Object.values(IntegrationConnectorType)[0] as IntegrationConnectorType,
  );

  return (
    <Modal
      title={intl.formatMessage(M.createTitle)}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={create.isPending}>
            {intl.formatMessage(M.cancel)}
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
            {create.isPending ? intl.formatMessage(M.creating) : intl.formatMessage(M.create)}
          </button>
        </>
      }
    >
      <label className="field">
        <span>{intl.formatMessage(M.nameLabel)}</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={intl.formatMessage(M.namePlaceholder)}
          autoFocus
        />
      </label>
      <p className="lane-help">{intl.formatMessage(M.nameHelp)}</p>
      <label className="field">
        <span>{intl.formatMessage(M.typeLabel)}</span>
        <select
          value={type}
          onChange={(e) => setType(e.target.value as IntegrationConnectorType)}
        >
          {Object.values(IntegrationConnectorType).map((t) => (
            <option key={t} value={t}>
              {typeLabel(intl, t)}
            </option>
          ))}
        </select>
      </label>
      <p className="lane-help">{intl.formatMessage(M.typeHelp)}</p>
      {create.isError && (
        <p className="error-text" role="alert">
          {intl.formatMessage(M.createError)}
        </p>
      )}
    </Modal>
  );
}
