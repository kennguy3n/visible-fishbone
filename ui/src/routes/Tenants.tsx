import { useState } from "react";
import { useIntl } from "react-intl";
import {
  useListTenants,
  useCreateTenant,
  useSuspendTenant,
  useDeleteTenant,
} from "@/api/generated/endpoints/tenants/tenants";
import type { Tenant } from "@/api/generated/model";
import { TenantCreateRequestTier } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  StatusBadge,
  Badge,
  AsyncBoundary,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { formatDateTime, titleCase } from "@/lib/format";
import { useTenant } from "@/lib/tenant-context";
import { M } from "@/routes/msp/lane-b6.messages";
import {
  LanePage,
  ConfirmDialog,
  PermissionDenied,
  LabelText,
} from "@/routes/msp/_lane";
import { isPermissionDenied } from "@/routes/msp/lane-utils";

type TierValue = (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];
const TIERS = Object.values(TenantCreateRequestTier) as TierValue[];

type ConfirmTarget = { kind: "suspend" | "delete"; tenant: Tenant };

export function Tenants() {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const list = useListTenants();
  const { selectedTenantId, setSelectedTenantId } = useTenant();
  const [showCreate, setShowCreate] = useState(false);
  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null);

  const suspend = useSuspendTenant();
  const del = useDeleteTenant();

  const newTenantBtn = (
    <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
      {fm(M.tenantsNew)}
    </button>
  );

  const columns: Column<Tenant>[] = [
    {
      header: fm(M.colName),
      cell: (t) => (
        <span className="lb6-chips">
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => setSelectedTenantId(t.id)}
            title={fm(M.makeActiveTitle)}
            disabled={t.id === selectedTenantId}
          >
            {t.name}
          </button>
          {t.id === selectedTenantId && (
            <Badge tone="info">{fm(M.activeTenantTag)}</Badge>
          )}
        </span>
      ),
    },
    { header: fm(M.colSlug), cell: (t) => <span className="mono">{t.slug}</span> },
    { header: fm(M.colStatus), cell: (t) => <StatusBadge status={t.status} /> },
    {
      header: fm(M.colTier),
      cell: (t) => <Badge tone="neutral">{titleCase(t.tier)}</Badge>,
    },
    { header: fm(M.colRegion), cell: (t) => t.region ?? "—" },
    {
      header: fm(M.colManagedBy),
      cell: (t) =>
        t.msp_id ? (
          <Badge tone="info">{fm(M.tenantManaged)}</Badge>
        ) : (
          <span className="muted">{fm(M.tenantDirect)}</span>
        ),
    },
    { header: fm(M.colCreated), cell: (t) => formatDateTime(t.created_at) },
    {
      header: fm(M.colActions),
      cell: (t) => (
        <div className="lb6-card-actions">
          <button
            className="btn btn--sm"
            disabled={t.status === "suspended" || suspend.isPending}
            onClick={() => setConfirmTarget({ kind: "suspend", tenant: t })}
          >
            {fm(M.suspend)}
          </button>
          <button
            className="btn btn--danger btn--sm"
            disabled={del.isPending}
            onClick={() => setConfirmTarget({ kind: "delete", tenant: t })}
          >
            {fm(M.delete)}
          </button>
        </div>
      ),
    },
  ];

  return (
    <LanePage>
      <PageHeader
        title={fm(M.tenantsTitle)}
        subtitle={fm(M.tenantsSubtitle)}
        actions={newTenantBtn}
      />
      <Card>
        {isPermissionDenied(list.error) ? (
          <PermissionDenied />
        ) : (
          <AsyncBoundary
            isLoading={list.isLoading}
            error={list.error ? new Error(fm(M.retryHint)) : null}
            data={list.data}
            onRetry={() => void list.refetch()}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="shield" />}
                title={fm(M.tenantsEmptyTitle)}
                description={fm(M.tenantsEmptyBody)}
                action={newTenantBtn}
              />
            }
          >
            {(d) => (
              <DataTable
                columns={columns}
                rows={d.items ?? []}
                rowKey={(t) => t.id}
              />
            )}
          </AsyncBoundary>
        )}
      </Card>

      {showCreate && (
        <CreateTenantModal
          onClose={() => setShowCreate(false)}
          onCreated={(name) =>
            toast.success(
              fm(M.createdToastTitle),
              fm(M.createdToastBody, { name }),
            )
          }
        />
      )}

      {confirmTarget?.kind === "suspend" && (
        <ConfirmDialog
          title={fm(M.suspendConfirmTitle, { name: confirmTarget.tenant.name })}
          confirmLabel={fm(M.suspendConfirmCta)}
          busy={suspend.isPending}
          onClose={() => setConfirmTarget(null)}
          onConfirm={() =>
            suspend.mutate(
              { tenantId: confirmTarget.tenant.id },
              { onSuccess: () => setConfirmTarget(null) },
            )
          }
        >
          <p>{fm(M.suspendConfirmBody)}</p>
        </ConfirmDialog>
      )}

      {confirmTarget?.kind === "delete" && (
        <DeleteTenantDialog
          tenant={confirmTarget.tenant}
          busy={del.isPending}
          onClose={() => setConfirmTarget(null)}
          onConfirm={() =>
            del.mutate(
              { tenantId: confirmTarget.tenant.id },
              { onSuccess: () => setConfirmTarget(null) },
            )
          }
        />
      )}
    </LanePage>
  );
}

function DeleteTenantDialog({
  tenant,
  busy,
  onClose,
  onConfirm,
}: {
  tenant: Tenant;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const { formatMessage: fm } = useIntl();
  const [typed, setTyped] = useState("");
  return (
    <ConfirmDialog
      title={fm(M.deleteConfirmTitle, { name: tenant.name })}
      confirmLabel={fm(M.deleteConfirmCta)}
      tone="danger"
      busy={busy}
      confirmDisabled={typed.trim() !== tenant.name}
      onClose={onClose}
      onConfirm={onConfirm}
    >
      <p>{fm(M.deleteConfirmBody)}</p>
      <label className="field">
        <LabelText>{fm(M.typeToConfirm, { name: tenant.name })}</LabelText>
        <input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
          autoFocus
        />
      </label>
    </ConfirmDialog>
  );
}

function CreateTenantModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (name: string) => void;
}) {
  const { formatMessage: fm } = useIntl();
  const create = useCreateTenant();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [region, setRegion] = useState("");
  const [tier, setTier] = useState<TierValue>(TIERS[1]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    create.mutate(
      {
        data: {
          name,
          slug: slug || undefined,
          region: region || undefined,
          tier,
        },
      },
      {
        onSuccess: () => {
          onCreated(name);
          onClose();
        },
      },
    );
  };

  return (
    <Modal
      title={fm(M.createTenantTitle)}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {fm(M.cancel)}
          </button>
          <button
            className="btn btn--primary"
            form="create-tenant"
            type="submit"
            disabled={create.isPending || !name.trim()}
          >
            {create.isPending ? fm(M.creating) : fm(M.create)}
          </button>
        </>
      }
    >
      <form id="create-tenant" onSubmit={submit}>
        <label className="field">
          <LabelText>{fm(M.fieldName)}</LabelText>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <div className="field-row">
          <label className="field">
            <LabelText help={fm(M.fieldSlugHelp)}>
              {fm(M.fieldSlugOptional)}
            </LabelText>
            <input value={slug} onChange={(e) => setSlug(e.target.value)} />
          </label>
          <label className="field">
            <LabelText help={fm(M.fieldRegionHelp)}>
              {fm(M.fieldRegionOptional)}
            </LabelText>
            <input value={region} onChange={(e) => setRegion(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <LabelText>{fm(M.fieldTier)}</LabelText>
          <select
            value={tier}
            onChange={(e) => setTier(e.target.value as TierValue)}
          >
            {TIERS.map((t) => (
              <option key={t} value={t}>
                {titleCase(t)}
              </option>
            ))}
          </select>
        </label>
        {create.isError && (
          <p className="error-text" role="alert">
            {fm(M.createTenantError)}
          </p>
        )}
      </form>
    </Modal>
  );
}
