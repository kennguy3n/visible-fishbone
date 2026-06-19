import { useState } from "react";
import { useIntl, type MessageDescriptor } from "react-intl";
import { useListRoles, useCreateRole } from "@/api/generated/endpoints/rbac/rbac";
import { RoleCreateRequestScope } from "@/api/generated/model";
import type { Role } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { useToast } from "@/components/Toast";
import { useTenant } from "@/lib/tenant-context";
import { M } from "./lane-b6.messages";
import { LanePage, LaneModal, PermissionDenied, LabelText } from "./_lane";
import { isPermissionDenied } from "./lane-utils";

// MSP-scoped roles share the RBAC store but carry scope "msp" or "platform",
// granting partner administrators cross-tenant authority. Each permission is
// paired with a plain-language label + description so non-expert operators
// understand what they are granting (the raw `msp.*` string is shown as
// secondary detail).
interface PermissionMeta {
  id: string;
  label: MessageDescriptor;
  desc: MessageDescriptor;
}

const PERMISSIONS: PermissionMeta[] = [
  { id: "msp.tenant.read", label: M.permTenantRead, desc: M.permTenantReadDesc },
  { id: "msp.tenant.write", label: M.permTenantWrite, desc: M.permTenantWriteDesc },
  {
    id: "msp.tenant.provision",
    label: M.permTenantProvision,
    desc: M.permTenantProvisionDesc,
  },
  {
    id: "msp.branding.write",
    label: M.permBrandingWrite,
    desc: M.permBrandingWriteDesc,
  },
  {
    id: "msp.policy.template.write",
    label: M.permPolicyTemplateWrite,
    desc: M.permPolicyTemplateWriteDesc,
  },
  { id: "msp.billing.read", label: M.permBillingRead, desc: M.permBillingReadDesc },
  { id: "msp.rbac.write", label: M.permRbacWrite, desc: M.permRbacWriteDesc },
];

const PERM_LABEL = new Map(PERMISSIONS.map((p) => [p.id, p.label]));

const MSP_SCOPES = [RoleCreateRequestScope.msp, RoleCreateRequestScope.platform];

function scopeName(scope: string): MessageDescriptor {
  return scope === "platform" ? M.rbacScopePlatformName : M.rbacScopeMspName;
}

export function MspRbac() {
  const { formatMessage: fm } = useIntl();
  const { selectedTenant, selectedTenantId } = useTenant();

  if (!selectedTenantId) {
    return (
      <LanePage>
        <PageHeader title={fm(M.rbacTitle)} subtitle={fm(M.rbacSubtitle)} />
        <Card>
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title={fm(M.scopeNoTenantTitle)}
            description={fm(M.scopeNoTenantBody)}
          />
        </Card>
      </LanePage>
    );
  }
  return (
    <MspRbacInner
      tenantId={selectedTenantId}
      tenantName={selectedTenant?.name ?? selectedTenantId}
    />
  );
}

function MspRbacInner({
  tenantId,
  tenantName,
}: {
  tenantId: string;
  tenantName: string;
}) {
  const { formatMessage: fm } = useIntl();
  const list = useListRoles(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  const mspRoles = (list.data?.items ?? []).filter(
    (r) => r.scope === "msp" || r.scope === "platform",
  );

  const newRoleBtn = (
    <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
      {fm(M.rbacNew)}
    </button>
  );

  const cols: Column<Role>[] = [
    { header: fm(M.rbacColRole), cell: (r) => <strong>{r.name}</strong> },
    {
      header: fm(M.rbacColScope),
      cell: (r) => <Badge tone="info">{fm(scopeName(r.scope))}</Badge>,
    },
    {
      header: fm(M.rbacColPerms),
      cell: (r) => (
        <div className="lb6-chips">
          {r.permissions.map((p) => {
            const label = PERM_LABEL.get(p);
            return (
              <Badge key={p} tone="neutral">
                {label ? fm(label) : p}
              </Badge>
            );
          })}
        </div>
      ),
    },
  ];

  return (
    <LanePage>
      <PageHeader
        title={fm(M.rbacTitle)}
        subtitle={fm(M.rbacSubtitle)}
        actions={newRoleBtn}
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
            isEmpty={() => mspRoles.length === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="shield" />}
                title={fm(M.rbacEmptyTitle)}
                description={fm(M.rbacEmptyBody)}
                action={newRoleBtn}
              />
            }
          >
            {() => (
              <DataTable columns={cols} rows={mspRoles} rowKey={(r) => r.id} />
            )}
          </AsyncBoundary>
        )}
      </Card>
      {showCreate && (
        <CreateMspRole
          tenantId={tenantId}
          tenantName={tenantName}
          onClose={() => setShowCreate(false)}
        />
      )}
    </LanePage>
  );
}

function CreateMspRole({
  tenantId,
  tenantName,
  onClose,
}: {
  tenantId: string;
  tenantName: string;
  onClose: () => void;
}) {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const create = useCreateRole();
  const [name, setName] = useState("");
  const [scope, setScope] = useState<RoleCreateRequestScope>(
    RoleCreateRequestScope.msp,
  );
  const [perms, setPerms] = useState<Set<string>>(new Set());

  const toggle = (p: string) =>
    setPerms((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });

  const scopeHelp =
    scope === RoleCreateRequestScope.platform
      ? fm(M.rbacScopePlatformHelp)
      : fm(M.rbacScopeMspHelp);

  return (
    <LaneModal
      title={fm(M.rbacCreateTitle)}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {fm(M.cancel)}
          </button>
          <button
            className="btn btn--primary"
            disabled={!name.trim() || perms.size === 0 || create.isPending}
            onClick={() =>
              create.mutate(
                {
                  tenantId,
                  data: { name: name.trim(), scope, permissions: [...perms] },
                },
                {
                  onSuccess: () => {
                    toast.success(
                      fm(M.rbacCreatedTitle),
                      fm(M.rbacCreatedBody, { name: name.trim() }),
                    );
                    onClose();
                  },
                },
              )
            }
          >
            {create.isPending ? fm(M.creating) : fm(M.create)}
          </button>
        </>
      }
    >
      <p className="muted" style={{ marginTop: 0 }}>
        {fm(M.rbacScopeForTenant, { tenant: tenantName })}
      </p>
      <label className="field">
        <LabelText>{fm(M.rbacName)}</LabelText>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="partner-admin"
          autoFocus
        />
      </label>
      <label className="field">
        <LabelText>{fm(M.rbacScope)}</LabelText>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as RoleCreateRequestScope)}
        >
          {MSP_SCOPES.map((s) => (
            <option key={s} value={s}>
              {fm(scopeName(s))}
            </option>
          ))}
        </select>
      </label>
      <p className="muted" style={{ marginBottom: 0 }}>
        {scopeHelp}
      </p>

      <fieldset
        style={{ border: "none", margin: 0, padding: 0, marginTop: 14 }}
      >
        <legend className="lb6-label" style={{ fontWeight: 600 }}>
          {fm(M.rbacPerms)}
        </legend>
        <p className="muted" style={{ margin: "4px 0 0" }}>
          {fm(M.rbacPermsHint)}
        </p>
        <div className="lb6-perms">
          {PERMISSIONS.map((p) => (
            <label key={p.id} className="lb6-perm">
              <input
                type="checkbox"
                checked={perms.has(p.id)}
                onChange={() => toggle(p.id)}
              />
              <span>
                <span className="lb6-perm__label">{fm(p.label)}</span>
                <span className="lb6-perm__desc">{fm(p.desc)}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      {create.isError && (
        <p className="error-text" role="alert">
          {fm(M.rbacError)}
        </p>
      )}
    </LaneModal>
  );
}
