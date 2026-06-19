import { useId, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useListRoles,
  useCreateRole,
  getListRolesQueryKey,
} from "@/api/generated/endpoints/rbac/rbac";
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
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { HelpTooltip } from "@/components/HelpTooltip";
import { titleCase } from "@/lib/format";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { isForbidden, PermissionDenied } from "./lane-b4-ui";
import type { LaneKey } from "./lane-b4-messages";

const PERMISSIONS: { code: string; labelKey: LaneKey }[] = [
  { code: "tenant.read", labelKey: "perm.tenant.read" },
  { code: "tenant.write", labelKey: "perm.tenant.write" },
  { code: "policy.read", labelKey: "perm.policy.read" },
  { code: "policy.write", labelKey: "perm.policy.write" },
  { code: "device.read", labelKey: "perm.device.read" },
  { code: "device.write", labelKey: "perm.device.write" },
  { code: "alert.read", labelKey: "perm.alert.read" },
  { code: "alert.write", labelKey: "perm.alert.write" },
  { code: "compliance.read", labelKey: "perm.compliance.read" },
  { code: "billing.read", labelKey: "perm.billing.read" },
];

const PERM_LABEL = new Map<string, LaneKey>(
  PERMISSIONS.map((p) => [p.code, p.labelKey]),
);

const SCOPE_LABEL = new Map<string, LaneKey>([
  ["platform", "rbac.scope.platform"],
  ["msp", "rbac.scope.msp"],
  ["tenant", "rbac.scope.tenant"],
  ["site", "rbac.scope.site"],
]);

export function Rbac() {
  return (
    <LaneB4Screen>
      <RequireTenant>{(tenantId) => <RbacInner tenantId={tenantId} />}</RequireTenant>
    </LaneB4Screen>
  );
}

function RbacInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const list = useListRoles(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  if (isForbidden(list.error)) return <PermissionDenied />;

  const cols: Column<Role>[] = [
    { header: t("rbac.col.role"), cell: (r) => r.name },
    {
      header: t("rbac.col.scope"),
      cell: (r) => (
        <Badge tone="info">
          {SCOPE_LABEL.has(r.scope) ? t(SCOPE_LABEL.get(r.scope)!) : titleCase(r.scope)}
        </Badge>
      ),
    },
    {
      header: t("rbac.col.permissions"),
      cell: (r) => (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {r.permissions.map((p) => (
            <Badge key={p} tone="neutral">
              {PERM_LABEL.has(p) ? t(PERM_LABEL.get(p)!) : titleCase(p)}
            </Badge>
          ))}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t("rbac.title")}
        subtitle={t("rbac.subtitle")}
        actions={
          <>
            <HelpTooltip title={t("rbac.help.title")}>{t("rbac.help.body")}</HelpTooltip>
            <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
              {t("rbac.new")}
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
              title={t("rbac.empty.title")}
              description={t("rbac.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setShowCreate(true)}>
                  {t("rbac.empty.action")}
                </button>
              }
            />
          }
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(r) => r.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateRole tenantId={tenantId} onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateRole({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const t = useT();
  const create = useCreateRole();
  const qc = useQueryClient();
  const formId = useId();
  const nameId = useId();
  const nameHelpId = useId();
  const scopeId = useId();
  const scopeHelpId = useId();
  const permsErrId = useId();

  const [name, setName] = useState("");
  // Default to the least-privilege scope so a role is never platform-wide unless
  // the operator deliberately selects it.
  const [scope, setScope] = useState<RoleCreateRequestScope>(
    RoleCreateRequestScope.tenant,
  );
  const [perms, setPerms] = useState<Set<string>>(new Set());
  const [submitted, setSubmitted] = useState(false);

  const nameInvalid = submitted && name.trim() === "";
  const permsInvalid = submitted && perms.size === 0;

  const toggle = (p: string) =>
    setPerms((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });

  const submit = () => {
    setSubmitted(true);
    if (name.trim() === "" || perms.size === 0) return;
    create.mutate(
      { tenantId, data: { name: name.trim(), scope, permissions: [...perms] } },
      {
        onSuccess: () => {
          void qc.invalidateQueries({ queryKey: getListRolesQueryKey(tenantId) });
          onClose();
        },
      },
    );
  };

  return (
    <Modal
      title={t("rbac.modal.title")}
      onClose={onClose}
      footer={
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
            {create.isPending ? t("rbac.creating") : t("rbac.create")}
          </button>
        </>
      }
    >
      <form
        id={formId}
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label className="field" htmlFor={nameId}>
          <span>{t("rbac.field.name")}</span>
          <input
            id={nameId}
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("rbac.field.name.placeholder")}
            aria-invalid={nameInvalid}
            aria-describedby={nameHelpId}
          />
          <span
            id={nameHelpId}
            className={`field-help${nameInvalid ? " field-help--error" : ""}`}
            role={nameInvalid ? "alert" : undefined}
          >
            {nameInvalid ? t("rbac.error.nameRequired") : t("rbac.field.name.help")}
          </span>
        </label>

        <label className="field" htmlFor={scopeId}>
          <span>{t("rbac.field.scope")}</span>
          <select
            id={scopeId}
            value={scope}
            onChange={(e) => setScope(e.target.value as RoleCreateRequestScope)}
            aria-describedby={scopeHelpId}
          >
            {Object.values(RoleCreateRequestScope).map((s) => (
              <option key={s} value={s}>
                {SCOPE_LABEL.has(s) ? t(SCOPE_LABEL.get(s)!) : titleCase(s)}
              </option>
            ))}
          </select>
          <span id={scopeHelpId} className="field-help">
            {t("rbac.field.scope.help")}
          </span>
        </label>

        <fieldset
          className="perm-grid"
          aria-invalid={permsInvalid}
          aria-describedby={permsInvalid ? permsErrId : undefined}
        >
          <legend>{t("rbac.field.permissions")}</legend>
          {PERMISSIONS.map((p) => (
            <label key={p.code} className="perm-option">
              <input
                type="checkbox"
                checked={perms.has(p.code)}
                onChange={() => toggle(p.code)}
              />
              <span className="perm-option__label">
                <span>{t(p.labelKey)}</span>
                <span className="perm-option__code">{p.code}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <span className="field-help" aria-live="polite">
          {permsInvalid ? "" : t("rbac.permsSelected", { count: perms.size })}
        </span>
        {permsInvalid && (
          <span id={permsErrId} className="field-help field-help--error" role="alert">
            {t("rbac.error.permsRequired")}
          </span>
        )}

        {create.isError && (
          <p className="error-text" role="alert">
            {t("rbac.error.create")}
          </p>
        )}
      </form>
    </Modal>
  );
}
