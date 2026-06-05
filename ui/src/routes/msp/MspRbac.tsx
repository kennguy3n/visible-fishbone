import { useState } from "react";
import { useListRoles, useCreateRole } from "@/api/generated/endpoints/rbac/rbac";
import { RoleCreateRequestScope } from "@/api/generated/model";
import type { Role } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, Badge, EmptyState } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { useTenant } from "@/lib/tenant-context";
import { titleCase } from "@/lib/format";

// MSP-scoped roles share the RBAC store but carry scope "msp" or
// "platform", granting partner administrators cross-tenant authority.
const MSP_PERMISSIONS = [
  "msp.tenant.read",
  "msp.tenant.write",
  "msp.tenant.provision",
  "msp.branding.write",
  "msp.policy.template.write",
  "msp.billing.read",
  "msp.rbac.write",
];

const MSP_SCOPES = [RoleCreateRequestScope.msp, RoleCreateRequestScope.platform];

export function MspRbac() {
  const { selectedTenantId } = useTenant();

  if (!selectedTenantId) {
    return (
      <>
        <PageHeader title="MSP RBAC" subtitle="Partner-scoped role administration." />
        <EmptyState
          title="Select a tenant"
          hint="MSP roles are managed in the context of the partner's management tenant. Pick a tenant from the top bar."
        />
      </>
    );
  }
  return <MspRbacInner tenantId={selectedTenantId} />;
}

function MspRbacInner({ tenantId }: { tenantId: string }) {
  const list = useListRoles(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  const mspRoles = (list.data?.items ?? []).filter(
    (r) => r.scope === "msp" || r.scope === "platform",
  );

  const cols: Column<Role>[] = [
    { header: "Role", cell: (r) => r.name },
    { header: "Scope", cell: (r) => <Badge tone="info">{titleCase(r.scope)}</Badge> },
    {
      header: "Permissions",
      cell: (r) => (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {r.permissions.map((p) => (
            <Badge key={p} tone="neutral">
              {p}
            </Badge>
          ))}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="MSP RBAC"
        subtitle="Partner-scoped roles granting cross-tenant administrative authority."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + MSP role
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={() => mspRoles.length === 0}
          empty={<p className="muted">No MSP- or platform-scoped roles defined.</p>}
        >
          {() => <DataTable columns={cols} rows={mspRoles} rowKey={(r) => r.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && (
        <CreateMspRole tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </>
  );
}

function CreateMspRole({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateRole();
  const [name, setName] = useState("");
  const [scope, setScope] = useState<RoleCreateRequestScope>(RoleCreateRequestScope.msp);
  const [perms, setPerms] = useState<Set<string>>(new Set());

  const toggle = (p: string) =>
    setPerms((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });

  return (
    <Modal
      title="New MSP role"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            disabled={!name || perms.size === 0 || create.isPending}
            onClick={() =>
              create.mutate(
                { tenantId, data: { name, scope, permissions: [...perms] } },
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
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="partner-admin" />
      </label>
      <label className="field">
        <span>Scope</span>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as RoleCreateRequestScope)}
        >
          {MSP_SCOPES.map((s) => (
            <option key={s} value={s}>
              {titleCase(s)}
            </option>
          ))}
        </select>
      </label>
      <span style={{ color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>
        Permissions
      </span>
      <div style={{ marginTop: 8 }}>
        {MSP_PERMISSIONS.map((p) => (
          <label
            key={p}
            style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}
          >
            <input
              type="checkbox"
              style={{ width: 16 }}
              checked={perms.has(p)}
              onChange={() => toggle(p)}
            />
            <span className="mono" style={{ fontSize: 12.5 }}>
              {p}
            </span>
          </label>
        ))}
      </div>
      {create.isError && (
        <p className="error-text">
          {create.error instanceof Error ? create.error.message : "Failed"}
        </p>
      )}
    </Modal>
  );
}
