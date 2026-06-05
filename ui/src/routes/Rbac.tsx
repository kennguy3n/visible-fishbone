import { useState } from "react";
import {
  useListRoles,
  useCreateRole,
} from "@/api/generated/endpoints/rbac/rbac";
import { RoleCreateRequestScope } from "@/api/generated/model";
import type { Role } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { titleCase } from "@/lib/format";

const PERMISSIONS = [
  "tenant.read",
  "tenant.write",
  "policy.read",
  "policy.write",
  "device.read",
  "device.write",
  "alert.read",
  "alert.write",
  "compliance.read",
  "billing.read",
];

export function Rbac() {
  return <RequireTenant>{(tenantId) => <RbacInner tenantId={tenantId} />}</RequireTenant>;
}

function RbacInner({ tenantId }: { tenantId: string }) {
  const list = useListRoles(tenantId);
  const [showCreate, setShowCreate] = useState(false);

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
        title="RBAC roles"
        subtitle="Scoped permission sets assignable to operators and service principals."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Role
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">No roles defined.</p>}
        >
          {(d) => <DataTable columns={cols} rows={d.items ?? []} rowKey={(r) => r.id} />}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateRole tenantId={tenantId} onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateRole({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const create = useCreateRole();
  const [name, setName] = useState("");
  const [scope, setScope] = useState<RoleCreateRequestScope>(
    Object.values(RoleCreateRequestScope)[0] as RoleCreateRequestScope,
  );
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
      title="New role"
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
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="soc-analyst" />
      </label>
      <label className="field">
        <span>Scope</span>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as RoleCreateRequestScope)}
        >
          {Object.values(RoleCreateRequestScope).map((s) => (
            <option key={s} value={s}>
              {titleCase(s)}
            </option>
          ))}
        </select>
      </label>
      <span style={{ color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>
        Permissions
      </span>
      <div style={{ marginTop: 8, columnCount: 2 }}>
        {PERMISSIONS.map((p) => (
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
