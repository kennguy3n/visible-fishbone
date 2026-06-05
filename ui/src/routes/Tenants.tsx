import { useState } from "react";
import {
  useListTenants,
  useCreateTenant,
  useSuspendTenant,
  useDeleteTenant,
} from "@/api/generated/endpoints/tenants/tenants";
import type { Tenant } from "@/api/generated/model";
import { TenantCreateRequestTier } from "@/api/generated/model";
import { PageHeader, Card, StatusBadge, Badge, AsyncBoundary } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { formatDateTime, titleCase } from "@/lib/format";
import { useTenant } from "@/lib/tenant-context";

type TierValue = (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];
const TIERS = Object.values(TenantCreateRequestTier) as TierValue[];

export function Tenants() {
  const list = useListTenants();
  const { setSelectedTenantId } = useTenant();
  const [showCreate, setShowCreate] = useState(false);

  const suspend = useSuspendTenant();
  const del = useDeleteTenant();

  const columns: Column<Tenant>[] = [
    {
      header: "Name",
      cell: (t) => (
        <button
          className="btn btn--ghost btn--sm"
          onClick={() => setSelectedTenantId(t.id)}
          title="Make active tenant"
        >
          {t.name}
        </button>
      ),
    },
    { header: "Slug", cell: (t) => <span className="mono">{t.slug}</span> },
    { header: "Status", cell: (t) => <StatusBadge status={t.status} /> },
    { header: "Tier", cell: (t) => <Badge tone="info">{titleCase(t.tier)}</Badge> },
    { header: "Region", cell: (t) => t.region ?? "—" },
    { header: "MSP", cell: (t) => (t.msp_id ? "managed" : "direct") },
    { header: "Created", cell: (t) => formatDateTime(t.created_at) },
    {
      header: "",
      cell: (t) => (
        <div style={{ display: "flex", gap: 6 }}>
          <button
            className="btn btn--sm"
            disabled={t.status === "suspended" || suspend.isPending}
            onClick={() => suspend.mutate({ tenantId: t.id })}
          >
            Suspend
          </button>
          <button
            className="btn btn--danger btn--sm"
            disabled={del.isPending}
            onClick={() => {
              if (confirm(`Delete tenant "${t.name}"? This cannot be undone.`))
                del.mutate({ tenantId: t.id });
            }}
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Tenants"
        subtitle="Customer organizations managed by this control plane."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + New tenant
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
        >
          {(d) => (
            <DataTable columns={columns} rows={d.items ?? []} rowKey={(t) => t.id} />
          )}
        </AsyncBoundary>
      </Card>
      {showCreate && <CreateTenantModal onClose={() => setShowCreate(false)} />}
    </>
  );
}

function CreateTenantModal({ onClose }: { onClose: () => void }) {
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
      { onSuccess: onClose },
    );
  };

  return (
    <Modal
      title="Create tenant"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            form="create-tenant"
            type="submit"
            disabled={create.isPending || !name}
          >
            {create.isPending ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      <form id="create-tenant" onSubmit={submit}>
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <div className="field-row">
          <label className="field">
            <span>Slug (optional)</span>
            <input value={slug} onChange={(e) => setSlug(e.target.value)} />
          </label>
          <label className="field">
            <span>Region (optional)</span>
            <input value={region} onChange={(e) => setRegion(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Tier</span>
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
          <p className="error-text">
            {create.error instanceof Error
              ? create.error.message
              : "Failed to create tenant"}
          </p>
        )}
      </form>
    </Modal>
  );
}
