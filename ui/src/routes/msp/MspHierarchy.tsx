import { useState } from "react";
import {
  useListMSPs,
  useCreateMSP,
  useListMSPTenants,
  useUpdateMSPStatus,
  useDeleteMSP,
} from "@/api/generated/endpoints/msps/msps";
import { MSPStatus, MSPCreateStatus } from "@/api/generated/model";
import type { Msp } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  LoadingState,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { Modal } from "@/components/Modal";
import { titleCase } from "@/lib/format";

export function MspHierarchy() {
  const list = useListMSPs(undefined);
  const [selected, setSelected] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  return (
    <>
      <PageHeader
        title="MSP hierarchy"
        subtitle="Managed service providers and the tenants they administer."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + New MSP
          </button>
        }
      />
      <div className="grid grid--2">
        <Card title="Providers">
          <AsyncBoundary
            isLoading={list.isLoading}
            error={list.error}
            data={list.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="inbox" />}
                title="No providers registered"
                description="Managed service providers will appear here once registered."
              />
            }
          >
            {(d) => (
              <div className="tree">
                {(d.items ?? []).map((m) => (
                  <MspNode
                    key={m.id}
                    msp={m}
                    selected={selected === m.id}
                    onSelect={() => setSelected(selected === m.id ? null : m.id)}
                    onDeleted={(id) =>
                      setSelected((cur) => (cur === id ? null : cur))
                    }
                  />
                ))}
              </div>
            )}
          </AsyncBoundary>
        </Card>
        <Card title="Tenant bindings">
          {selected ? (
            <MspTenants mspId={selected} />
          ) : (
            <p className="muted">Select a provider to view its tenant cohort.</p>
          )}
        </Card>
      </div>
      {showCreate && <CreateMsp onClose={() => setShowCreate(false)} />}
    </>
  );
}

function MspNode({
  msp,
  selected,
  onSelect,
  onDeleted,
}: {
  msp: Msp;
  selected: boolean;
  onSelect: () => void;
  onDeleted: (id: string) => void;
}) {
  const status = useUpdateMSPStatus();
  const del = useDeleteMSP();
  const isDeleted = msp.status === MSPStatus.deleted;
  return (
    <div
      className="tree__node"
      style={{ borderColor: selected ? "var(--brand)" : "var(--border-soft)" }}
    >
      <button className="tree__label" onClick={onSelect}>
        <span style={{ fontWeight: 700 }}>{msp.name}</span>
        <span className="mono muted"> {msp.slug}</span>
      </button>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <StatusBadge status={msp.status} />
        {/* Routine transitions only. `deleted` is a terminal, cascading state
            (it clears tenants.msp_id across the whole cohort), so it is
            deliberately NOT offered here — mirroring the API's MSPCreateStatus,
            which omits it — to stop an operator soft-deleting an MSP with a
            stray dropdown pick. Deletion goes through the confirm()-gated
            Delete button, consistent with destructive actions elsewhere. */}
        <select
          value={msp.status}
          disabled={isDeleted || status.isPending}
          onChange={(e) =>
            status.mutate({
              mspId: msp.id,
              data: { status: e.target.value as MSPStatus },
            })
          }
          style={{ width: 130 }}
        >
          {/* Keep a matching (but unselectable) option for a terminal status so
              the controlled <select> stays consistent. */}
          {isDeleted && (
            <option value={msp.status} disabled>
              {titleCase(msp.status)}
            </option>
          )}
          {Object.values(MSPCreateStatus).map((s) => (
            <option key={s} value={s}>
              {titleCase(s)}
            </option>
          ))}
        </select>
        <button
          className="btn btn--danger btn--sm"
          disabled={isDeleted || del.isPending}
          onClick={() => {
            if (
              confirm(
                `Delete MSP "${msp.name}"? This soft-deletes the provider and ` +
                  `unassigns every tenant in its cohort. This cannot be undone.`,
              )
            ) {
              del.mutate(
                { mspId: msp.id },
                { onSuccess: () => onDeleted(msp.id) },
              );
            }
          }}
        >
          Delete
        </button>
      </div>
    </div>
  );
}

function MspTenants({ mspId }: { mspId: string }) {
  const tenants = useListMSPTenants(mspId, undefined);
  if (tenants.isLoading) return <LoadingState />;
  const items = tenants.data?.items ?? [];
  if (items.length === 0)
    return (
      <EmptyState
        title="No tenants assigned"
        description="This provider has no tenants assigned yet."
      />
    );
  return (
    <ul className="tree tree--child">
      {items.map((b) => (
        <li key={b.tenant_id} className="tree__leaf">
          <span className="mono">{b.tenant_id.slice(0, 12)}</span>
          <StatusBadge status={b.relationship} />
        </li>
      ))}
    </ul>
  );
}

function CreateMsp({ onClose }: { onClose: () => void }) {
  const create = useCreateMSP();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  return (
    <Modal
      title="New MSP"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            disabled={!name || !slug || create.isPending}
            onClick={() => create.mutate({ data: { name, slug } }, { onSuccess: onClose })}
          >
            {create.isPending ? "Creating…" : "Create"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="field">
        <span>Slug</span>
        <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="acme-msp" />
      </label>
      {create.isError && (
        <p className="error-text">
          {create.error instanceof Error ? create.error.message : "Failed"}
        </p>
      )}
    </Modal>
  );
}
