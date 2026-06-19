import { useMemo, useState } from "react";
import { useIntl } from "react-intl";
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
import { useToast } from "@/components/Toast";
import { titleCase } from "@/lib/format";
import { useTenant } from "@/lib/tenant-context";
import { M } from "./lane-b6.messages";
import {
  LanePage,
  LaneModal,
  ConfirmDialog,
  PermissionDenied,
  LabelText,
} from "./_lane";
import { isPermissionDenied } from "./lane-utils";

export function MspHierarchy() {
  const { formatMessage: fm } = useIntl();
  const list = useListMSPs(undefined);
  const [selected, setSelected] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const newMspBtn = (
    <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
      {fm(M.hierNew)}
    </button>
  );

  return (
    <LanePage>
      <PageHeader
        title={fm(M.hierTitle)}
        subtitle={fm(M.hierSubtitle)}
        actions={newMspBtn}
      />
      <div className="grid grid--2">
        <Card title={fm(M.hierProviders)} subtitle={fm(M.hierProvidersSub)}>
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
                  illustration={<EmptyIllustration kind="inbox" />}
                  title={fm(M.hierEmptyTitle)}
                  description={fm(M.hierEmptyBody)}
                  action={newMspBtn}
                />
              }
            >
              {(d) => (
                <div className="tree" role="list">
                  {(d.items ?? []).map((m) => (
                    <MspNode
                      key={m.id}
                      msp={m}
                      selected={selected === m.id}
                      onSelect={() =>
                        setSelected(selected === m.id ? null : m.id)
                      }
                      onDeleted={(id) =>
                        setSelected((cur) => (cur === id ? null : cur))
                      }
                    />
                  ))}
                </div>
              )}
            </AsyncBoundary>
          )}
        </Card>
        <Card title={fm(M.hierBindings)}>
          {selected ? (
            <MspTenants mspId={selected} />
          ) : (
            <EmptyState
              icon="←"
              title={fm(M.hierPickPrompt)}
              description={fm(M.hierPickBody)}
            />
          )}
        </Card>
      </div>
      {showCreate && <CreateMsp onClose={() => setShowCreate(false)} />}
    </LanePage>
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
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const status = useUpdateMSPStatus();
  const del = useDeleteMSP();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const isDeleted = msp.status === MSPStatus.deleted;

  return (
    <div
      className="tree__node"
      role="listitem"
      style={{ borderColor: selected ? "var(--brand)" : "var(--border-soft)" }}
    >
      <button className="tree__label" onClick={onSelect} aria-pressed={selected}>
        <span style={{ fontWeight: 700 }}>{msp.name}</span>
        <span className="mono muted"> {msp.slug}</span>
      </button>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <StatusBadge status={msp.status} />
        {/* Routine transitions only. `deleted` is a terminal, cascading state
            (it clears tenants.msp_id across the whole cohort), so it is
            deliberately NOT offered here — mirroring the API's MSPCreateStatus,
            which omits it — to stop an operator soft-deleting an MSP with a
            stray dropdown pick. Deletion goes through the guarded Delete
            button, consistent with destructive actions elsewhere. */}
        <select
          value={msp.status}
          disabled={isDeleted || status.isPending}
          aria-label={fm(M.hierStatusLabel, { name: msp.name })}
          onChange={(e) =>
            status.mutate(
              {
                mspId: msp.id,
                data: { status: e.target.value as MSPStatus },
              },
              {
                onSuccess: () => toast.success(fm(M.hierStatusToast)),
                onError: () => toast.error(fm(M.hierActionError)),
              },
            )
          }
          style={{ width: 130 }}
        >
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
          onClick={() => setConfirmDelete(true)}
        >
          {fm(M.delete)}
        </button>
      </div>

      {confirmDelete && (
        <ConfirmDialog
          title={fm(M.hierDeleteTitle, { name: msp.name })}
          confirmLabel={fm(M.hierDeleteCta)}
          tone="danger"
          busy={del.isPending}
          onClose={() => setConfirmDelete(false)}
          onConfirm={() =>
            del.mutate(
              { mspId: msp.id },
              {
                onSuccess: () => {
                  onDeleted(msp.id);
                  setConfirmDelete(false);
                  toast.success(fm(M.hierDeletedToast, { name: msp.name }));
                },
                onError: () => toast.error(fm(M.hierActionError)),
              },
            )
          }
        >
          <p>{fm(M.hierDeleteBody)}</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function MspTenants({ mspId }: { mspId: string }) {
  const { formatMessage: fm } = useIntl();
  const { tenants } = useTenant();
  const tenantList = useListMSPTenants(mspId, undefined);
  const nameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const t of tenants) map.set(t.id, t.name);
    return map;
  }, [tenants]);

  if (tenantList.isLoading) return <LoadingState />;
  const items = tenantList.data?.items ?? [];
  if (items.length === 0)
    return (
      <EmptyState
        title={fm(M.hierTenantsEmptyTitle)}
        description={fm(M.hierTenantsEmptyBody)}
      />
    );
  return (
    <ul className="tree tree--child">
      {items.map((b) => (
        <li key={b.tenant_id} className="tree__leaf">
          <span>{nameById.get(b.tenant_id) ?? b.tenant_id.slice(0, 12)}</span>
          <StatusBadge status={b.relationship} />
        </li>
      ))}
    </ul>
  );
}

function CreateMsp({ onClose }: { onClose: () => void }) {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const create = useCreateMSP();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  return (
    <LaneModal
      title={fm(M.hierCreateTitle)}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {fm(M.cancel)}
          </button>
          <button
            className="btn btn--primary"
            disabled={!name.trim() || !slug.trim() || create.isPending}
            onClick={() =>
              create.mutate(
                { data: { name, slug } },
                {
                  onSuccess: () => {
                    toast.success(fm(M.hierCreatedToast, { name }));
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
      <label className="field">
        <LabelText>{fm(M.fieldName)}</LabelText>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </label>
      <label className="field">
        <LabelText help={fm(M.fieldSlugHelp)}>{fm(M.fieldSlug)}</LabelText>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="acme-msp"
        />
      </label>
      {create.isError && (
        <p className="error-text" role="alert">
          {fm(M.hierCreateError)}
        </p>
      )}
    </LaneModal>
  );
}
