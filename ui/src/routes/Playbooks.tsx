import { useState } from "react";
import {
  usePlaybooks,
  usePlaybookExecutions,
  usePendingApprovals,
  useCreatePlaybook,
  useDecideApproval,
} from "@/api/manual/hooks";
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
import { formatRelative } from "@/lib/format";
import type { Playbook, PlaybookExecution, PlaybookApproval } from "@/api/manual/types";

export function Playbooks() {
  return (
    <RequireTenant>{(tenantId) => <PlaybooksInner tenantId={tenantId} />}</RequireTenant>
  );
}

function PlaybooksInner({ tenantId }: { tenantId: string }) {
  const playbooks = usePlaybooks(tenantId);
  const executions = usePlaybookExecutions(tenantId);
  const approvals = usePendingApprovals(tenantId);
  const decide = useDecideApproval(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  const pbCols: Column<Playbook>[] = [
    { header: "Name", cell: (p) => p.name },
    { header: "Trigger", cell: (p) => <span className="mono">{p.trigger_condition}</span> },
    { header: "Enabled", cell: (p) => <StatusBadge status={p.enabled ? "enabled" : "disabled"} /> },
  ];

  const exCols: Column<PlaybookExecution>[] = [
    { header: "Playbook", cell: (e) => <span className="mono">{e.playbook_id.slice(0, 8)}</span> },
    { header: "Status", cell: (e) => <StatusBadge status={e.status} /> },
    { header: "Started", cell: (e) => formatRelative(e.started_at) },
    { header: "Finished", cell: (e) => (e.finished_at ? formatRelative(e.finished_at) : "—") },
  ];

  return (
    <>
      <PageHeader
        title="Playbooks"
        subtitle="Automated response runbooks with human-in-the-loop approval."
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            + Playbook
          </button>
        }
      />

      <Card title="Pending approvals">
        <AsyncBoundary
          isLoading={approvals.isLoading}
          error={approvals.error}
          data={approvals.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="inbox" />}
              title="No approvals waiting"
              description="Playbook runs that need sign-off will appear here."
            />
          }
        >
          {(d) => (
            <div className="grid" style={{ gap: 10 }}>
              {(d.items ?? []).map((a: PlaybookApproval) => (
                <div
                  key={a.id}
                  className="card"
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
                >
                  <div>
                    <div style={{ fontWeight: 700 }}>
                      Playbook <span className="mono">{a.playbook_id.slice(0, 8)}</span>
                    </div>
                    <div className="muted" style={{ fontSize: 12.5 }}>
                      Requested by {a.requested_by} · {formatRelative(a.requested_at)} ·{" "}
                      <Badge tone="warn">{a.status}</Badge>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      className="btn btn--primary btn--sm"
                      disabled={decide.isPending}
                      onClick={() => decide.mutate({ id: a.id, decision: "approve" })}
                    >
                      Approve
                    </button>
                    <button
                      className="btn btn--danger btn--sm"
                      disabled={decide.isPending}
                      onClick={() => decide.mutate({ id: a.id, decision: "reject" })}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </AsyncBoundary>
      </Card>

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        <Card title="Playbooks">
          <AsyncBoundary
            isLoading={playbooks.isLoading}
            error={playbooks.error}
            data={playbooks.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="policy" />}
                title="No playbooks yet"
                description="Define an automated response playbook to remediate incidents with one click."
              />
            }
          >
            {(d) => <DataTable columns={pbCols} rows={d.items ?? []} rowKey={(p) => p.id} />}
          </AsyncBoundary>
        </Card>

        <Card title="Recent executions">
          <AsyncBoundary
            isLoading={executions.isLoading}
            error={executions.error}
            data={executions.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="inbox" />}
                title="No executions yet"
                description="Playbook runs and their outcomes will be listed here."
              />
            }
          >
            {(d) => <DataTable columns={exCols} rows={d.items ?? []} rowKey={(e) => e.id} />}
          </AsyncBoundary>
        </Card>
      </div>

      {showCreate && (
        <CreatePlaybookModal tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </>
  );
}

function CreatePlaybookModal({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const create = useCreatePlaybook(tenantId);
  const [name, setName] = useState("");
  const [trigger, setTrigger] = useState("alert.severity == 'critical'");
  const [steps, setSteps] = useState(
    JSON.stringify([{ action: "notify", channel: "soc" }], null, 2),
  );
  const [err, setErr] = useState<string | null>(null);

  const submit = () => {
    setErr(null);
    let parsedSteps: unknown;
    try {
      parsedSteps = JSON.parse(steps);
    } catch {
      setErr("Steps must be valid JSON.");
      return;
    }
    create.mutate(
      { name, trigger_condition: trigger, steps: parsedSteps, enabled: true },
      { onSuccess: onClose },
    );
  };

  return (
    <Modal
      title="New playbook"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            disabled={!name || create.isPending}
            onClick={submit}
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
        <span>Trigger condition</span>
        <input value={trigger} onChange={(e) => setTrigger(e.target.value)} />
      </label>
      <label className="field">
        <span>Steps (JSON)</span>
        <textarea
          style={{ minHeight: 140 }}
          value={steps}
          onChange={(e) => setSteps(e.target.value)}
        />
      </label>
      {err && <p className="error-text">{err}</p>}
      {create.isError && (
        <p className="error-text">
          {create.error instanceof Error ? create.error.message : "Failed"}
        </p>
      )}
    </Modal>
  );
}
