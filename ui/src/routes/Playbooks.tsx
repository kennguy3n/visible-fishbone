import { useState } from "react";
import { useIntl, FormattedMessage } from "react-intl";
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
import { LanePage } from "./lane-b5";
import { playbooksMsg as M } from "./lane-b5.messages";

export function Playbooks() {
  return (
    <RequireTenant>{(tenantId) => <PlaybooksInner tenantId={tenantId} />}</RequireTenant>
  );
}

function PlaybooksInner({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const playbooks = usePlaybooks(tenantId);
  const executions = usePlaybookExecutions(tenantId);
  const approvals = usePendingApprovals(tenantId);
  const decide = useDecideApproval(tenantId);
  const [showCreate, setShowCreate] = useState(false);

  const pbCols: Column<Playbook>[] = [
    { header: intl.formatMessage(M.pbColName), cell: (p) => p.name },
    {
      header: intl.formatMessage(M.pbColTrigger),
      cell: (p) => <span className="mono">{p.trigger_condition}</span>,
    },
    {
      header: intl.formatMessage(M.pbColEnabled),
      cell: (p) => <StatusBadge status={p.enabled ? "enabled" : "disabled"} />,
    },
  ];

  const exCols: Column<PlaybookExecution>[] = [
    {
      header: intl.formatMessage(M.exColPlaybook),
      cell: (e) => <span className="mono">{e.playbook_id.slice(0, 8)}</span>,
    },
    { header: intl.formatMessage(M.exColStatus), cell: (e) => <StatusBadge status={e.status} /> },
    { header: intl.formatMessage(M.exColStarted), cell: (e) => formatRelative(e.started_at) },
    {
      header: intl.formatMessage(M.exColFinished),
      cell: (e) => (e.finished_at ? formatRelative(e.finished_at) : "—"),
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
        <Card title={intl.formatMessage(M.approvalsTitle)}>
          <AsyncBoundary
            isLoading={approvals.isLoading}
            error={approvals.error}
            data={approvals.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            onRetry={() => approvals.refetch()}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="shield" />}
                title={intl.formatMessage(M.approvalsEmptyTitle)}
                description={intl.formatMessage(M.approvalsEmptyBody)}
              />
            }
          >
            {(d) => (
              <div className="lane-stack">
                {(d.items ?? []).map((a: PlaybookApproval) => (
                  <div key={a.id} className="card lane-approval">
                    <div>
                      <div className="lane-approval__title">
                        <FormattedMessage
                          {...M.approvalHeading}
                          values={{
                            id: <span className="mono">{a.playbook_id.slice(0, 8)}</span>,
                          }}
                        />
                      </div>
                      <div className="lane-approval__meta">
                        {intl.formatMessage(M.approvalRequestedBy, {
                          who: a.requested_by,
                          when: formatRelative(a.requested_at),
                        })}
                        <Badge tone="warn" dot>
                          {intl.formatMessage(M.approvalPending)}
                        </Badge>
                      </div>
                    </div>
                    <div className="lane-approval__actions">
                      <button
                        className="btn btn--primary btn--sm"
                        disabled={decide.isPending}
                        onClick={() => decide.mutate({ id: a.id, decision: "approve" })}
                      >
                        {intl.formatMessage(M.approve)}
                      </button>
                      <button
                        className="btn btn--danger btn--sm"
                        disabled={decide.isPending}
                        onClick={() => decide.mutate({ id: a.id, decision: "reject" })}
                      >
                        {intl.formatMessage(M.reject)}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </AsyncBoundary>
        </Card>

        <div className="grid grid--2">
          <Card title={intl.formatMessage(M.playbooksTitle)}>
            <AsyncBoundary
              isLoading={playbooks.isLoading}
              error={playbooks.error}
              data={playbooks.data}
              isEmpty={(d) => (d.items?.length ?? 0) === 0}
              onRetry={() => playbooks.refetch()}
              empty={
                <EmptyState
                  illustration={<EmptyIllustration kind="policy" />}
                  title={intl.formatMessage(M.pbEmptyTitle)}
                  description={intl.formatMessage(M.pbEmptyBody)}
                  action={addButton}
                />
              }
            >
              {(d) => <DataTable columns={pbCols} rows={d.items ?? []} rowKey={(p) => p.id} />}
            </AsyncBoundary>
          </Card>

          <Card title={intl.formatMessage(M.execTitle)}>
            <AsyncBoundary
              isLoading={executions.isLoading}
              error={executions.error}
              data={executions.data}
              isEmpty={(d) => (d.items?.length ?? 0) === 0}
              onRetry={() => executions.refetch()}
              empty={
                <EmptyState
                  illustration={<EmptyIllustration kind="inbox" />}
                  title={intl.formatMessage(M.execEmptyTitle)}
                  description={intl.formatMessage(M.execEmptyBody)}
                />
              }
            >
              {(d) => <DataTable columns={exCols} rows={d.items ?? []} rowKey={(e) => e.id} />}
            </AsyncBoundary>
          </Card>
        </div>
      </div>

      {showCreate && (
        <CreatePlaybookModal tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </LanePage>
  );
}

function CreatePlaybookModal({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const intl = useIntl();
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
      setErr(intl.formatMessage(M.stepsError));
      return;
    }
    create.mutate(
      { name, trigger_condition: trigger, steps: parsedSteps, enabled: true },
      { onSuccess: onClose },
    );
  };

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
            onClick={submit}
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
      <label className="field">
        <span>{intl.formatMessage(M.triggerLabel)}</span>
        <input
          className="mono"
          value={trigger}
          onChange={(e) => setTrigger(e.target.value)}
        />
      </label>
      <p className="lane-help">{intl.formatMessage(M.triggerHelp)}</p>
      <label className="field">
        <span>{intl.formatMessage(M.stepsLabel)}</span>
        <textarea
          rows={8}
          className="lane-code"
          value={steps}
          onChange={(e) => setSteps(e.target.value)}
        />
      </label>
      <p className="lane-help">{intl.formatMessage(M.stepsHelp)}</p>
      {err && (
        <p className="error-text" role="alert">
          {err}
        </p>
      )}
      {create.isError && (
        <p className="error-text" role="alert">
          {intl.formatMessage(M.createError)}
        </p>
      )}
    </Modal>
  );
}
