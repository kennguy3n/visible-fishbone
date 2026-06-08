import {
  useRunTroubleshootDiagnostics,
  useListTroubleshootKBEntries,
} from "@/api/generated/endpoints/troubleshoot/troubleshoot";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  Badge,
  ErrorState,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative } from "@/lib/format";

export function Troubleshoot() {
  return (
    <RequireTenant>
      {(tenantId) => <TroubleshootInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function TroubleshootInner({ tenantId }: { tenantId: string }) {
  const diagnostics = useRunTroubleshootDiagnostics();
  const kb = useListTroubleshootKBEntries(tenantId, undefined);

  const results = diagnostics.data?.results ?? [];

  return (
    <>
      <PageHeader
        title="Troubleshooting"
        subtitle="Run platform diagnostics and search the resolution knowledge base."
        actions={
          <button
            className="btn btn--primary"
            disabled={diagnostics.isPending}
            onClick={() => diagnostics.mutate({ tenantId })}
          >
            {diagnostics.isPending ? "Running…" : "Run diagnostics"}
          </button>
        }
      />

      <Card title="Diagnostic checks">
        {diagnostics.isError ? (
          <ErrorState error={diagnostics.error} />
        ) : diagnostics.isSuccess && results.length === 0 ? (
          <p className="muted">All checks passed or no checks returned.</p>
        ) : results.length === 0 ? (
          <p className="muted">
            Run diagnostics to evaluate tunnel health, policy compilation,
            connector reachability and posture pipeline status.
          </p>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Message</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td className="mono">{r.check_name}</td>
                  <td>
                    <StatusBadge status={r.status} />
                  </td>
                  <td>{r.message}</td>
                  <td>{formatRelative(r.executed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Knowledge base" className="">
        <AsyncBoundary
          isLoading={kb.isLoading}
          error={kb.error}
          data={kb.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title="No knowledge base entries"
              description="Troubleshooting articles and remediation guides will appear here."
            />
          }
        >
          {(d) => (
            <div className="grid" style={{ gap: 10 }}>
              {(d.items ?? []).map((e) => (
                <div key={e.id} className="card">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong>{e.title}</strong>
                    <Badge tone="info">{e.category}</Badge>
                  </div>
                  <p className="muted" style={{ fontSize: 13 }}>
                    {e.content.length > 240 ? `${e.content.slice(0, 240)}…` : e.content}
                  </p>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {e.tags.map((t) => (
                      <Badge key={t} tone="neutral">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}
