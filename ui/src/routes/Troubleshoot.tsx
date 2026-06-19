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
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative } from "@/lib/format";
import { LaneB2Intl, useT } from "./lane-b2/i18n";

export function Troubleshoot() {
  return (
    <LaneB2Intl>
      <RequireTenant>
        {(tenantId) => <TroubleshootInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB2Intl>
  );
}

function TroubleshootInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const diagnostics = useRunTroubleshootDiagnostics();
  const kb = useListTroubleshootKBEntries(tenantId, undefined);

  const results = diagnostics.data?.results ?? [];
  const run = () => diagnostics.mutate({ tenantId });

  return (
    <>
      <PageHeader
        title={t("ts.title")}
        subtitle={t("ts.subtitle")}
        actions={
          <button className="btn btn--primary" disabled={diagnostics.isPending} onClick={run}>
            {diagnostics.isPending ? t("ts.running") : t("ts.run")}
          </button>
        }
      />

      <div className="grid">
        <Card
          title={t("ts.checks.title")}
          actions={
            <HelpTooltip title={t("ts.checks.help.title")} align="right">
              {t("ts.checks.help.body")}
            </HelpTooltip>
          }
        >
          {diagnostics.isError ? (
            <ErrorState error={t("ts.checks.error")} onRetry={run} />
          ) : results.length > 0 ? (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>{t("ts.col.check")}</th>
                    <th>{t("ts.col.status")}</th>
                    <th>{t("ts.col.message")}</th>
                    <th>{t("ts.col.when")}</th>
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
            </div>
          ) : diagnostics.isSuccess ? (
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("ts.checks.allclear.title")}
              description={t("ts.checks.allclear.body")}
            />
          ) : (
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title={t("ts.checks.title")}
              description={t("ts.checks.intro")}
              action={
                <button
                  className="btn btn--primary"
                  disabled={diagnostics.isPending}
                  onClick={run}
                >
                  {diagnostics.isPending ? t("ts.running") : t("ts.run")}
                </button>
              }
            />
          )}
        </Card>

        <Card title={t("ts.kb.title")}>
          <AsyncBoundary
            isLoading={kb.isLoading}
            error={kb.error}
            data={kb.data}
            onRetry={() => kb.refetch()}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                illustration={<EmptyIllustration kind="search" />}
                title={t("ts.kb.empty.title")}
                description={t("ts.kb.empty.body")}
              />
            }
          >
            {(d) => (
              <div className="grid" style={{ gap: 10 }}>
                {(d.items ?? []).map((e) => (
                  <div key={e.id} className="card">
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                      <strong>{e.title}</strong>
                      <Badge tone="info">{e.category}</Badge>
                    </div>
                    <p className="muted" style={{ fontSize: 13 }}>
                      {e.content.length > 240 ? `${e.content.slice(0, 240)}…` : e.content}
                    </p>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {e.tags.map((tag) => (
                        <Badge key={tag} tone="neutral">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </AsyncBoundary>
        </Card>
      </div>
    </>
  );
}
