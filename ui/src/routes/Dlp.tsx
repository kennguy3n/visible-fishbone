import { useState } from "react";
import {
  useDlpPolicies,
  useDlpTemplates,
  useApplyDlpTemplate,
  useClassifyText,
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
import { HelpTooltip } from "@/components/HelpTooltip";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime } from "@/lib/format";
import type { DlpPolicy, DlpTemplate } from "@/api/manual/types";

export function Dlp() {
  return <RequireTenant>{(tenantId) => <DlpInner tenantId={tenantId} />}</RequireTenant>;
}

function DlpInner({ tenantId }: { tenantId: string }) {
  const policies = useDlpPolicies(tenantId);
  const templates = useDlpTemplates(tenantId);
  const apply = useApplyDlpTemplate(tenantId);
  const classify = useClassifyText(tenantId);
  const [sample, setSample] = useState("");

  const policyCols: Column<DlpPolicy>[] = [
    { header: "Name", cell: (p) => p.name },
    { header: "Detectors", cell: (p) => p.rules?.length ?? 0 },
    { header: "Action", cell: (p) => <Badge tone={p.action === "block" ? "danger" : "warn"}>{p.action}</Badge> },
    { header: "Enabled", cell: (p) => <StatusBadge status={p.enabled ? "enabled" : "disabled"} /> },
    { header: "Created", cell: (p) => formatDateTime(p.created_at) },
  ];

  return (
    <>
      <PageHeader
        title="Data loss prevention"
        subtitle="DLP policies, classification taxonomy templates and the classifier sandbox."
      />

      <div className="grid grid--2" style={{ marginBottom: 16 }}>
        <Card
          title="Classification taxonomy templates"
          actions={
            <HelpTooltip title="What is a DLP template?" align="right">
              A template is a ready-made set of data classifiers (e.g. credit
              cards, health records). Applying one creates DLP policies tuned
              for that data type so you don't have to build detectors by hand.
            </HelpTooltip>
          }
        >
          <AsyncBoundary
            isLoading={templates.isLoading}
            error={templates.error}
            data={templates.data}
            isEmpty={(d) => (d.items?.length ?? 0) === 0}
            empty={
              <EmptyState
                title="No templates available"
                description="DLP taxonomy templates will appear here when available."
              />
            }
          >
            {(d) => (
              <div className="grid" style={{ gap: 10 }}>
                {(d.items ?? []).map((t: DlpTemplate) => (
                  <div
                    key={t.id}
                    className="card"
                    style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
                  >
                    <div>
                      <div style={{ fontWeight: 700 }}>{t.name}</div>
                      <div className="muted" style={{ fontSize: 12.5 }}>
                        {t.description} · <Badge tone="info">{t.taxonomy}</Badge>
                      </div>
                    </div>
                    <button
                      className="btn btn--sm"
                      disabled={apply.isPending}
                      onClick={() => apply.mutate(t.id)}
                    >
                      Apply
                    </button>
                  </div>
                ))}
              </div>
            )}
          </AsyncBoundary>
        </Card>

        <Card title="Classifier sandbox">
          <p className="muted" style={{ marginTop: 0 }}>
            Run sample text through the tenant DLP detectors.
          </p>
          <textarea
            value={sample}
            onChange={(e) => setSample(e.target.value)}
            placeholder="Paste text containing e.g. a credit-card or SSN pattern…"
          />
          <button
            className="btn btn--primary"
            style={{ marginTop: 10 }}
            disabled={!sample.trim() || classify.isPending}
            onClick={() => classify.mutate(sample)}
          >
            {classify.isPending ? "Classifying…" : "Classify"}
          </button>
          {classify.data && (
            <div style={{ marginTop: 12 }}>
              <Badge tone="info">{classify.data.classification}</Badge>{" "}
              <span className="muted">
                confidence {(classify.data.confidence * 100).toFixed(0)}%
              </span>
              {classify.data.matched_detectors?.length > 0 && (
                <p className="mono" style={{ marginTop: 8 }}>
                  {classify.data.matched_detectors.join(", ")}
                </p>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title="DLP policies">
        <AsyncBoundary
          isLoading={policies.isLoading}
          error={policies.error}
          data={policies.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title="No DLP policies yet"
              description="Apply a classification template above to start protecting sensitive data."
            />
          }
        >
          {(d) => <DataTable columns={policyCols} rows={d.items ?? []} rowKey={(p) => p.id} />}
        </AsyncBoundary>
      </Card>
    </>
  );
}
