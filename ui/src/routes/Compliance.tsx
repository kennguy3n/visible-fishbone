import { useState } from "react";
import {
  useComplianceReports,
  useGenerateComplianceReport,
} from "@/api/manual/hooks";
import { sngRequest } from "@/api/http-client";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime } from "@/lib/format";
import type { ComplianceReport, GenerateReportRequest } from "@/api/manual/types";

const FRAMEWORKS = ["soc2", "iso27001", "hipaa", "pci_dss", "gdpr"];
const SCOPES: (keyof GenerateReportRequest)[] = [
  "dlp",
  "browser",
  "casb",
  "policy",
  "access_control",
];

export function Compliance() {
  return (
    <RequireTenant>{(tenantId) => <ComplianceInner tenantId={tenantId} />}</RequireTenant>
  );
}

function ComplianceInner({ tenantId }: { tenantId: string }) {
  const reports = useComplianceReports(tenantId);
  const [showGen, setShowGen] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const download = async (report: ComplianceReport) => {
    setDownloading(report.id);
    try {
      const blob = await sngRequest<Blob>({
        method: "GET",
        url: `/tenants/${tenantId}/compliance/reports/${report.id}/evidence`,
        responseType: "blob",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence-${report.framework}-${report.id}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <>
      <PageHeader
        title="Compliance"
        subtitle="Framework posture reports with signed evidence packs."
        actions={
          <button className="btn btn--primary" onClick={() => setShowGen(true)}>
            Generate report
          </button>
        }
      />
      <AsyncBoundary
        isLoading={reports.isLoading}
        error={reports.error}
        data={reports.data}
        isEmpty={(d) => (d.items?.length ?? 0) === 0}
        empty={
          <Card>
            <EmptyState
              illustration={<EmptyIllustration kind="policy" />}
              title="No compliance reports yet"
              description="Generate a report to evaluate this tenant against a compliance framework."
            />
          </Card>
        }
      >
        {(d) => (
          <div className="grid grid--2">
            {(d.items ?? []).map((r) => {
              const pct = r.max_score > 0 ? (r.score / r.max_score) * 100 : 0;
              return (
                <Card key={r.id} title={r.framework.toUpperCase()}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                    <span style={{ fontSize: 30, fontWeight: 800 }}>
                      {pct.toFixed(0)}%
                    </span>
                    <Badge tone={pct >= 80 ? "ok" : pct >= 50 ? "warn" : "danger"}>
                      {r.score}/{r.max_score}
                    </Badge>
                  </div>
                  <p className="muted" style={{ fontSize: 12 }}>
                    Generated {formatDateTime(r.generated_at)} · {r.controls?.length ?? 0}{" "}
                    controls
                  </p>
                  <button
                    className="btn btn--sm"
                    disabled={downloading === r.id}
                    onClick={() => download(r)}
                  >
                    {downloading === r.id ? "Preparing…" : "Download evidence pack"}
                  </button>
                </Card>
              );
            })}
          </div>
        )}
      </AsyncBoundary>
      {showGen && (
        <GenerateModal tenantId={tenantId} onClose={() => setShowGen(false)} />
      )}
    </>
  );
}

function GenerateModal({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const gen = useGenerateComplianceReport(tenantId);
  const [framework, setFramework] = useState(FRAMEWORKS[0]);
  const [scopes, setScopes] = useState<Record<string, boolean>>({
    dlp: true,
    browser: true,
    casb: true,
    policy: true,
    access_control: true,
  });

  const submit = () => {
    const body: GenerateReportRequest = { framework, ...scopes };
    gen.mutate(body, { onSuccess: onClose });
  };

  return (
    <Modal
      title="Generate compliance report"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn--primary" disabled={gen.isPending} onClick={submit}>
            {gen.isPending ? "Generating…" : "Generate"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Framework</span>
        <select value={framework} onChange={(e) => setFramework(e.target.value)}>
          {FRAMEWORKS.map((f) => (
            <option key={f} value={f}>
              {f.toUpperCase()}
            </option>
          ))}
        </select>
      </label>
      <span style={{ color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>
        Evidence scopes
      </span>
      <div style={{ marginTop: 8 }}>
        {SCOPES.map((s) => (
          <label key={s} style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
            <input
              type="checkbox"
              style={{ width: 16 }}
              checked={!!scopes[s]}
              onChange={(e) => setScopes((prev) => ({ ...prev, [s]: e.target.checked }))}
            />
            {s.replace(/_/g, " ")}
          </label>
        ))}
      </div>
    </Modal>
  );
}
