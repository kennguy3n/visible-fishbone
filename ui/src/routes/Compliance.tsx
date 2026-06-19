import { useId, useState } from "react";
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
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import { formatDateTime } from "@/lib/format";
import type { ComplianceReport, GenerateReportRequest } from "@/api/manual/types";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { isForbidden, PermissionDenied } from "./lane-b4-ui";
import type { LaneKey } from "./lane-b4-messages";

const FRAMEWORKS: { id: string; labelKey: LaneKey }[] = [
  { id: "soc2", labelKey: "compliance.framework.soc2" },
  { id: "iso27001", labelKey: "compliance.framework.iso27001" },
  { id: "hipaa", labelKey: "compliance.framework.hipaa" },
  { id: "pci_dss", labelKey: "compliance.framework.pci_dss" },
  { id: "gdpr", labelKey: "compliance.framework.gdpr" },
];
const FRAMEWORK_LABEL = new Map<string, LaneKey>(
  FRAMEWORKS.map((f) => [f.id, f.labelKey]),
);

const SCOPES: { id: keyof GenerateReportRequest; labelKey: LaneKey }[] = [
  { id: "dlp", labelKey: "compliance.scope.dlp" },
  { id: "browser", labelKey: "compliance.scope.browser" },
  { id: "casb", labelKey: "compliance.scope.casb" },
  { id: "policy", labelKey: "compliance.scope.policy" },
  { id: "access_control", labelKey: "compliance.scope.access_control" },
];

export function Compliance() {
  return (
    <LaneB4Screen>
      <RequireTenant>{(tenantId) => <ComplianceInner tenantId={tenantId} />}</RequireTenant>
    </LaneB4Screen>
  );
}

function ComplianceInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const toast = useToast();
  const reports = useComplianceReports(tenantId);
  const [showGen, setShowGen] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  if (isForbidden(reports.error)) return <PermissionDenied />;

  const frameworkLabel = (id: string) =>
    FRAMEWORK_LABEL.has(id) ? t(FRAMEWORK_LABEL.get(id)!) : id.toUpperCase();

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
      toast.success(t("compliance.download.ok"));
    } catch {
      toast.error(t("compliance.download.failTitle"), t("compliance.download.failBody"));
    } finally {
      setDownloading(null);
    }
  };

  return (
    <>
      <PageHeader
        title={t("compliance.title")}
        subtitle={t("compliance.subtitle")}
        actions={
          <>
            <HelpTooltip title={t("compliance.help.title")}>
              {t("compliance.help.body")}
            </HelpTooltip>
            <button className="btn btn--primary" onClick={() => setShowGen(true)}>
              {t("compliance.generate")}
            </button>
          </>
        }
      />
      <AsyncBoundary
        isLoading={reports.isLoading}
        error={reports.error}
        data={reports.data}
        onRetry={() => reports.refetch()}
        isEmpty={(d) => (d.items?.length ?? 0) === 0}
        empty={
          <Card>
            <EmptyState
              illustration={<EmptyIllustration kind="policy" />}
              title={t("compliance.empty.title")}
              description={t("compliance.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setShowGen(true)}>
                  {t("compliance.empty.action")}
                </button>
              }
            />
          </Card>
        }
      >
        {(d) => (
          <div className="grid grid--2">
            {(d.items ?? []).map((r) => {
              const pct = r.max_score > 0 ? (r.score / r.max_score) * 100 : 0;
              return (
                <Card key={r.id} title={frameworkLabel(r.framework)}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                    <span style={{ fontSize: 30, fontWeight: 800 }}>
                      {t("compliance.card.percent", { pct: pct.toFixed(0) })}
                    </span>
                    <Badge tone={pct >= 80 ? "ok" : pct >= 50 ? "warn" : "danger"}>
                      {t("compliance.card.score", { score: r.score, max: r.max_score })}
                    </Badge>
                  </div>
                  <p className="field-help" style={{ margin: "6px 0 12px" }}>
                    {t("compliance.card.generated", {
                      when: formatDateTime(r.generated_at),
                      controls: r.controls?.length ?? 0,
                    })}
                  </p>
                  <button
                    className="btn btn--sm"
                    disabled={downloading === r.id}
                    onClick={() => download(r)}
                  >
                    {downloading === r.id
                      ? t("compliance.download.preparing")
                      : t("compliance.download.cta")}
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
  const t = useT();
  const toast = useToast();
  const gen = useGenerateComplianceReport(tenantId);
  const formId = useId();
  const frameworkId = useId();
  const scopesErrId = useId();
  const [framework, setFramework] = useState(FRAMEWORKS[0].id);
  const [scopes, setScopes] = useState<Record<string, boolean>>({
    dlp: true,
    browser: true,
    casb: true,
    policy: true,
    access_control: true,
  });
  const [submitted, setSubmitted] = useState(false);

  const selectedCount = SCOPES.filter((s) => scopes[s.id]).length;
  const scopesInvalid = submitted && selectedCount === 0;

  const submit = () => {
    setSubmitted(true);
    if (selectedCount === 0) return;
    const body: GenerateReportRequest = { framework, ...scopes };
    gen.mutate(body, {
      onSuccess: () => {
        toast.success(t("compliance.generate.ok"));
        onClose();
      },
    });
  };

  return (
    <Modal
      title={t("compliance.modal.title")}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {t("b4.action.cancel")}
          </button>
          <button
            className="btn btn--primary"
            type="submit"
            form={formId}
            disabled={gen.isPending}
          >
            {gen.isPending ? t("compliance.generating") : t("compliance.generate.cta")}
          </button>
        </>
      }
    >
      <form
        id={formId}
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label className="field" htmlFor={frameworkId}>
          <span>{t("compliance.field.framework")}</span>
          <select
            id={frameworkId}
            autoFocus
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
          >
            {FRAMEWORKS.map((f) => (
              <option key={f.id} value={f.id}>
                {t(f.labelKey)}
              </option>
            ))}
          </select>
        </label>
        <fieldset
          className="perm-grid"
          aria-invalid={scopesInvalid}
          aria-describedby={scopesInvalid ? scopesErrId : undefined}
        >
          <legend>{t("compliance.field.scopes")}</legend>
          {SCOPES.map((s) => (
            <label key={s.id} className="perm-option">
              <input
                type="checkbox"
                checked={!!scopes[s.id]}
                onChange={(e) =>
                  setScopes((prev) => ({ ...prev, [s.id]: e.target.checked }))
                }
              />
              <span className="perm-option__label">
                <span>{t(s.labelKey)}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {scopesInvalid && (
          <span id={scopesErrId} className="field-help field-help--error" role="alert">
            {t("compliance.error.scopes")}
          </span>
        )}
        {gen.isError && (
          <p className="error-text" role="alert">
            {t("compliance.error.generate")}
          </p>
        )}
      </form>
    </Modal>
  );
}
