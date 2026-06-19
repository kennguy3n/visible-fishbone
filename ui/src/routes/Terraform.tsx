import { useState } from "react";
import { useIntl } from "react-intl";
import {
  useExportTenantConfig,
  useImportTenantConfig,
  useDetectConfigDrift,
} from "@/api/generated/endpoints/terraform/terraform";
import type { ExportedConfig } from "@/api/generated/model";
import { PageHeader, Card, Badge, ErrorState } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";
import { LanePage } from "./lane-b5";
import { terraformMsg as M } from "./lane-b5.messages";

export function Terraform() {
  return (
    <RequireTenant>{(tenantId) => <TerraformInner tenantId={tenantId} />}</RequireTenant>
  );
}

function TerraformInner({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const exported = useExportTenantConfig(tenantId, { query: { retry: false } });
  const importCfg = useImportTenantConfig();
  const drift = useDetectConfigDrift();
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const exportedJson = exported.data ? JSON.stringify(exported.data, null, 2) : "";

  const download = () => {
    const blob = new Blob([exportedJson], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sng-config-${tenantId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const parseInput = (): ExportedConfig | null => {
    setErr(null);
    try {
      return JSON.parse(text) as ExportedConfig;
    } catch {
      setErr(intl.formatMessage(M.jsonError));
      return null;
    }
  };

  const runImport = () => {
    const cfg = parseInput();
    if (cfg) importCfg.mutate({ tenantId, data: cfg });
  };

  const runDrift = () => {
    const cfg = parseInput();
    if (cfg) drift.mutate({ tenantId, data: cfg });
  };

  // drift.data is typed as DriftReport; use its real field (`entries`) and
  // sub-fields (resource_type/resource_name/drift_type/details).
  const driftItems = drift.data?.entries ?? [];

  return (
    <LanePage>
      <PageHeader
        title={intl.formatMessage(M.title)}
        subtitle={intl.formatMessage(M.subtitle)}
      />

      <div className="grid grid--2">
        <Card
          title={intl.formatMessage(M.exportTitle)}
          actions={
            <button className="btn btn--sm" onClick={download} disabled={!exported.data}>
              {intl.formatMessage(M.download)}
            </button>
          }
        >
          <p className="lane-help">{intl.formatMessage(M.exportHelp)}</p>
          {exported.isError ? (
            <ErrorState error={exported.error} onRetry={() => exported.refetch()} />
          ) : (
            <textarea
              readOnly
              rows={16}
              className="lane-code"
              aria-label={intl.formatMessage(M.exportAria)}
              value={exported.isLoading ? intl.formatMessage(M.loading) : exportedJson}
            />
          )}
        </Card>

        <Card title={intl.formatMessage(M.importTitle)}>
          <p className="lane-help">{intl.formatMessage(M.importHelp)}</p>
          <textarea
            rows={12}
            className="lane-code"
            aria-label={intl.formatMessage(M.importAria)}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={intl.formatMessage(M.importPlaceholder)}
          />
          <div className="lane-actions-row">
            <button
              className="btn btn--primary"
              disabled={!text.trim() || importCfg.isPending}
              onClick={runImport}
            >
              {importCfg.isPending
                ? intl.formatMessage(M.importing)
                : intl.formatMessage(M.runImport)}
            </button>
            <button
              className="btn"
              disabled={!text.trim() || drift.isPending}
              onClick={runDrift}
            >
              {drift.isPending
                ? intl.formatMessage(M.comparing)
                : intl.formatMessage(M.runDrift)}
            </button>
          </div>

          {err && (
            <p className="error-text" role="alert">
              {err}
            </p>
          )}
          {importCfg.isError && (
            <p className="error-text" role="alert">
              {intl.formatMessage(M.importError)}
            </p>
          )}
          {drift.isError && (
            <p className="error-text" role="alert">
              {intl.formatMessage(M.driftError)}
            </p>
          )}
          {importCfg.isSuccess && (
            <p className="lane-success" role="status">
              <span aria-hidden="true">✓</span>
              {intl.formatMessage(M.importSuccess)}
            </p>
          )}
          {drift.isSuccess && (
            <div className="lane-drift" role="status">
              {driftItems.length === 0 ? (
                <Badge tone="ok" dot>
                  {intl.formatMessage(M.driftNone)}
                </Badge>
              ) : (
                <>
                  <div>
                    <Badge tone="warn" dot>
                      {intl.formatMessage(M.driftSome, { count: driftItems.length })}
                    </Badge>
                  </div>
                  {driftItems.map((d, i) => (
                    <div key={i} className="lane-drift__row">
                      {d.drift_type && <Badge tone="neutral">{d.drift_type}</Badge>}
                      <span className="mono">
                        {d.resource_type ?? "resource"}/{d.resource_name ?? ""}
                        {d.details ? ` — ${d.details}` : ""}
                      </span>
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </Card>
      </div>
    </LanePage>
  );
}
