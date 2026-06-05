import { useState } from "react";
import {
  useExportTenantConfig,
  useImportTenantConfig,
  useDetectConfigDrift,
} from "@/api/generated/endpoints/terraform/terraform";
import type { ExportedConfig } from "@/api/generated/model";
import { PageHeader, Card, Badge, ErrorState } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";

export function Terraform() {
  return (
    <RequireTenant>{(tenantId) => <TerraformInner tenantId={tenantId} />}</RequireTenant>
  );
}

function TerraformInner({ tenantId }: { tenantId: string }) {
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
      setErr("Input is not valid JSON.");
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
  // sub-fields (resource_type/resource_name/drift_type/details) rather than
  // casting to an invented shape that never matched the API response.
  const driftItems = drift.data?.entries ?? [];

  return (
    <>
      <PageHeader
        title="Terraform / config as code"
        subtitle="Export the declarative tenant config, re-import it, or detect drift."
      />

      <div className="grid grid--2">
        <Card
          title="Current configuration"
          actions={
            <button className="btn btn--sm" onClick={download} disabled={!exported.data}>
              Download JSON
            </button>
          }
        >
          {exported.isError ? (
            <ErrorState error={exported.error} />
          ) : (
            <textarea
              readOnly
              style={{ minHeight: 320, fontFamily: "var(--mono)" }}
              value={exported.isLoading ? "Loading…" : exportedJson}
            />
          )}
        </Card>

        <Card title="Import / drift detection">
          <p className="muted" style={{ marginTop: 0 }}>
            Paste an exported configuration document.
          </p>
          <textarea
            style={{ minHeight: 220, fontFamily: "var(--mono)" }}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder='{ "version": 1, "tenant_id": "…", "policies": [] }'
          />
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button
              className="btn btn--primary"
              disabled={!text.trim() || importCfg.isPending}
              onClick={runImport}
            >
              {importCfg.isPending ? "Importing…" : "Import"}
            </button>
            <button
              className="btn"
              disabled={!text.trim() || drift.isPending}
              onClick={runDrift}
            >
              {drift.isPending ? "Comparing…" : "Detect drift"}
            </button>
          </div>
          {err && <p className="error-text">{err}</p>}
          {importCfg.isSuccess && (
            <p style={{ color: "var(--ok)" }}>Configuration imported.</p>
          )}
          {drift.isSuccess && (
            <div style={{ marginTop: 12 }}>
              {driftItems.length === 0 ? (
                <Badge tone="ok">No drift detected</Badge>
              ) : (
                <>
                  <Badge tone="warn">{driftItems.length} drifted resource(s)</Badge>
                  <ul className="mono" style={{ fontSize: 12.5 }}>
                    {driftItems.map((d, i) => (
                      <li key={i}>
                        {d.resource_type ?? "resource"}/{d.resource_name ?? ""}
                        {d.drift_type ? ` [${d.drift_type}]` : ""} — {d.details ?? ""}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
