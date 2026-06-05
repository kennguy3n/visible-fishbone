import { useState } from "react";
import {
  useBulkApplyPolicyTemplate,
  useBulkProvisionSites,
  useBulkGenerateClaimTokens,
} from "@/api/generated/endpoints/msps/msps";
import { BulkProvisionSitesBodyTemplate } from "@/api/generated/model";
import { PageHeader, Card, Badge } from "@/components/ui";
import { MspPicker } from "./MspPicker";
import { titleCase } from "@/lib/format";

export function MspBulkOps() {
  const [mspId, setMspId] = useState<string | null>(null);

  return (
    <>
      <PageHeader
        title="MSP bulk operations"
        subtitle="Fan out provisioning and policy actions across an MSP's tenant cohort."
      />
      <Card>
        <MspPicker value={mspId} onChange={setMspId} />
      </Card>
      {mspId && (
        <div className="grid grid--2" style={{ marginTop: 16 }}>
          <BulkProvision mspId={mspId} />
          <BulkClaimTokens mspId={mspId} />
          <BulkPolicyTemplate mspId={mspId} />
        </div>
      )}
    </>
  );
}

function ResultBadge({ ok, error }: { ok: boolean; error: unknown }) {
  if (error)
    return (
      <Badge tone="danger">
        {error instanceof Error ? error.message : "Failed"}
      </Badge>
    );
  if (ok) return <Badge tone="ok">Applied</Badge>;
  return null;
}

function BulkProvision({ mspId }: { mspId: string }) {
  const provision = useBulkProvisionSites();
  const [name, setName] = useState("");
  const [template, setTemplate] = useState<BulkProvisionSitesBodyTemplate>(
    BulkProvisionSitesBodyTemplate.branch,
  );

  return (
    <Card title="Provision sites across cohort">
      <label className="field">
        <span>Site name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Branch-01" />
      </label>
      <label className="field">
        <span>Template</span>
        <select
          value={template}
          onChange={(e) => setTemplate(e.target.value as BulkProvisionSitesBodyTemplate)}
        >
          {Object.values(BulkProvisionSitesBodyTemplate).map((t) => (
            <option key={t} value={t}>
              {titleCase(t)}
            </option>
          ))}
        </select>
      </label>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
        <button
          className="btn btn--primary"
          disabled={!name || provision.isPending}
          onClick={() => provision.mutate({ mspId, data: { name, template } })}
        >
          {provision.isPending ? "Provisioning…" : "Provision"}
        </button>
        <ResultBadge ok={provision.isSuccess} error={provision.error} />
      </div>
    </Card>
  );
}

function BulkClaimTokens({ mspId }: { mspId: string }) {
  const gen = useBulkGenerateClaimTokens();
  const [count, setCount] = useState(10);

  return (
    <Card title="Generate claim tokens">
      <label className="field">
        <span>Tokens per tenant</span>
        <input
          type="number"
          min={1}
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
        />
      </label>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
        <button
          className="btn btn--primary"
          disabled={count < 1 || gen.isPending}
          onClick={() => gen.mutate({ mspId, data: { count } })}
        >
          {gen.isPending ? "Generating…" : "Generate"}
        </button>
        <ResultBadge ok={gen.isSuccess} error={gen.error} />
      </div>
    </Card>
  );
}

function BulkPolicyTemplate({ mspId }: { mspId: string }) {
  const apply = useBulkApplyPolicyTemplate();
  const [text, setText] = useState('{\n  "nodes": [],\n  "edges": []\n}');
  const [err, setErr] = useState<string | null>(null);

  const run = () => {
    setErr(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text);
    } catch {
      setErr("Template is not valid JSON.");
      return;
    }
    apply.mutate({ mspId, data: { template: parsed } });
  };

  return (
    <Card title="Apply policy template to cohort" className="span-2">
      <textarea
        style={{ minHeight: 180, fontFamily: "var(--mono)" }}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
        <button className="btn btn--primary" disabled={apply.isPending} onClick={run}>
          {apply.isPending ? "Applying…" : "Apply to all tenants"}
        </button>
        <ResultBadge ok={apply.isSuccess} error={apply.error} />
      </div>
      {err && <p className="error-text">{err}</p>}
    </Card>
  );
}
