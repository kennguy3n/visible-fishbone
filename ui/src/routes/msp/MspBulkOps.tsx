import { useState } from "react";
import {
  useBulkApplyPolicyTemplate,
  useBulkProvisionSites,
  useBulkGenerateClaimTokens,
} from "@/api/generated/endpoints/msps/msps";
import { BulkProvisionSitesBodyTemplate } from "@/api/generated/model";
import type { MSPBulkResult } from "@/api/generated/model";
import { PageHeader, Card, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { useToast } from "@/components/Toast";
import { MspPicker } from "./MspPicker";
import { shortId, titleCase } from "@/lib/format";

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
        // Key every operation on the MSP id so switching cohorts remounts them
        // and clears prior results — otherwise one MSP's outcomes would linger
        // on screen against another, which is especially misleading for the
        // rich per-tenant onboarding table.
        <>
          <BulkOnboarding key={mspId} mspId={mspId} />
          <h3 style={{ margin: "24px 0 8px", fontSize: 14 }}>
            Individual operations
          </h3>
          <div className="grid grid--2">
            <BulkProvision key={`${mspId}-provision`} mspId={mspId} />
            <BulkClaimTokens key={`${mspId}-tokens`} mspId={mspId} />
            <BulkPolicyTemplate key={`${mspId}-policy`} mspId={mspId} />
          </div>
        </>
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

// --- Unified bulk onboarding ----------------------------------------------
//
// A single guided flow that onboards an MSP's whole tenant cohort the same way
// the per-tenant wizard does, but fanned out: provision a site, optionally
// apply a baseline policy, and issue enrolment tokens — then report a single
// per-tenant outcome. It composes the three existing bulk endpoints rather
// than adding any new backend; each phase is independent server-side, so a
// failure in one phase for one tenant does not abort the others.

interface CohortRow {
  tenantId: string;
  siteId?: string;
  policyVersion?: number;
  tokenCount?: number;
  errors: string[];
}

type Phase = "site" | "policy" | "tokens";

const PHASE_LABEL: Record<Phase, string> = {
  site: "site provisioning",
  policy: "policy template",
  tokens: "claim tokens",
};

// Fold one phase's result into the per-tenant accumulator, keyed by tenant id.
function mergePhase(
  acc: Map<string, CohortRow>,
  phase: Phase,
  result: MSPBulkResult,
) {
  const row = (tenantId: string): CohortRow => {
    let r = acc.get(tenantId);
    if (!r) {
      r = { tenantId, errors: [] };
      acc.set(tenantId, r);
    }
    return r;
  };
  for (const o of result.successes) {
    const r = row(o.tenant_id);
    if (phase === "site" && o.site_id) r.siteId = o.site_id;
    if (phase === "policy" && o.policy_version != null)
      r.policyVersion = o.policy_version;
    // Record only the COUNT of issued tokens — the plaintext values are
    // captured once in the response and intentionally never surfaced in the
    // cohort summary or persisted client-side.
    if (phase === "tokens" && o.claim_tokens)
      r.tokenCount = o.claim_tokens.length;
  }
  for (const o of result.failures) {
    const r = row(o.tenant_id);
    r.errors.push(`${PHASE_LABEL[phase]}: ${o.error ?? "failed"}`);
  }
}

function BulkOnboarding({ mspId }: { mspId: string }) {
  const provision = useBulkProvisionSites();
  const applyPolicy = useBulkApplyPolicyTemplate();
  const genTokens = useBulkGenerateClaimTokens();
  const toast = useToast();

  const [siteName, setSiteName] = useState("");
  const [siteTemplate, setSiteTemplate] = useState<BulkProvisionSitesBodyTemplate>(
    BulkProvisionSitesBodyTemplate.branch,
  );
  const [withPolicy, setWithPolicy] = useState(false);
  const [policyText, setPolicyText] = useState(
    '{\n  "nodes": [],\n  "edges": []\n}',
  );
  const [tokensPerTenant, setTokensPerTenant] = useState(5);

  const [running, setRunning] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [rows, setRows] = useState<CohortRow[] | null>(null);
  const [ranAt, setRanAt] = useState<string | null>(null);

  const run = async () => {
    setFormError(null);

    if (!siteName.trim()) {
      setFormError("Site name is required.");
      return;
    }
    if (!Number.isFinite(tokensPerTenant) || tokensPerTenant < 1) {
      setFormError("Tokens per tenant must be at least 1.");
      return;
    }
    let policyTemplate: Record<string, unknown> | null = null;
    if (withPolicy) {
      try {
        policyTemplate = JSON.parse(policyText) as Record<string, unknown>;
      } catch {
        setFormError("Policy template is not valid JSON.");
        return;
      }
    }

    setRunning(true);
    const acc = new Map<string, CohortRow>();
    try {
      // Provision the site first so every tenant has somewhere to route, then
      // layer policy and enrolment on top. Phases run sequentially so the
      // summary reflects the real, ordered rollout.
      mergePhase(
        acc,
        "site",
        await provision.mutateAsync({
          mspId,
          data: { name: siteName.trim(), template: siteTemplate },
        }),
      );
      if (policyTemplate) {
        mergePhase(
          acc,
          "policy",
          await applyPolicy.mutateAsync({
            mspId,
            data: { template: policyTemplate },
          }),
        );
      }
      mergePhase(
        acc,
        "tokens",
        await genTokens.mutateAsync({
          mspId,
          data: { count: tokensPerTenant },
        }),
      );

      const result = [...acc.values()].sort((a, b) =>
        a.tenantId.localeCompare(b.tenantId),
      );
      setRows(result);
      setRanAt(new Date().toLocaleString());
      const failed = result.filter((r) => r.errors.length > 0).length;
      if (failed === 0) {
        toast.success(
          "Cohort onboarded",
          `${result.length} tenant${result.length === 1 ? "" : "s"} provisioned.`,
        );
      } else {
        toast.error(
          "Onboarding completed with errors",
          `${failed} of ${result.length} tenant${result.length === 1 ? "" : "s"} had a failure.`,
        );
      }
    } catch (e) {
      // A whole-phase failure (e.g. authorization) — surface it but still show
      // whatever partial per-tenant outcomes we managed to collect.
      const partial = [...acc.values()].sort((a, b) =>
        a.tenantId.localeCompare(b.tenantId),
      );
      if (partial.length > 0) {
        setRows(partial);
        setRanAt(new Date().toLocaleString());
      }
      toast.error(
        "Bulk onboarding failed",
        e instanceof Error ? e.message : undefined,
      );
    } finally {
      setRunning(false);
    }
  };

  const columns: Column<CohortRow>[] = [
    {
      header: "Tenant",
      cell: (r) => <span className="mono">{shortId(r.tenantId)}</span>,
    },
    {
      header: "Site",
      cell: (r) =>
        r.siteId ? (
          <span className="mono">{shortId(r.siteId)}</span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: "Policy",
      cell: (r) =>
        r.policyVersion != null ? (
          <Badge tone="info">v{r.policyVersion}</Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: "Tokens",
      cell: (r) =>
        r.tokenCount != null ? r.tokenCount : <span className="muted">—</span>,
    },
    {
      header: "Status",
      cell: (r) =>
        r.errors.length === 0 ? (
          <Badge tone="ok">OK</Badge>
        ) : (
          <span title={r.errors.join("; ")}>
            <Badge tone="danger">
              {r.errors.length} error{r.errors.length === 1 ? "" : "s"}
            </Badge>
          </span>
        ),
    },
  ];

  const okCount = rows?.filter((r) => r.errors.length === 0).length ?? 0;

  return (
    <Card
      title="Bulk onboarding (full cohort)"
      className="span-2"
      actions={
        <Badge tone="info">
          provision · {withPolicy ? "policy · " : ""}enrol
        </Badge>
      }
    >
      <p className="muted" style={{ marginTop: 0 }}>
        Run the full onboarding sequence across every tenant this MSP owns:
        provision a site, optionally apply a baseline policy template, and issue
        enrolment tokens — in one pass.
      </p>

      <div className="grid grid--2">
        <label className="field">
          <span>Site name (per tenant)</span>
          <input
            value={siteName}
            onChange={(e) => setSiteName(e.target.value)}
            placeholder="Branch-01"
          />
        </label>
        <label className="field">
          <span>Site template</span>
          <select
            value={siteTemplate}
            onChange={(e) =>
              setSiteTemplate(e.target.value as BulkProvisionSitesBodyTemplate)
            }
          >
            {Object.values(BulkProvisionSitesBodyTemplate).map((t) => (
              <option key={t} value={t}>
                {titleCase(t)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Claim tokens per tenant</span>
          <input
            type="number"
            min={1}
            value={tokensPerTenant}
            onChange={(e) => setTokensPerTenant(Number(e.target.value))}
          />
        </label>
        <label className="field">
          <span>Baseline policy</span>
          <label
            style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 6 }}
          >
            <input
              type="checkbox"
              checked={withPolicy}
              onChange={(e) => setWithPolicy(e.target.checked)}
            />
            <span style={{ fontWeight: 400 }}>
              Apply a policy template to every tenant
            </span>
          </label>
        </label>
      </div>

      {withPolicy && (
        <label className="field">
          <span>Policy template (JSON — same shape as the policy graph)</span>
          <textarea
            style={{ minHeight: 140, fontFamily: "var(--mono)" }}
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
          />
        </label>
      )}

      <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
        <button
          className="btn btn--primary"
          disabled={!siteName.trim() || running}
          onClick={run}
        >
          {running ? "Onboarding cohort…" : "Onboard entire cohort"}
        </button>
        <span className="muted" style={{ fontSize: 12.5 }}>
          Tokens are issued once and never shown here — distribute them from the
          per-tenant device pages.
        </span>
      </div>

      {formError && <p className="error-text">{formError}</p>}

      {rows && (
        <div style={{ marginTop: 16 }}>
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              marginBottom: 8,
            }}
          >
            <Badge tone="ok">{okCount} succeeded</Badge>
            {rows.length - okCount > 0 && (
              <Badge tone="danger">{rows.length - okCount} failed</Badge>
            )}
            {ranAt && (
              <span className="muted" style={{ fontSize: 12 }}>
                Ran {ranAt}
              </span>
            )}
          </div>
          {rows.length === 0 ? (
            <p className="muted">This MSP has no tenants to onboard.</p>
          ) : (
            <DataTable
              rows={rows}
              columns={columns}
              rowKey={(r) => r.tenantId}
            />
          )}
        </div>
      )}
    </Card>
  );
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
