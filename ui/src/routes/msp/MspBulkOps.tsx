import { useMemo, useState } from "react";
import { useIntl, type MessageDescriptor } from "react-intl";
import {
  useBulkApplyPolicyTemplate,
  useBulkProvisionSites,
  useBulkGenerateClaimTokens,
  useListMSPs,
  useListMSPTenants,
} from "@/api/generated/endpoints/msps/msps";
import { BulkProvisionSitesBodyTemplate } from "@/api/generated/model";
import type { MSPBulkResult } from "@/api/generated/model";
import { PageHeader, Card, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { useToast } from "@/components/Toast";
import { shortId, titleCase } from "@/lib/format";
import { MspPicker } from "./MspPicker";
import { M } from "./lane-b6.messages";
import { LanePage, MspScopeBanner, ConfirmDialog, LabelText } from "./_lane";

export function MspBulkOps() {
  const { formatMessage: fm } = useIntl();
  const [mspId, setMspId] = useState<string | null>(null);
  const msps = useListMSPs(undefined);
  const mspName = useMemo(
    () => msps.data?.items?.find((m) => m.id === mspId)?.name ?? "",
    [msps.data?.items, mspId],
  );

  return (
    <LanePage>
      <PageHeader title={fm(M.bulkTitle)} subtitle={fm(M.bulkSubtitle)} />
      <Card>
        <MspPicker value={mspId} onChange={setMspId} />
      </Card>
      {mspId && (
        // Key the cohort section on the MSP id so switching providers remounts
        // it and clears prior results — otherwise one provider's outcomes would
        // linger against another, which is especially misleading for the rich
        // per-tenant onboarding table.
        <CohortSection key={mspId} mspId={mspId} mspName={mspName} />
      )}
    </LanePage>
  );
}

function CohortSection({ mspId, mspName }: { mspId: string; mspName: string }) {
  const { formatMessage: fm } = useIntl();
  const cohort = useListMSPTenants(mspId, undefined);
  const cohortCount = cohort.data?.items?.length ?? 0;

  return (
    <>
      <MspScopeBanner
        name={mspName || "—"}
        aside={
          <Badge tone="neutral">{fm(M.scopeMspCohort, { count: cohortCount })}</Badge>
        }
      />
      <BulkOnboarding mspId={mspId} mspName={mspName} cohortCount={cohortCount} />

      <div className="lb6-subhead">
        <h3>{fm(M.bulkIndividual)}</h3>
        <p className="muted">{fm(M.bulkIndividualSub)}</p>
      </div>
      <div className="grid grid--2">
        <BulkProvision mspId={mspId} />
        <BulkClaimTokens mspId={mspId} />
        <BulkPolicyTemplate
          mspId={mspId}
          mspName={mspName}
          cohortCount={cohortCount}
        />
      </div>
    </>
  );
}

function ResultBadge({ ok, error }: { ok: boolean; error: unknown }) {
  const { formatMessage: fm } = useIntl();
  if (error) return <Badge tone="danger">{fm(M.bulkOpFailed)}</Badge>;
  if (ok) return <Badge tone="ok">{fm(M.bulkDone)}</Badge>;
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

const PHASE_MSG: Record<Phase, MessageDescriptor> = {
  site: M.phaseSite,
  policy: M.phasePolicy,
  tokens: M.phaseTokens,
};

// Fold one phase's result into the per-tenant accumulator, keyed by tenant id.
// `phaseLabel` is the already-localized phase name used in failure detail.
function mergePhase(
  acc: Map<string, CohortRow>,
  phase: Phase,
  result: MSPBulkResult,
  phaseLabel: string,
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
    r.errors.push(o.error ? `${phaseLabel}: ${o.error}` : phaseLabel);
  }
}

function BulkOnboarding({
  mspId,
  mspName,
  cohortCount,
}: {
  mspId: string;
  mspName: string;
  cohortCount: number;
}) {
  const { formatMessage: fm } = useIntl();
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
  const [showConfirm, setShowConfirm] = useState(false);
  const [rows, setRows] = useState<CohortRow[] | null>(null);
  const [ranAt, setRanAt] = useState<string | null>(null);

  const phaseLabel = (p: Phase) => fm(PHASE_MSG[p]);

  // Validate inputs, then open the scope-preview confirm. The actual fan-out
  // only runs once the operator confirms in the dialog.
  const review = () => {
    setFormError(null);
    if (!siteName.trim()) {
      setFormError(fm(M.bulkErrSiteName));
      return;
    }
    if (!Number.isInteger(tokensPerTenant) || tokensPerTenant < 1) {
      setFormError(fm(M.bulkErrTokens));
      return;
    }
    if (withPolicy) {
      try {
        JSON.parse(policyText);
      } catch {
        setFormError(fm(M.bulkErrJson));
        return;
      }
    }
    setShowConfirm(true);
  };

  const run = async () => {
    const policyTemplate: Record<string, unknown> | null = withPolicy
      ? (JSON.parse(policyText) as Record<string, unknown>)
      : null;

    setRunning(true);
    const acc = new Map<string, CohortRow>();
    // Track which phase is in flight so a whole-phase throw can tell the
    // operator exactly where the rollout stopped (later phases never ran).
    let phase: Phase = "site";
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
        phaseLabel("site"),
      );
      if (policyTemplate) {
        phase = "policy";
        mergePhase(
          acc,
          "policy",
          await applyPolicy.mutateAsync({
            mspId,
            data: { template: policyTemplate },
          }),
          phaseLabel("policy"),
        );
      }
      phase = "tokens";
      mergePhase(
        acc,
        "tokens",
        await genTokens.mutateAsync({
          mspId,
          data: { count: tokensPerTenant },
        }),
        phaseLabel("tokens"),
      );

      const result = [...acc.values()].sort((a, b) =>
        a.tenantId.localeCompare(b.tenantId),
      );
      setRows(result);
      setRanAt(new Date().toLocaleString());
      setShowConfirm(false);
      const failed = result.filter((r) => r.errors.length > 0).length;
      if (failed === 0) {
        toast.success(
          fm(M.bulkDoneToast),
          fm(M.bulkDoneToastBody, { count: result.length }),
        );
      } else {
        toast.error(
          fm(M.bulkPartialToast),
          fm(M.bulkPartialToastBody, { failed, total: result.length }),
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
      setShowConfirm(false);
      // Name the phase that failed and exactly which later phases were skipped
      // (not silently completed), matching singular/plural to how many actually
      // remained — the policy phase is absent when it was opted out.
      const reason = e instanceof Error ? e.message : fm(M.bulkRequestFailed);
      const plan: Phase[] = policyTemplate
        ? ["site", "policy", "tokens"]
        : ["site", "tokens"];
      const remaining = plan.slice(plan.indexOf(phase) + 1);
      let detail = reason;
      if (remaining.length === 1) {
        detail = fm(M.bulkPhaseRemainingOne, {
          reason,
          phase: phaseLabel(remaining[0]),
        });
      } else if (remaining.length > 1) {
        detail = fm(M.bulkPhaseRemainingMany, {
          reason,
          phase: phaseLabel(phase),
        });
      }
      toast.error(fm(M.bulkPhaseFailToast, { phase: phaseLabel(phase) }), detail);
    } finally {
      setRunning(false);
    }
  };

  const columns: Column<CohortRow>[] = [
    {
      header: fm(M.bulkColTenant),
      cell: (r) => <span className="mono">{shortId(r.tenantId)}</span>,
    },
    {
      header: fm(M.bulkColSite),
      cell: (r) =>
        r.siteId ? (
          <span className="mono">{shortId(r.siteId)}</span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: fm(M.bulkColPolicy),
      cell: (r) =>
        r.policyVersion != null ? (
          <Badge tone="info">{fm(M.bulkPolicyVer, { v: r.policyVersion })}</Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: fm(M.bulkColTokens),
      cell: (r) =>
        r.tokenCount != null ? r.tokenCount : <span className="muted">—</span>,
    },
    {
      header: fm(M.bulkColStatus),
      cell: (r) =>
        r.errors.length === 0 ? (
          <Badge tone="ok">{fm(M.bulkStatusOk)}</Badge>
        ) : (
          <span title={r.errors.join("; ")}>
            <Badge tone="danger">
              {fm(M.bulkStatusErr, { count: r.errors.length })}
            </Badge>
          </span>
        ),
    },
  ];

  const okCount = rows?.filter((r) => r.errors.length === 0).length ?? 0;
  const disabled =
    !siteName.trim() ||
    !Number.isInteger(tokensPerTenant) ||
    tokensPerTenant < 1 ||
    running;

  return (
    <Card
      title={fm(M.bulkOnboardCard)}
      className="span-2"
      actions={
        <Badge tone="info">
          {fm(M.bulkBadgeSummary, { withPolicy: withPolicy ? "true" : "false" })}
        </Badge>
      }
    >
      <p className="muted" style={{ marginTop: 0 }}>
        {fm(M.bulkOnboardIntro)}
      </p>

      <div className="grid grid--2">
        <label className="field">
          <LabelText>{fm(M.bulkSiteName)}</LabelText>
          <input
            value={siteName}
            onChange={(e) => setSiteName(e.target.value)}
            placeholder="Branch-01"
          />
        </label>
        <label className="field">
          <LabelText>{fm(M.bulkSiteTemplate)}</LabelText>
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
          <LabelText>{fm(M.bulkTokens)}</LabelText>
          <input
            type="number"
            min={1}
            step={1}
            value={tokensPerTenant}
            onChange={(e) => setTokensPerTenant(Number(e.target.value))}
          />
        </label>
        <div className="field">
          <LabelText>{fm(M.bulkBaselinePolicy)}</LabelText>
          <label
            style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 6 }}
          >
            <input
              type="checkbox"
              checked={withPolicy}
              onChange={(e) => setWithPolicy(e.target.checked)}
            />
            <span style={{ fontWeight: 400 }}>{fm(M.bulkApplyPolicyLabel)}</span>
          </label>
        </div>
      </div>

      {withPolicy && (
        <label className="field">
          <LabelText>{fm(M.bulkPolicyJson)}</LabelText>
          <textarea
            style={{ minHeight: 140, fontFamily: "var(--mono)" }}
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
          />
        </label>
      )}

      <div className="lb6-actions">
        <button className="btn btn--primary" disabled={disabled} onClick={review}>
          {running ? fm(M.bulkRunning) : fm(M.bulkRun)}
        </button>
        <span className="muted" style={{ fontSize: 12.5 }}>
          {fm(M.bulkTokensNote)}
        </span>
      </div>

      {formError && (
        <p className="error-text" role="alert">
          {formError}
        </p>
      )}

      {rows && (
        <div style={{ marginTop: 16 }}>
          <div className="lb6-summary">
            <Badge tone="ok">{fm(M.bulkSucceeded, { count: okCount })}</Badge>
            {rows.length - okCount > 0 && (
              <Badge tone="danger">
                {fm(M.bulkFailed, { count: rows.length - okCount })}
              </Badge>
            )}
            {ranAt && (
              <span className="muted" style={{ fontSize: 12 }}>
                {fm(M.bulkRanAt, { when: ranAt })}
              </span>
            )}
          </div>
          {rows.length === 0 ? (
            <p className="muted">{fm(M.bulkConfirmNoTenants)}</p>
          ) : (
            <DataTable rows={rows} columns={columns} rowKey={(r) => r.tenantId} />
          )}
        </div>
      )}

      {showConfirm && (
        <ConfirmDialog
          title={fm(M.bulkConfirmTitle, { count: cohortCount })}
          confirmLabel={fm(M.bulkConfirmCta)}
          busy={running}
          confirmDisabled={cohortCount === 0}
          onConfirm={() => void run()}
          onClose={() => (running ? undefined : setShowConfirm(false))}
        >
          {cohortCount === 0 ? (
            <p>{fm(M.bulkConfirmNoTenants)}</p>
          ) : (
            <>
              <p>{fm(M.bulkConfirmIntro, { msp: mspName || "—" })}</p>
              <ul className="lb6-checklist">
                <li>
                  {fm(M.bulkConfirmSite, {
                    site: siteName.trim(),
                    template: titleCase(siteTemplate),
                  })}
                </li>
                {withPolicy && <li>{fm(M.bulkConfirmPolicy)}</li>}
                <li>{fm(M.bulkConfirmTokens, { count: tokensPerTenant })}</li>
              </ul>
            </>
          )}
        </ConfirmDialog>
      )}
    </Card>
  );
}

function BulkProvision({ mspId }: { mspId: string }) {
  const { formatMessage: fm } = useIntl();
  const provision = useBulkProvisionSites();
  const [name, setName] = useState("");
  const [template, setTemplate] = useState<BulkProvisionSitesBodyTemplate>(
    BulkProvisionSitesBodyTemplate.branch,
  );

  return (
    <Card title={fm(M.bulkProvCard)}>
      <label className="field">
        <LabelText>{fm(M.bulkSiteName)}</LabelText>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Branch-01"
        />
      </label>
      <label className="field">
        <LabelText>{fm(M.bulkSiteTemplate)}</LabelText>
        <select
          value={template}
          onChange={(e) =>
            setTemplate(e.target.value as BulkProvisionSitesBodyTemplate)
          }
        >
          {Object.values(BulkProvisionSitesBodyTemplate).map((t) => (
            <option key={t} value={t}>
              {titleCase(t)}
            </option>
          ))}
        </select>
      </label>
      <div className="lb6-actions">
        <button
          className="btn btn--primary"
          disabled={!name.trim() || provision.isPending}
          onClick={() =>
            provision.mutate({ mspId, data: { name: name.trim(), template } })
          }
        >
          {provision.isPending ? fm(M.bulkProvisioning) : fm(M.bulkProvision)}
        </button>
        <ResultBadge ok={provision.isSuccess} error={provision.error} />
      </div>
    </Card>
  );
}

function BulkClaimTokens({ mspId }: { mspId: string }) {
  const { formatMessage: fm } = useIntl();
  const gen = useBulkGenerateClaimTokens();
  const [count, setCount] = useState(10);

  return (
    <Card title={fm(M.bulkTokCard)}>
      <label className="field">
        <LabelText>{fm(M.bulkTokens)}</LabelText>
        <input
          type="number"
          min={1}
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
        />
      </label>
      <div className="lb6-actions">
        <button
          className="btn btn--primary"
          disabled={count < 1 || gen.isPending}
          onClick={() => gen.mutate({ mspId, data: { count } })}
        >
          {gen.isPending ? fm(M.bulkGenerating) : fm(M.bulkGenerate)}
        </button>
        <ResultBadge ok={gen.isSuccess} error={gen.error} />
      </div>
      <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
        {fm(M.bulkTokensNote)}
      </p>
    </Card>
  );
}

function BulkPolicyTemplate({
  mspId,
  mspName,
  cohortCount,
}: {
  mspId: string;
  mspName: string;
  cohortCount: number;
}) {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const apply = useBulkApplyPolicyTemplate();
  const [text, setText] = useState('{\n  "nodes": [],\n  "edges": []\n}');
  const [err, setErr] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const review = () => {
    setErr(null);
    try {
      JSON.parse(text);
    } catch {
      setErr(fm(M.bulkErrJson));
      return;
    }
    setShowConfirm(true);
  };

  const run = () => {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    apply.mutate(
      { mspId, data: { template: parsed } },
      {
        onSuccess: () => {
          setShowConfirm(false);
          toast.success(fm(M.bulkDone));
        },
        onError: () => toast.error(fm(M.tplApplyError)),
      },
    );
  };

  return (
    <Card title={fm(M.bulkPolCard)} className="span-2">
      <label className="field">
        <LabelText>{fm(M.bulkPolicyJson)}</LabelText>
        <textarea
          style={{ minHeight: 180, fontFamily: "var(--mono)" }}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      <div className="lb6-actions">
        <button
          className="btn btn--primary"
          disabled={apply.isPending}
          onClick={review}
        >
          {apply.isPending ? fm(M.bulkApplying) : fm(M.bulkApply)}
        </button>
        <ResultBadge ok={apply.isSuccess} error={apply.error} />
      </div>
      {err && (
        <p className="error-text" role="alert">
          {err}
        </p>
      )}

      {showConfirm && (
        <ConfirmDialog
          title={fm(M.bulkPolicyConfirmTitle, { count: cohortCount })}
          confirmLabel={fm(M.bulkApply)}
          busy={apply.isPending}
          onConfirm={run}
          onClose={() => (apply.isPending ? undefined : setShowConfirm(false))}
        >
          <p>{fm(M.bulkPolicyConfirmBody, { msp: mspName || "—" })}</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}
