import { useEffect, useMemo, useRef, useState } from "react";
import {
  useGetPolicyGraph,
  useUpdatePolicyGraph,
  useCompilePolicyBundles,
} from "@/api/generated/endpoints/policy/policy";
import { useRunSimulation } from "@/api/manual/hooks";
import type { SimulationResponse } from "@/api/manual/types";
import {
  PageHeader,
  Card,
  LoadingState,
  ErrorState,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";

// Each network-security domain is a lens over the one unified tenant policy
// graph (the same `rules` the Policy editor authors). A rule's `domain` field
// places it under exactly one tab; the verb vocabulary is domain-specific so
// the guided form only offers actions that make sense for that plane.
const DOMAINS = [
  { key: "ngfw", label: "NGFW", blurb: "L3–L7 firewall rules, app-id and IPS profiles." },
  { key: "swg", label: "SWG", blurb: "Secure web gateway: URL filtering, TLS inspection, content rules." },
  { key: "dns", label: "DNS", blurb: "DNS-layer security: sinkholing, category blocking, DoH control." },
  { key: "ztna", label: "ZTNA", blurb: "Identity-aware per-app access with device posture gating." },
  { key: "sdwan", label: "SD-WAN", blurb: "Path selection, link SLAs and traffic-steering policy." },
] as const;

type DomainKey = (typeof DOMAINS)[number]["key"];

const DOMAIN_VERBS: Record<DomainKey, string[]> = {
  ngfw: ["allow", "deny", "inspect", "log"],
  swg: ["allow", "deny", "inspect", "decrypt", "log"],
  dns: ["allow", "deny", "inspect", "log"],
  ztna: ["allow", "deny", "inspect"],
  sdwan: ["steer", "allow", "deny", "log"],
};

const VERB_TONE: Record<string, "ok" | "danger" | "warn" | "info" | "neutral"> = {
  allow: "ok",
  steer: "ok",
  deny: "danger",
  inspect: "info",
  decrypt: "warn",
  log: "neutral",
};

interface GraphRule {
  id?: string;
  domain?: string;
  verb?: string;
  description?: string;
  subject_refs?: string[];
  predicate_refs?: string[];
  // Structured subjects/predicates are preserved verbatim through edits via
  // spread; the guided form edits the *_refs arrays, which is the model the
  // Policy simple-editor and the simulator use.
  [k: string]: unknown;
}

interface GraphDoc {
  default_action?: string;
  rules?: GraphRule[];
  [k: string]: unknown;
}

// A locally-managed row: the rule plus a stable key (so React keeps input
// focus across re-orders) and whether it was just added (not yet saved).
interface Row {
  key: string;
  rule: GraphRule;
  isNew: boolean;
}

let rowSeq = 0;
function freshKey(): string {
  rowSeq += 1;
  return `net-${Date.now()}-${rowSeq}`;
}

function refsToText(refs?: string[]): string {
  return (refs ?? []).join(", ");
}
function textToRefs(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Stable signature of the rule *content* (not array identity) plus the default
// action, used both to detect drift from the server and to gate Apply on a
// matching dry-run. Order matters (first-match-wins), so it is preserved.
function signatureOf(rules: GraphRule[], defaultAction: string): string {
  return JSON.stringify({
    d: defaultAction,
    r: rules.map((r) => [
      r.domain ?? null,
      r.verb ?? null,
      r.subject_refs ?? null,
      r.predicate_refs ?? null,
      r.subjects ?? null,
      r.predicates ?? null,
      r.description ?? null,
    ]),
  });
}

export function NetworkPolicies() {
  return (
    <RequireTenant>
      {(tenantId) => <NetworkPoliciesInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function NetworkPoliciesInner({ tenantId }: { tenantId: string }) {
  const graphQuery = useGetPolicyGraph(tenantId, { query: { retry: false } });
  const update = useUpdatePolicyGraph();
  const compile = useCompilePolicyBundles();
  const sim = useRunSimulation(tenantId);
  const toast = useToast();

  const [active, setActive] = useState<DomainKey>("ngfw");
  const [rows, setRows] = useState<Row[]>([]);
  const [defaultAction, setDefaultAction] = useState<string>("deny");
  // The draft signature that was last successfully dry-run. Apply is gated on
  // this matching the current draft, so any edit after a simulation re-locks
  // the apply until the operator re-tests — this is the test-before-rollout
  // guardrail, mirrored from the Access policy promotion flow.
  const [simulatedSig, setSimulatedSig] = useState<string | null>(null);

  const upstream = (graphQuery.data?.graph ?? {}) as GraphDoc;
  const upstreamRules = useMemo(() => upstream.rules ?? [], [upstream.rules]);
  const upstreamDefault = (upstream.default_action as string) ?? "deny";

  // Reset the local draft whenever the upstream rule *content* changes. The
  // global MutationCache invalidates every query after any mutation, so the
  // graph query refetches and hands back new object identities even when the
  // rules are unchanged; keying on content (not identity) means an unrelated
  // mutation no longer wipes an in-progress edit.
  const upstreamSig = useMemo(
    () => signatureOf(upstreamRules, upstreamDefault),
    [upstreamRules, upstreamDefault],
  );
  const resetSim = useRef(sim.reset);
  resetSim.current = sim.reset;
  const seedRef = useRef<{ rules: GraphRule[]; def: string }>({
    rules: upstreamRules,
    def: upstreamDefault,
  });
  seedRef.current = { rules: upstreamRules, def: upstreamDefault };
  useEffect(() => {
    setRows(
      seedRef.current.rules.map((rule) => ({
        key: freshKey(),
        rule,
        isNew: false,
      })),
    );
    setDefaultAction(seedRef.current.def);
    setSimulatedSig(null);
    resetSim.current();
  }, [upstreamSig]);

  const draftRules = rows.map((r) => r.rule);
  const draftSig = signatureOf(draftRules, defaultAction);
  const dirty = draftSig !== upstreamSig;
  const simDataForDraft = sim.data && simulatedSig === draftSig ? sim.data : null;
  const introducesErrors = simDataForDraft
    ? simDataForDraft.next_errors > simDataForDraft.prev_errors
    : false;
  const tested = dirty && simulatedSig === draftSig && !!sim.data;
  const canApply = dirty && tested && !introducesErrors;

  const proposed = (): GraphDoc => ({
    ...upstream,
    default_action: defaultAction,
    rules: draftRules,
  });

  const indicesForDomain = (domain: DomainKey): number[] =>
    rows.reduce<number[]>((acc, r, i) => {
      if ((r.rule.domain ?? "") === domain) acc.push(i);
      return acc;
    }, []);

  const patchRule = (key: string, patch: Partial<GraphRule>) =>
    setRows((prev) =>
      prev.map((r) => (r.key === key ? { ...r, rule: { ...r.rule, ...patch } } : r)),
    );

  const removeRule = (key: string) =>
    setRows((prev) => prev.filter((r) => r.key !== key));

  const addRule = () =>
    setRows((prev) => {
      const next = [...prev];
      // Insert after the last rule already in this domain so the new row lands
      // inside its tab's group; if the domain has none yet, append at the end.
      const lastIdx = next.reduce(
        (acc, r, i) => ((r.rule.domain ?? "") === active ? i : acc),
        -1,
      );
      const row: Row = {
        key: freshKey(),
        isNew: true,
        rule: {
          domain: active,
          verb: DOMAIN_VERBS[active][0],
          subject_refs: [],
          predicate_refs: [],
        },
      };
      next.splice(lastIdx + 1, 0, row);
      return next;
    });

  // Move a rule up/down *within its own domain group*, swapping with the
  // adjacent rule of the same domain so the global first-match-wins order is
  // adjusted predictably without disturbing other domains.
  const move = (key: string, dir: -1 | 1) =>
    setRows((prev) => {
      const idx = prev.findIndex((r) => r.key === key);
      if (idx < 0) return prev;
      const domain = prev[idx].rule.domain ?? "";
      const sameDomain = prev
        .map((r, i) => ({ i, d: r.rule.domain ?? "" }))
        .filter((x) => x.d === domain)
        .map((x) => x.i);
      const pos = sameDomain.indexOf(idx);
      const targetPos = pos + dir;
      if (targetPos < 0 || targetPos >= sameDomain.length) return prev;
      const a = idx;
      const b = sameDomain[targetPos];
      const next = [...prev];
      [next[a], next[b]] = [next[b], next[a]];
      return next;
    });

  const test = () => {
    const sig = draftSig;
    sim.mutate(
      { proposed: proposed() },
      { onSuccess: () => setSimulatedSig(sig) },
    );
  };

  const apply = () => {
    update.mutate(
      { tenantId, data: proposed() as Record<string, unknown> },
      {
        onSuccess: () =>
          toast.success("Network policy updated", "Your changes are live."),
        onError: (e) =>
          toast.error(
            "Could not save policy",
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  const discard = () => {
    setRows(
      upstreamRules.map((rule) => ({ key: freshKey(), rule, isNew: false })),
    );
    setDefaultAction(upstreamDefault);
    setSimulatedSig(null);
    sim.reset();
  };

  if (graphQuery.isLoading) return <LoadingState />;

  // A 404 (no graph compiled yet) is distinct from an empty graph: authoring
  // network rules requires the policy scaffold to exist first, so send the
  // operator to the Policy editor rather than letting them build into the void.
  if (graphQuery.isError) {
    return (
      <>
        <PageHeader
          title="Network policies"
          subtitle="Guided, domain-segmented editor over the unified tenant policy graph."
        />
        <Card title="No policy graph yet">
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title="No policy graph for this tenant"
            description="Initialize the tenant policy in the Policy editor, then return here to manage NGFW / SWG / DNS / ZTNA / SD-WAN rules."
          />
        </Card>
      </>
    );
  }

  const activeMeta = DOMAINS.find((d) => d.key === active)!;
  const activeIdxs = indicesForDomain(active);

  return (
    <>
      <PageHeader
        title="Network policies"
        subtitle="Guided, domain-segmented editor over the unified tenant policy graph."
        actions={
          <button
            className="btn"
            onClick={() =>
              compile.mutate(
                { tenantId },
                {
                  onSuccess: () =>
                    toast.success(
                      "Bundles compiled",
                      "Enforcers will pick up the new policy.",
                    ),
                  onError: (e) =>
                    toast.error(
                      "Compile failed",
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              )
            }
            disabled={compile.isPending}
          >
            {compile.isPending ? "Compiling…" : "Compile bundles"}
          </button>
        }
      />

      <div className="pill-tabs">
        {DOMAINS.map((d) => {
          const count = rows.filter((r) => (r.rule.domain ?? "") === d.key).length;
          return (
            <button
              key={d.key}
              className={active === d.key ? "active" : ""}
              onClick={() => setActive(d.key)}
            >
              {d.label} {count > 0 && <Badge tone="info">{count}</Badge>}
            </button>
          );
        })}
      </div>

      <Card
        title={`${activeMeta.label} rules`}
        actions={
          <HelpTooltip title="Test before you apply" align="right">
            Rules evaluate top to bottom; the first match wins. After any edit
            you must run a dry-run (which replays recent traffic) before the
            change can be applied — a change that would introduce policy errors
            stays blocked.
          </HelpTooltip>
        }
      >
        <p className="muted" style={{ marginTop: 0 }}>
          {activeMeta.blurb}
        </p>

        {activeIdxs.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title={`No ${activeMeta.label} rules`}
            description={`This tenant has no ${activeMeta.label} rules yet. Add one below to get started.`}
          />
        ) : (
          <div className="rule-table">
            {activeIdxs.map((idx, posInDomain) => {
              const row = rows[idx];
              const r = row.rule;
              const verb = (r.verb ?? "").toLowerCase();
              const verbs = DOMAIN_VERBS[active];
              const verbOptions = verbs.includes(verb)
                ? verbs
                : [verb, ...verbs].filter(Boolean);
              return (
                <div
                  key={row.key}
                  className={`net-rule${row.isNew ? " net-rule--new" : ""}`}
                >
                  <div>
                    <label className="net-rule__label">
                      Source <b>{idx + 1}.</b>
                    </label>
                    <input
                      value={refsToText(r.subject_refs)}
                      placeholder="any (identity / group / cidr refs)"
                      onChange={(e) =>
                        patchRule(row.key, {
                          subject_refs: textToRefs(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="net-rule__label">Action</label>
                    <select
                      value={verb}
                      onChange={(e) => patchRule(row.key, { verb: e.target.value })}
                    >
                      {verbOptions.map((v) => (
                        <option key={v} value={v}>
                          {v}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="net-rule__label">Destination</label>
                    <input
                      value={refsToText(r.predicate_refs)}
                      placeholder="any (app / url-category / fqdn refs)"
                      onChange={(e) =>
                        patchRule(row.key, {
                          predicate_refs: textToRefs(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="net-rule__acts">
                    <Badge tone={VERB_TONE[verb] ?? "neutral"}>{r.verb ?? "—"}</Badge>
                    <button
                      className="btn btn--sm"
                      title="Move up"
                      disabled={posInDomain === 0}
                      onClick={() => move(row.key, -1)}
                    >
                      ↑
                    </button>
                    <button
                      className="btn btn--sm"
                      title="Move down"
                      disabled={posInDomain === activeIdxs.length - 1}
                      onClick={() => move(row.key, 1)}
                    >
                      ↓
                    </button>
                    <button
                      className="btn btn--sm btn--danger"
                      title="Remove rule"
                      onClick={() => removeRule(row.key)}
                    >
                      Remove
                    </button>
                  </div>
                  <div className="net-rule__desc">
                    <input
                      value={r.description ?? ""}
                      placeholder="Description (optional) — why this rule exists"
                      onChange={(e) =>
                        patchRule(row.key, { description: e.target.value })
                      }
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div className="rule-actions">
          <button className="btn" onClick={addRule}>
            + Add {activeMeta.label} rule
          </button>
        </div>

        <div className="field-row" style={{ marginTop: 16, alignItems: "center" }}>
          <label className="net-rule__label" style={{ marginBottom: 0 }}>
            Default action (no rule matches)
          </label>
          <select
            value={defaultAction}
            onChange={(e) => setDefaultAction(e.target.value)}
            style={{ maxWidth: 160 }}
          >
            <option value="deny">deny</option>
            <option value="allow">allow</option>
          </select>
        </div>

        {dirty &&
          (canApply ? (
            <div className="net-gate net-gate--ready">
              Dry-run passed — this change is safe to apply.
            </div>
          ) : introducesErrors ? (
            <div className="net-gate net-gate--blocked">
              This change would introduce policy errors — resolve them before
              applying.
            </div>
          ) : (
            <div className="net-gate">
              Run a dry-run to preview the impact before this change can be
              applied.
            </div>
          ))}

        <div className="rule-actions">
          <button className="btn" onClick={test} disabled={sim.isPending || !dirty}>
            {sim.isPending ? "Testing…" : "Test this change"}
          </button>
          <button
            className="btn btn--primary"
            onClick={apply}
            disabled={update.isPending || !canApply}
          >
            {update.isPending ? "Saving…" : "Apply changes"}
          </button>
          {dirty && (
            <button className="btn" onClick={discard} disabled={update.isPending}>
              Discard
            </button>
          )}
        </div>
      </Card>

      {(sim.isPending || sim.data || sim.isError) && (
        <Card title="Impact of this change">
          {sim.isError ? (
            <ErrorState error={sim.error} />
          ) : sim.isPending ? (
            <p className="muted">Replaying recent traffic…</p>
          ) : sim.data ? (
            <ImpactSummary report={sim.data} stale={simulatedSig !== draftSig} />
          ) : null}
        </Card>
      )}
    </>
  );
}

function ImpactSummary({
  report,
  stale,
}: {
  report: SimulationResponse;
  stale: boolean;
}) {
  return (
    <>
      {stale && (
        <p className="net-gate" style={{ marginTop: 0 }}>
          This preview is for an earlier draft — re-test to refresh it.
        </p>
      )}
      <div className="impact-summary">
        {report.changed === 0 ? (
          <>
            Replaying the last {report.total} request{report.total === 1 ? "" : "s"},{" "}
            <b>nothing changes</b> — this edit looks safe to apply.
          </>
        ) : (
          <>
            Replaying the last {report.total} request{report.total === 1 ? "" : "s"},{" "}
            <b>
              {report.changed} verdict{report.changed === 1 ? "" : "s"} change
            </b>
            .
          </>
        )}
        <ul className="impact-list">
          {report.transitions.map((t, i) => (
            <li key={i}>
              {t.prev_verdict} → {t.next_verdict}: <b>{t.count}</b>
            </li>
          ))}
          {report.affected_devices.length > 0 && (
            <li>{report.affected_devices.length} device(s) affected</li>
          )}
          {report.affected_sites.length > 0 && (
            <li>{report.affected_sites.length} site(s) affected</li>
          )}
          {report.next_errors !== report.prev_errors && (
            <li>
              policy errors: {report.prev_errors} → <b>{report.next_errors}</b>
            </li>
          )}
        </ul>
      </div>
    </>
  );
}
