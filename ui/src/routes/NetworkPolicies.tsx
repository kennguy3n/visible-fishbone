import { useEffect, useMemo, useRef, useState } from "react";
import { FormattedMessage } from "react-intl";
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
import { LaneB2Intl, useT, richBold, type LaneB2Key } from "./lane-b2/i18n";

// Each network-security domain is a lens over the one unified tenant policy
// graph (the same `rules` the Policy editor authors). A rule's `domain` field
// places it under exactly one tab; the verb vocabulary is domain-specific so
// the guided form only offers actions that make sense for that plane.
const DOMAINS = ["ngfw", "swg", "dns", "ztna", "sdwan"] as const;

type DomainKey = (typeof DOMAINS)[number];

const DOMAIN_LABEL: Record<DomainKey, LaneB2Key> = {
  ngfw: "net.domain.ngfw",
  swg: "net.domain.swg",
  dns: "net.domain.dns",
  ztna: "net.domain.ztna",
  sdwan: "net.domain.sdwan",
};

const DOMAIN_BLURB: Record<DomainKey, LaneB2Key> = {
  ngfw: "net.domain.ngfw.blurb",
  swg: "net.domain.swg.blurb",
  dns: "net.domain.dns.blurb",
  ztna: "net.domain.ztna.blurb",
  sdwan: "net.domain.sdwan.blurb",
};

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

const VERB_KEYS: Record<string, LaneB2Key> = {
  allow: "verb.allow",
  deny: "verb.deny",
  inspect: "verb.inspect",
  decrypt: "verb.decrypt",
  log: "verb.log",
  steer: "verb.steer",
  isolate: "verb.isolate",
  block: "verb.block",
  bypass: "verb.bypass",
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
//
// srcText/dstText are the *raw* contents of the Source/Destination inputs and
// are the source of truth while editing. Parsing to ref arrays only happens at
// commit time (see materialize) so an in-progress comma (e.g. "team-a,") is not
// stripped on every keystroke, which would make multi-ref entry impossible.
interface Row {
  key: string;
  rule: GraphRule;
  srcText: string;
  dstText: string;
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

// Resolve a row's editing state into the rule that gets simulated/saved: the
// structured subjects/predicates are preserved verbatim (via spread) while the
// guided *_refs arrays are derived from the raw input text at commit time.
function materialize(row: Row): GraphRule {
  return {
    ...row.rule,
    subject_refs: textToRefs(row.srcText),
    predicate_refs: textToRefs(row.dstText),
  };
}

// Stable signature of the rule *content* (not array identity) plus the default
// action, used both to detect drift from the server and to gate Apply on a
// matching dry-run. Order matters (first-match-wins), so it is preserved.
//
// Empty/absent ref arrays are canonicalized to null so that a server rule that
// omits `subject_refs` (Go `omitempty` → undefined) and the same rule after a
// materialize round-trip (undefined → "" → []) hash identically — otherwise the
// editor would report a phantom dirty state on load with no user edit.
function signatureOf(rules: GraphRule[], defaultAction: string): string {
  return JSON.stringify({
    d: defaultAction,
    r: rules.map((r) => [
      r.domain ?? null,
      r.verb ?? null,
      r.subject_refs?.length ? r.subject_refs : null,
      r.predicate_refs?.length ? r.predicate_refs : null,
      r.subjects ?? null,
      r.predicates ?? null,
      r.description ?? null,
    ]),
  });
}

export function NetworkPolicies() {
  return (
    <LaneB2Intl>
      <RequireTenant>
        {(tenantId) => <NetworkPoliciesInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB2Intl>
  );
}

function NetworkPoliciesInner({ tenantId }: { tenantId: string }) {
  const t = useT();
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
        srcText: refsToText(rule.subject_refs),
        dstText: refsToText(rule.predicate_refs),
        isNew: false,
      })),
    );
    setDefaultAction(seedRef.current.def);
    setSimulatedSig(null);
    resetSim.current();
  }, [upstreamSig]);

  const draftRules = rows.map(materialize);
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

  // Update the raw Source/Destination input text. Refs are parsed from this
  // text only at commit time (materialize), so commas survive while typing.
  const setText = (key: string, field: "srcText" | "dstText", value: string) =>
    setRows((prev) =>
      prev.map((r) => (r.key === key ? { ...r, [field]: value } : r)),
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
        srcText: "",
        dstText: "",
        rule: {
          domain: active,
          verb: DOMAIN_VERBS[active][0],
          subject_refs: [],
          predicate_refs: [],
        },
      };
      // lastIdx < 0 means this domain has no rules yet → append at the end so
      // the new rule sits after every existing rule (preserving global
      // first-match-wins order) rather than being prepended at index 0.
      if (lastIdx < 0) next.push(row);
      else next.splice(lastIdx + 1, 0, row);
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

  const verbLabel = (v: string): string => {
    const k = VERB_KEYS[v.toLowerCase()];
    return k ? t(k) : v;
  };

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
          toast.success(t("net.apply.ok.title"), t("net.apply.ok.body")),
        onError: (e) =>
          toast.error(
            t("net.apply.err.title"),
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  const discard = () => {
    setRows(
      upstreamRules.map((rule) => ({
        key: freshKey(),
        rule,
        srcText: refsToText(rule.subject_refs),
        dstText: refsToText(rule.predicate_refs),
        isNew: false,
      })),
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
        <PageHeader title={t("net.title")} subtitle={t("net.subtitle")} />
        <Card title={t("net.noGraph.empty.title")}>
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title={t("net.noGraph.empty.title")}
            description={t("net.noGraph.empty.body")}
          />
        </Card>
      </>
    );
  }

  const activeLabel = t(DOMAIN_LABEL[active]);
  const activeIdxs = indicesForDomain(active);

  return (
    <>
      <PageHeader
        title={t("net.title")}
        subtitle={t("net.subtitle")}
        actions={
          <button
            className="btn"
            onClick={() =>
              compile.mutate(
                { tenantId },
                {
                  onSuccess: () =>
                    toast.success(
                      t("net.compile.ok.title"),
                      t("net.compile.ok.body"),
                    ),
                  onError: (e) =>
                    toast.error(
                      t("net.compile.err.title"),
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              )
            }
            disabled={compile.isPending}
          >
            {compile.isPending ? t("net.compiling") : t("net.compile")}
          </button>
        }
      />

      <div className="pill-tabs" role="tablist" aria-label={t("net.title")}>
        {DOMAINS.map((d) => {
          const count = rows.filter((r) => (r.rule.domain ?? "") === d).length;
          return (
            <button
              key={d}
              role="tab"
              aria-selected={active === d}
              className={active === d ? "active" : ""}
              onClick={() => setActive(d)}
            >
              {t(DOMAIN_LABEL[d])} {count > 0 && <Badge tone="info">{count}</Badge>}
            </button>
          );
        })}
      </div>

      <Card
        title={t("net.card.title", { domain: activeLabel })}
        actions={
          <HelpTooltip title={t("net.help.title")} align="right">
            {t("net.help.body")}
          </HelpTooltip>
        }
      >
        <p className="muted" style={{ marginTop: 0 }}>
          {t(DOMAIN_BLURB[active])}
        </p>

        {activeIdxs.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title={t("net.empty.title", { domain: activeLabel })}
            description={t("net.empty.body", { domain: activeLabel })}
            action={
              <button className="btn btn--primary" onClick={addRule}>
                {t("net.add", { domain: activeLabel })}
              </button>
            }
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
              const n = posInDomain + 1;
              return (
                <div
                  key={row.key}
                  className={`net-rule${row.isNew ? " net-rule--new" : ""}`}
                >
                  <div>
                    <label className="net-rule__label">
                      {t("net.rule.source")} <b>{n}.</b>
                    </label>
                    <input
                      value={row.srcText}
                      placeholder={t("net.rule.source.placeholder")}
                      onChange={(e) => setText(row.key, "srcText", e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="net-rule__label">{t("net.rule.action")}</label>
                    <select
                      value={verb}
                      aria-label={t("net.rule.action")}
                      onChange={(e) => patchRule(row.key, { verb: e.target.value })}
                    >
                      {verbOptions.map((v) => (
                        <option key={v} value={v}>
                          {verbLabel(v)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="net-rule__label">{t("net.rule.dest")}</label>
                    <input
                      value={row.dstText}
                      placeholder={t("net.rule.dest.placeholder")}
                      onChange={(e) => setText(row.key, "dstText", e.target.value)}
                    />
                  </div>
                  <div className="net-rule__acts">
                    <Badge tone={VERB_TONE[verb] ?? "neutral"}>
                      {r.verb ? verbLabel(r.verb) : "—"}
                    </Badge>
                    <button
                      className="btn btn--sm"
                      aria-label={t("net.rule.moveUp", { n })}
                      title={t("net.rule.moveUp", { n })}
                      disabled={posInDomain === 0}
                      onClick={() => move(row.key, -1)}
                    >
                      ↑
                    </button>
                    <button
                      className="btn btn--sm"
                      aria-label={t("net.rule.moveDown", { n })}
                      title={t("net.rule.moveDown", { n })}
                      disabled={posInDomain === activeIdxs.length - 1}
                      onClick={() => move(row.key, 1)}
                    >
                      ↓
                    </button>
                    <button
                      className="btn btn--sm btn--danger"
                      aria-label={t("net.rule.remove", { n })}
                      title={t("net.rule.remove", { n })}
                      onClick={() => removeRule(row.key)}
                    >
                      {t("common.remove")}
                    </button>
                  </div>
                  <div className="net-rule__desc">
                    <input
                      value={r.description ?? ""}
                      aria-label={t("net.rule.desc")}
                      placeholder={t("net.rule.desc.placeholder")}
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
            + {t("net.add", { domain: activeLabel })}
          </button>
        </div>

        <div className="field-row" style={{ marginTop: 16, alignItems: "center" }}>
          <label className="net-rule__label" style={{ marginBottom: 0 }}>
            {t("net.default.label")}
          </label>
          <select
            value={defaultAction}
            aria-label={t("net.default.label")}
            onChange={(e) => setDefaultAction(e.target.value)}
            style={{ maxWidth: 160 }}
          >
            <option value="deny">{t("verb.deny")}</option>
            <option value="allow">{t("verb.allow")}</option>
          </select>
        </div>

        {dirty &&
          (canApply ? (
            <div className="net-gate net-gate--ready" role="status">
              {t("net.gate.ready")}
            </div>
          ) : introducesErrors ? (
            <div className="net-gate net-gate--blocked" role="status">
              {t("net.gate.blocked")}
            </div>
          ) : (
            <div className="net-gate" role="status">
              {t("net.gate.untested")}
            </div>
          ))}

        <div className="rule-actions">
          <button className="btn" onClick={test} disabled={sim.isPending || !dirty}>
            {sim.isPending ? t("net.testing") : t("net.test")}
          </button>
          <button
            className="btn btn--primary"
            onClick={apply}
            disabled={update.isPending || !canApply}
          >
            {update.isPending ? t("net.applying") : t("net.apply")}
          </button>
          {dirty && (
            <button className="btn" onClick={discard} disabled={update.isPending}>
              {t("common.discard")}
            </button>
          )}
        </div>
      </Card>

      {(sim.isPending || sim.data || sim.isError) && (
        <Card title={t("net.impact.title")}>
          {sim.isError ? (
            <ErrorState error={sim.error} />
          ) : sim.isPending ? (
            <p className="muted">{t("net.impact.replaying")}</p>
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
  const t = useT();
  // Translate server-returned verdict verbs (e.g. "allow") through the catalog
  // so the impact summary reads "Allow → Deny", matching the Policy editor's
  // transition list rather than showing raw lowercase server strings.
  const verbLabel = (v: string): string => {
    const k = VERB_KEYS[v.toLowerCase()];
    return k ? t(k) : v;
  };
  return (
    <>
      {stale && (
        <p className="net-gate" style={{ marginTop: 0 }}>
          {t("net.impact.stale")}
        </p>
      )}
      <div className="impact-summary">
        {report.changed === 0 ? (
          <FormattedMessage
            id="net.impact.safe"
            values={{ total: report.total, ...richBold }}
          />
        ) : (
          <FormattedMessage
            id="net.impact.changed"
            values={{ total: report.total, changed: report.changed, ...richBold }}
          />
        )}
        <ul className="impact-list">
          {report.transitions.map((tr, i) => (
            <li key={i}>
              <FormattedMessage
                id="net.impact.transition"
                values={{
                  from: verbLabel(tr.prev_verdict),
                  to: verbLabel(tr.next_verdict),
                  count: tr.count,
                  ...richBold,
                }}
              />
            </li>
          ))}
          {report.affected_devices.length > 0 && (
            <li>
              <FormattedMessage
                id="net.impact.affected"
                values={{ devices: report.affected_devices.length }}
              />
            </li>
          )}
          {report.affected_sites.length > 0 && (
            <li>
              <FormattedMessage
                id="net.impact.sites"
                values={{ sites: report.affected_sites.length }}
              />
            </li>
          )}
          {report.next_errors !== report.prev_errors && (
            <li>
              <FormattedMessage
                id="net.impact.errors"
                values={{
                  prev: report.prev_errors,
                  next: report.next_errors,
                  ...richBold,
                }}
              />
            </li>
          )}
        </ul>
      </div>
    </>
  );
}
