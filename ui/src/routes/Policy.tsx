import { useEffect, useMemo, useRef, useState } from "react";
import { FormattedMessage } from "react-intl";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CHART } from "@/lib/chart-theme";
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
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { LaneB2Intl, useT, richBold, type LaneB2Key } from "./lane-b2/i18n";

type TFunc = (id: LaneB2Key, values?: Record<string, string | number>) => string;

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

function verbLabel(t: TFunc, v?: string): string {
  if (!v) return "—";
  const k = VERB_KEYS[v.toLowerCase()];
  return k ? t(k) : v;
}

export function Policy() {
  return (
    <LaneB2Intl>
      <RequireTenant>
        {(tenantId) => <PolicyInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB2Intl>
  );
}

interface RawGraph {
  nodes?: { id?: string; name?: string; label?: string; type?: string }[];
  edges?: { source?: string; from?: string; target?: string; to?: string }[];
  [k: string]: unknown;
}

// Stable empty-graph fallback. Using one frozen module-level value (instead of
// an inline `?? {}`) means children that receive the graph as a prop keep a
// stable reference while the query is errored/empty, so e.g. SimpleRules'
// content-signature memo isn't recomputed against a fresh object every render.
const EMPTY_GRAPH = Object.freeze({});

function toFlow(graph: RawGraph): { nodes: Node[]; edges: Edge[] } {
  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];
  const perRow = Math.ceil(Math.sqrt(Math.max(rawNodes.length, 1)));
  const nodes: Node[] = rawNodes.map((n, i) => ({
    id: String(n.id ?? n.name ?? i),
    data: { label: String(n.label ?? n.name ?? n.id ?? i) },
    position: { x: (i % perRow) * 200, y: Math.floor(i / perRow) * 120 },
    style: {
      background: CHART.surface,
      color: CHART.text,
      border: `1px solid ${CHART.brand}`,
      borderRadius: 8,
      fontSize: 12,
      padding: 8,
    },
  }));
  const edges: Edge[] = rawEdges.map((e, i) => ({
    id: `e${i}`,
    source: String(e.source ?? e.from ?? ""),
    target: String(e.target ?? e.to ?? ""),
    animated: true,
    style: { stroke: CHART.brand },
  }));
  return { nodes, edges };
}

function PolicyInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const toast = useToast();
  const graphQuery = useGetPolicyGraph(tenantId, { query: { retry: false } });
  const update = useUpdatePolicyGraph();
  const compile = useCompilePolicyBundles();
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  const [tab, setTab] = useState<"graph" | "json" | "simulate">("graph");
  const [draft, setDraft] = useState<string | null>(null);
  const [saveErr, setSaveErr] = useState<string | null>(null);

  const flow = useMemo(
    () => toFlow((graphQuery.data?.graph ?? {}) as RawGraph),
    [graphQuery.data?.graph],
  );

  const jsonText =
    draft ?? JSON.stringify(graphQuery.data?.graph ?? {}, null, 2);

  const save = () => {
    setSaveErr(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      setSaveErr(t("policy.json.invalid"));
      return;
    }
    update.mutate(
      { tenantId, data: parsed },
      { onSuccess: () => setDraft(null) },
    );
  };

  if (graphQuery.isLoading) return <LoadingState />;

  return (
    <>
      <PageHeader
        title={t("policy.title")}
        subtitle={t("policy.subtitle")}
        actions={
          <>
            <span className="muted" style={{ alignSelf: "center" }}>
              {graphQuery.data ? (
                <FormattedMessage
                  id="policy.version"
                  values={{ version: <b>{graphQuery.data.version}</b> }}
                />
              ) : null}
            </span>
            <button
              className="btn"
              disabled={compile.isPending}
              onClick={() =>
                compile.mutate(
                  { tenantId },
                  {
                    onSuccess: () =>
                      toast.success(
                        t("policy.compile.ok.title"),
                        t("policy.compile.ok.body"),
                      ),
                    onError: (e) =>
                      toast.error(
                        t("policy.compile.err.title"),
                        e instanceof Error ? e.message : undefined,
                      ),
                  },
                )
              }
            >
              {compile.isPending ? t("policy.compiling") : t("policy.compile")}
            </button>
          </>
        }
      />

      <div className="mode-toggle" role="group" aria-label={t("policy.mode.label")}>
        <button
          className={mode === "simple" ? "active" : ""}
          aria-pressed={mode === "simple"}
          onClick={() => setMode("simple")}
        >
          {t("policy.mode.simple")}
        </button>
        <button
          className={mode === "advanced" ? "active" : ""}
          aria-pressed={mode === "advanced"}
          onClick={() => setMode("advanced")}
        >
          {t("policy.mode.advanced")}
        </button>
        <HelpTooltip title={t("policy.mode.help.title")}>
          {t("policy.mode.help.body")}
        </HelpTooltip>
      </div>

      {mode === "simple" && (
        <SimpleRules
          tenantId={tenantId}
          graph={(graphQuery.data?.graph ?? EMPTY_GRAPH) as GraphDoc}
          isError={graphQuery.isError}
        />
      )}

      {mode === "advanced" && (
        <div className="pill-tabs" role="tablist" aria-label={t("policy.title")}>
          <button
            role="tab"
            aria-selected={tab === "graph"}
            className={tab === "graph" ? "active" : ""}
            onClick={() => setTab("graph")}
          >
            {t("policy.tab.graph")}
          </button>
          <button
            role="tab"
            aria-selected={tab === "json"}
            className={tab === "json" ? "active" : ""}
            onClick={() => setTab("json")}
          >
            {t("policy.tab.json")}
          </button>
          <button
            role="tab"
            aria-selected={tab === "simulate"}
            className={tab === "simulate" ? "active" : ""}
            onClick={() => setTab("simulate")}
          >
            {t("policy.tab.simulate")}
          </button>
        </div>
      )}

      {mode === "advanced" && graphQuery.isError && (
        <Card>
          <p className="muted">{t("policy.advanced.noGraph")}</p>
        </Card>
      )}

      {mode === "advanced" && tab === "graph" && (
        <Card title={t("policy.graph.title")}>
          {flow.nodes.length === 0 ? (
            <p className="muted">{t("policy.graph.empty")}</p>
          ) : (
            <div className="graph-canvas">
              <ReactFlow nodes={flow.nodes} edges={flow.edges} fitView>
                <Background color={CHART.border} />
                <Controls />
              </ReactFlow>
            </div>
          )}
        </Card>
      )}

      {mode === "advanced" && tab === "json" && (
        <Card title={t("policy.json.title")}>
          <textarea
            style={{ minHeight: 360 }}
            value={jsonText}
            aria-label={t("policy.json.title")}
            onChange={(e) => setDraft(e.target.value)}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button
              className="btn btn--primary"
              onClick={save}
              disabled={update.isPending || draft === null}
            >
              {update.isPending ? t("policy.json.saving") : t("policy.json.save")}
            </button>
            {draft !== null && (
              <button className="btn" onClick={() => setDraft(null)}>
                {t("policy.json.reset")}
              </button>
            )}
          </div>
          {saveErr && (
            <p className="error-text" role="alert">
              {saveErr}
            </p>
          )}
          {update.isError && (
            <p className="error-text" role="alert">
              {update.error instanceof Error
                ? update.error.message
                : t("policy.json.saveFailed.title")}
            </p>
          )}
        </Card>
      )}

      {mode === "advanced" && tab === "simulate" && (
        <SimulationPanel
          tenantId={tenantId}
          baseGraph={graphQuery.data?.graph ?? EMPTY_GRAPH}
        />
      )}
    </>
  );
}

function SimulationPanel({
  tenantId,
  baseGraph,
}: {
  tenantId: string;
  baseGraph: unknown;
}) {
  const t = useT();
  const sim = useRunSimulation(tenantId);
  const [proposed, setProposed] = useState(() =>
    JSON.stringify(baseGraph, null, 2),
  );
  const [err, setErr] = useState<string | null>(null);

  const run = () => {
    setErr(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(proposed);
    } catch {
      setErr(t("policy.sim.invalid"));
      return;
    }
    sim.mutate({ proposed: parsed });
  };

  return (
    <div className="grid grid--2">
      <Card title={t("policy.sim.proposed")}>
        <textarea
          style={{ minHeight: 320 }}
          value={proposed}
          aria-label={t("policy.sim.proposed")}
          onChange={(e) => setProposed(e.target.value)}
        />
        <button
          className="btn btn--primary"
          style={{ marginTop: 10 }}
          onClick={run}
          disabled={sim.isPending}
        >
          {sim.isPending ? t("policy.sim.running") : t("policy.sim.run")}
        </button>
        {err && (
          <p className="error-text" role="alert">
            {err}
          </p>
        )}
        {sim.isError && <ErrorState error={sim.error} />}
      </Card>
      <Card title={t("policy.sim.report")}>
        {sim.data ? (
          <SimulationResult report={sim.data} />
        ) : (
          <p className="muted">{t("policy.sim.intro")}</p>
        )}
      </Card>
    </div>
  );
}

function SimulationResult({ report }: { report: SimulationResponse }) {
  const t = useT();
  return (
    <>
      <div className="grid grid--stats" style={{ marginBottom: 14 }}>
        <div className="stat">
          <div className="stat__label">{t("policy.sim.evaluated")}</div>
          <div className="stat__value">{report.total}</div>
        </div>
        <div className="stat">
          <div className="stat__label">{t("policy.sim.changed")}</div>
          <div className="stat__value" style={{ color: "var(--warn)" }}>
            {report.changed}
          </div>
        </div>
        <div className="stat">
          <div className="stat__label">{t("policy.sim.affected")}</div>
          <div className="stat__value">{report.affected_devices.length}</div>
        </div>
      </div>
      <h4 style={{ margin: "4px 0 8px" }}>{t("policy.sim.transitions")}</h4>
      {report.transitions.length === 0 ? (
        <p className="muted">{t("policy.sim.noTransitions")}</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>{t("policy.sim.col.from")}</th>
              <th>{t("policy.sim.col.to")}</th>
              <th>{t("policy.sim.col.count")}</th>
            </tr>
          </thead>
          <tbody>
            {report.transitions.map((tr, i) => (
              <tr key={i}>
                <td>
                  <Badge tone="neutral">{verbLabel(t, tr.prev_verdict)}</Badge>
                </td>
                <td>
                  <Badge tone={tr.next_verdict === "deny" ? "danger" : "ok"}>
                    {verbLabel(t, tr.next_verdict)}
                  </Badge>
                </td>
                <td>{tr.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// --- Simple mode ---------------------------------------------------------

interface GraphRule {
  id?: string;
  domain?: string;
  verb?: string;
  description?: string;
  subject_refs?: string[];
  predicate_refs?: string[];
  subjects?: { name?: string; kind?: string }[];
  predicates?: { name?: string }[];
  [k: string]: unknown;
}

interface GraphDoc {
  default_action?: string;
  rules?: GraphRule[];
  [k: string]: unknown;
}

const VERB_TONE: Record<string, "ok" | "warn" | "danger" | "neutral" | "info"> = {
  allow: "ok",
  deny: "danger",
  inspect: "info",
  decrypt: "info",
  steer: "info",
  log: "neutral",
  suggest_only: "warn",
};

function describeSource(r: GraphRule, t: TFunc): string {
  const refs = r.subject_refs ?? [];
  const inline = (r.subjects ?? []).map((s) =>
    s.kind ? `${s.kind}:${s.name ?? "?"}` : (s.name ?? "?"),
  );
  const all = [...refs, ...inline];
  return all.length ? all.join(", ") : t("policy.describe.anyone");
}

function describeDest(r: GraphRule, t: TFunc): string {
  const refs = r.predicate_refs ?? [];
  const inline = (r.predicates ?? []).map((p) => p.name ?? "?");
  const all = [...refs, ...inline];
  if (all.length) return all.join(", ");
  return r.domain
    ? t("policy.describe.allDomain", { domain: r.domain.toUpperCase() })
    : t("policy.describe.anything");
}

interface Row {
  rule: GraphRule;
  status: "active" | "removed";
  key: string;
}

function SimpleRules({
  tenantId,
  graph,
  isError,
}: {
  tenantId: string;
  graph: GraphDoc;
  isError: boolean;
}) {
  const t = useT();
  const update = useUpdatePolicyGraph();
  const sim = useRunSimulation(tenantId);
  const toast = useToast();

  const initial = useMemo<Row[]>(
    () =>
      (graph.rules ?? []).map((rule, i) => ({
        rule,
        status: "active" as const,
        key: rule.id || `rule-${i}`,
      })),
    [graph.rules],
  );

  const [rows, setRows] = useState<Row[]>(initial);
  const [dragKey, setDragKey] = useState<string | null>(null);
  // Keep the latest `sim.reset` and `initial` in refs so the reset effect can
  // depend only on the content signature below (refs never re-fire effects).
  const resetSim = useRef(sim.reset);
  resetSim.current = sim.reset;
  const initialRef = useRef(initial);
  initialRef.current = initial;
  // A stable signature of the upstream rule *content* (not array identity).
  // The global MutationCache invalidates every query after any successful
  // mutation, so the policy-graph query refetches and `graph`/`initial` get
  // new object identities even when the rules are unchanged. Keying the reset
  // on content means an unrelated mutation (e.g. acking an alert) no longer
  // wipes the operator's in-progress reordering/removals; a genuine upstream
  // change still resets, as it should.
  const signature = useMemo(
    () =>
      JSON.stringify({
        d: graph.default_action ?? null,
        r: (graph.rules ?? []).map((rule, i) => [
          rule.id || `rule-${i}`,
          rule.verb ?? null,
          rule.domain ?? null,
          rule.subject_refs ?? null,
          rule.predicate_refs ?? null,
          rule.subjects ?? null,
          rule.predicates ?? null,
        ]),
      }),
    [graph],
  );
  // Reset local edits only when the upstream rule content actually changes.
  useEffect(() => {
    setRows(initialRef.current);
    resetSim.current();
  }, [signature]);

  const removedKeys = new Set(
    rows.filter((r) => r.status === "removed").map((r) => r.key),
  );
  const activeKeys = rows
    .filter((r) => r.status === "active")
    .map((r) => r.key);
  // Expected order = original order with the removed rules filtered out, so a
  // removal alone doesn't count as a reorder.
  const expectedKeys = initial
    .filter((r) => !removedKeys.has(r.key))
    .map((r) => r.key);
  const activeOrder = activeKeys.join("|");
  const expectedOrder = expectedKeys.join("|");
  const removedCount = removedKeys.size;
  const reordered = activeOrder !== expectedOrder;
  const dirty = removedCount > 0 || reordered;
  // Per-row "moved" flag, compared within the *active* sequence only. A row is
  // moved iff its position among the active rows differs from where it sits in
  // the expected (removal-only) sequence. Comparing like-for-like coordinates
  // means a row that merely slid up because a row above it was marked for
  // removal is NOT flagged — only rows the operator actually reordered are.
  const movedKeys = new Set(
    reordered ? activeKeys.filter((k, idx) => expectedKeys[idx] !== k) : [],
  );

  const proposed = (): GraphDoc => ({
    ...graph,
    rules: rows.filter((r) => r.status === "active").map((r) => r.rule),
  });

  const onDrop = (targetKey: string) => {
    if (!dragKey || dragKey === targetKey) return;
    setRows((prev) => {
      const next = [...prev];
      const from = next.findIndex((r) => r.key === dragKey);
      const to = next.findIndex((r) => r.key === targetKey);
      if (from < 0 || to < 0) return prev;
      // Don't reposition relative to a removed row — only active rows define
      // the meaningful order, so dropping onto a removed row is a no-op that
      // keeps the visible active sequence unambiguous.
      if (next[to].status === "removed") return prev;
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });
    setDragKey(null);
  };

  const test = () => {
    sim.mutate({ proposed: proposed() });
  };

  const apply = () => {
    update.mutate(
      { tenantId, data: proposed() as Record<string, unknown> },
      {
        onSuccess: () =>
          toast.success(t("policy.save.ok.title"), t("policy.save.ok.body")),
        onError: (e) =>
          toast.error(
            t("policy.save.err.title"),
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  if (isError || rows.length === 0) {
    return (
      <Card title={t("policy.simple.title")}>
        <EmptyState
          title={t("policy.simple.empty.title")}
          description={t("policy.simple.empty.body")}
        />
      </Card>
    );
  }

  return (
    <>
      <Card
        title={t("policy.simple.title")}
        actions={
          <HelpTooltip title={t("policy.simple.help.title")} align="right">
            {t("policy.simple.help.body")}
          </HelpTooltip>
        }
      >
        <div className="rule-table" role="table" aria-label={t("policy.simple.title")}>
          <div className="rule-row rule-row--head" role="row">
            <span role="columnheader" aria-label={t("policy.dragHint")} />
            <span role="columnheader">{t("policy.col.source")}</span>
            <span role="columnheader">{t("policy.col.action")}</span>
            <span role="columnheader">{t("policy.col.dest")}</span>
            <span role="columnheader">{t("policy.col.domain")}</span>
            <span role="columnheader" aria-label={t("common.remove")} />
          </div>
          {rows.map((row, i) => {
            const r = row.rule;
            const verb = (r.verb ?? "").toLowerCase();
            const moved = row.status === "active" && movedKeys.has(row.key);
            const variant =
              row.status === "removed" ? "remove" : moved ? "draft" : "active";
            const src = describeSource(r, t);
            const dst = describeDest(r, t);
            return (
              <div
                key={row.key}
                className={`rule-row rule-row--${variant}`}
                role="row"
                draggable={row.status === "active"}
                onDragStart={() => setDragKey(row.key)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => onDrop(row.key)}
              >
                <span
                  className="rule-row__handle"
                  role="cell"
                  title={t("policy.dragHint")}
                >
                  <span aria-hidden>⠿</span>
                </span>
                <span className="rule-row__src" role="cell" title={src}>
                  <b>{i + 1}.</b> {src}
                  {r.description && (
                    <span className="rule-row__desc">{r.description}</span>
                  )}
                </span>
                <span role="cell">
                  <Badge tone={VERB_TONE[verb] ?? "neutral"}>
                    {verbLabel(t, r.verb)}
                  </Badge>
                </span>
                <span role="cell" title={dst}>{dst}</span>
                <span className="muted" role="cell">{r.domain ?? "—"}</span>
                <span role="cell">
                  {row.status === "active" ? (
                    <button
                      className="btn btn--sm btn--danger"
                      aria-label={t("policy.row.remove", { n: i + 1 })}
                      onClick={() =>
                        setRows((prev) =>
                          prev.map((x) =>
                            x.key === row.key ? { ...x, status: "removed" } : x,
                          ),
                        )
                      }
                    >
                      {t("common.remove")}
                    </button>
                  ) : (
                    <button
                      className="btn btn--sm"
                      aria-label={t("policy.row.undo", { n: i + 1 })}
                      onClick={() =>
                        setRows((prev) =>
                          prev.map((x) =>
                            x.key === row.key ? { ...x, status: "active" } : x,
                          ),
                        )
                      }
                    >
                      {t("common.undo")}
                    </button>
                  )}
                </span>
              </div>
            );
          })}
        </div>

        <div className="rule-legend">
          <span>
            <i className="dot dot--ok" /> {t("policy.legend.active")}
          </span>
          <span>
            <i className="dot dot--warn" /> {t("policy.legend.reordered")}
          </span>
          <span>
            <i className="dot dot--danger" /> {t("policy.legend.removed")}
          </span>
        </div>

        <div className="rule-actions">
          <button
            className="btn"
            onClick={test}
            disabled={sim.isPending || !dirty}
          >
            {sim.isPending ? t("policy.testing") : t("policy.test")}
          </button>
          <button
            className="btn btn--primary"
            onClick={apply}
            disabled={update.isPending || !dirty}
          >
            {update.isPending ? t("policy.saving") : t("policy.save")}
          </button>
          {dirty && (
            <button
              className="btn"
              onClick={() => {
                setRows(initial);
                sim.reset();
              }}
            >
              {t("common.discard")}
            </button>
          )}
        </div>
      </Card>

      {(sim.isPending || sim.data || sim.isError) && (
        <Card title={t("policy.impact.title")}>
          {sim.isError ? (
            <ErrorState error={sim.error} />
          ) : sim.isPending ? (
            <p className="muted">{t("policy.impact.replaying")}</p>
          ) : sim.data ? (
            <ImpactSummary
              report={sim.data}
              removed={removedCount}
              reordered={reordered}
            />
          ) : null}
        </Card>
      )}
    </>
  );
}

function ImpactSummary({
  report,
  removed,
  reordered,
}: {
  report: SimulationResponse;
  removed: number;
  reordered: boolean;
}) {
  const t = useT();
  const edits: string[] = [];
  if (removed > 0) edits.push(t("policy.impact.removed", { removed }));
  if (reordered) edits.push(t("policy.impact.reordered"));

  return (
    <>
      <p>
        {edits.length > 0 && <b>{edits.join(", ")}. </b>}
        {report.changed === 0 ? (
          <FormattedMessage
            id="policy.impact.safe"
            values={{ total: report.total, ...richBold }}
          />
        ) : (
          <>
            <FormattedMessage
              id="policy.impact.changed"
              values={{ total: report.total, changed: report.changed, ...richBold }}
            />{" "}
            <FormattedMessage
              id="policy.impact.affected"
              values={{ devices: report.affected_devices.length }}
            />
          </>
        )}
      </p>
      {report.transitions.length > 0 && (
        <ul className="impact-list">
          {report.transitions.map((tr, i) => (
            <li key={i}>
              <Badge tone="neutral">{verbLabel(t, tr.prev_verdict)}</Badge> →{" "}
              <Badge tone={tr.next_verdict === "deny" ? "danger" : "ok"}>
                {verbLabel(t, tr.next_verdict)}
              </Badge>{" "}
              <FormattedMessage
                id="policy.impact.forRequests"
                values={{ count: tr.count }}
              />
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
