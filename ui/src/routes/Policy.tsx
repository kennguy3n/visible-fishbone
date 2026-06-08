import { useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
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

export function Policy() {
  return (
    <RequireTenant>{(tenantId) => <PolicyInner tenantId={tenantId} />}</RequireTenant>
  );
}

interface RawGraph {
  nodes?: { id?: string; name?: string; label?: string; type?: string }[];
  edges?: { source?: string; from?: string; target?: string; to?: string }[];
  [k: string]: unknown;
}

function toFlow(graph: RawGraph): { nodes: Node[]; edges: Edge[] } {
  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];
  const perRow = Math.ceil(Math.sqrt(Math.max(rawNodes.length, 1)));
  const nodes: Node[] = rawNodes.map((n, i) => ({
    id: String(n.id ?? n.name ?? i),
    data: { label: String(n.label ?? n.name ?? n.id ?? i) },
    position: { x: (i % perRow) * 200, y: Math.floor(i / perRow) * 120 },
    style: {
      background: "#15203a",
      color: "#e6ecf7",
      border: "1px solid #3b82f6",
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
    style: { stroke: "#3b82f6" },
  }));
  return { nodes, edges };
}

function PolicyInner({ tenantId }: { tenantId: string }) {
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
      setSaveErr("Graph is not valid JSON.");
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
        title="Policy editor"
        subtitle="Visualize, edit and simulate the tenant policy graph."
        actions={
          <>
            <span className="muted" style={{ alignSelf: "center" }}>
              {graphQuery.data ? (
                <>
                  version <b>{graphQuery.data.version}</b>
                </>
              ) : null}
            </span>
            <button
              className="btn"
              disabled={compile.isPending}
              onClick={() => compile.mutate({ tenantId })}
            >
              {compile.isPending ? "Compiling…" : "Compile bundles"}
            </button>
          </>
        }
      />

      <div className="mode-toggle">
        <button
          className={mode === "simple" ? "active" : ""}
          onClick={() => setMode("simple")}
        >
          Simple
        </button>
        <button
          className={mode === "advanced" ? "active" : ""}
          onClick={() => setMode("advanced")}
        >
          Advanced
        </button>
        <HelpTooltip title="Simple vs Advanced">
          <b>Simple</b> shows your rules as a plain "who → can do what → to
          where" list you can reorder and trim. <b>Advanced</b> exposes the raw
          policy graph, JSON and the full change simulator.
        </HelpTooltip>
      </div>

      {mode === "simple" && (
        <SimpleRules
          tenantId={tenantId}
          graph={(graphQuery.data?.graph ?? {}) as GraphDoc}
          isError={graphQuery.isError}
        />
      )}

      {mode === "advanced" && (
      <div className="pill-tabs">
        <button className={tab === "graph" ? "active" : ""} onClick={() => setTab("graph")}>
          Graph
        </button>
        <button className={tab === "json" ? "active" : ""} onClick={() => setTab("json")}>
          JSON
        </button>
        <button
          className={tab === "simulate" ? "active" : ""}
          onClick={() => setTab("simulate")}
        >
          Change simulation
        </button>
      </div>
      )}

      {mode === "advanced" && graphQuery.isError && (
        <Card>
          <p className="muted">
            No policy graph exists for this tenant yet. Use the JSON tab to
            author one.
          </p>
        </Card>
      )}

      {mode === "advanced" && tab === "graph" && (
        <Card title="Policy graph">
          {flow.nodes.length === 0 ? (
            <p className="muted">
              The graph has no renderable nodes. Switch to the JSON tab to
              inspect the raw document.
            </p>
          ) : (
            <div className="graph-canvas">
              <ReactFlow nodes={flow.nodes} edges={flow.edges} fitView>
                <Background color="#243352" />
                <Controls />
              </ReactFlow>
            </div>
          )}
        </Card>
      )}

      {mode === "advanced" && tab === "json" && (
        <Card title="Raw policy document">
          <textarea
            style={{ minHeight: 360 }}
            value={jsonText}
            onChange={(e) => setDraft(e.target.value)}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button
              className="btn btn--primary"
              onClick={save}
              disabled={update.isPending || draft === null}
            >
              {update.isPending ? "Saving…" : "Save graph"}
            </button>
            {draft !== null && (
              <button className="btn" onClick={() => setDraft(null)}>
                Reset
              </button>
            )}
          </div>
          {saveErr && <p className="error-text">{saveErr}</p>}
          {update.isError && (
            <p className="error-text">
              {update.error instanceof Error
                ? update.error.message
                : "Save failed"}
            </p>
          )}
        </Card>
      )}

      {mode === "advanced" && tab === "simulate" && (
        <SimulationPanel tenantId={tenantId} baseGraph={graphQuery.data?.graph ?? {}} />
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
      setErr("Proposed graph is not valid JSON.");
      return;
    }
    sim.mutate({ proposed: parsed });
  };

  return (
    <div className="grid grid--2">
      <Card title="Proposed graph">
        <textarea
          style={{ minHeight: 320 }}
          value={proposed}
          onChange={(e) => setProposed(e.target.value)}
        />
        <button
          className="btn btn--primary"
          style={{ marginTop: 10 }}
          onClick={run}
          disabled={sim.isPending}
        >
          {sim.isPending ? "Replaying…" : "Run simulation"}
        </button>
        {err && <p className="error-text">{err}</p>}
        {sim.isError && <ErrorState error={sim.error} />}
      </Card>
      <Card title="Impact report">
        {sim.data ? (
          <SimulationResult report={sim.data} />
        ) : (
          <p className="muted">
            Replays recent traffic through the proposed graph and reports how
            many verdicts would change. No simulation run yet.
          </p>
        )}
      </Card>
    </div>
  );
}

function SimulationResult({ report }: { report: SimulationResponse }) {
  return (
    <>
      <div className="grid grid--stats" style={{ marginBottom: 14 }}>
        <div className="stat">
          <div className="stat__label">Evaluated</div>
          <div className="stat__value">{report.total}</div>
        </div>
        <div className="stat">
          <div className="stat__label">Changed</div>
          <div className="stat__value" style={{ color: "var(--warn)" }}>
            {report.changed}
          </div>
        </div>
        <div className="stat">
          <div className="stat__label">Affected devices</div>
          <div className="stat__value">{report.affected_devices.length}</div>
        </div>
      </div>
      <h4 style={{ margin: "4px 0 8px" }}>Verdict transitions</h4>
      {report.transitions.length === 0 ? (
        <p className="muted">No verdict changes in the replay window.</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>From</th>
              <th>To</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {report.transitions.map((t, i) => (
              <tr key={i}>
                <td>
                  <Badge tone="neutral">{t.prev_verdict}</Badge>
                </td>
                <td>
                  <Badge
                    tone={t.next_verdict === "deny" ? "danger" : "ok"}
                  >
                    {t.next_verdict}
                  </Badge>
                </td>
                <td>{t.count}</td>
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

function describeSource(r: GraphRule): string {
  const refs = r.subject_refs ?? [];
  const inline = (r.subjects ?? []).map((s) =>
    s.kind ? `${s.kind}:${s.name ?? "?"}` : (s.name ?? "?"),
  );
  const all = [...refs, ...inline];
  return all.length ? all.join(", ") : "Anyone";
}

function describeDest(r: GraphRule): string {
  const refs = r.predicate_refs ?? [];
  const inline = (r.predicates ?? []).map((p) => p.name ?? "?");
  const all = [...refs, ...inline];
  if (all.length) return all.join(", ");
  return r.domain ? `all ${r.domain.toUpperCase()} traffic` : "anything";
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
  // Keep the latest `sim.reset` in a ref so the reset effect depends only on
  // `initial` and never re-fires from an identity change in the mutation
  // method (which would otherwise risk a reset -> render -> reset loop).
  const resetSim = useRef(sim.reset);
  resetSim.current = sim.reset;
  // Reset local edits whenever the upstream graph changes (e.g. after save).
  useEffect(() => {
    setRows(initial);
    resetSim.current();
  }, [initial]);

  const removedKeys = new Set(
    rows.filter((r) => r.status === "removed").map((r) => r.key),
  );
  const activeOrder = rows
    .filter((r) => r.status === "active")
    .map((r) => r.key)
    .join("|");
  // Expected order = original order with the removed rules filtered out, so a
  // removal alone doesn't count as a reorder.
  const expectedOrder = initial
    .filter((r) => !removedKeys.has(r.key))
    .map((r) => r.key)
    .join("|");
  const removedCount = removedKeys.size;
  const reordered = activeOrder !== expectedOrder;
  const dirty = removedCount > 0 || reordered;

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
        onSuccess: () => toast.success("Policy updated", "Your changes are live."),
        onError: (e) =>
          toast.error(
            "Could not save policy",
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  if (isError || rows.length === 0) {
    return (
      <Card title="Rules">
        <EmptyState
          title="No rules yet"
          description="This tenant's policy has no rules. Switch to Advanced to author the policy graph, then come back here to manage rules in plain English."
        />
      </Card>
    );
  }

  return (
    <>
      <Card
        title="Rules — who can do what, to where"
        actions={
          <HelpTooltip title="Reordering rules" align="right">
            Rules are evaluated top to bottom; the first match wins. Drag the ⠿
            handle to reorder. Mark a rule for removal to preview deleting it,
            then test the change before saving.
          </HelpTooltip>
        }
      >
        <div className="rule-table" role="table" aria-label="Policy rules">
          <div className="rule-row rule-row--head" role="row">
            <span />
            <span>Source</span>
            <span>Action</span>
            <span>Destination</span>
            <span>Domain</span>
            <span />
          </div>
          {rows.map((row, i) => {
            const r = row.rule;
            const verb = (r.verb ?? "").toLowerCase();
            const originalIndex = initial.findIndex((x) => x.key === row.key);
            const moved =
              row.status === "active" && reordered && originalIndex !== i;
            const variant =
              row.status === "removed" ? "remove" : moved ? "draft" : "active";
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
                  title="Drag to reorder"
                  aria-hidden
                >
                  ⠿
                </span>
                <span className="rule-row__src" title={describeSource(r)}>
                  <b>{i + 1}.</b> {describeSource(r)}
                  {r.description && (
                    <span className="rule-row__desc">{r.description}</span>
                  )}
                </span>
                <span>
                  <Badge tone={VERB_TONE[verb] ?? "neutral"}>
                    {r.verb ?? "—"}
                  </Badge>
                </span>
                <span title={describeDest(r)}>{describeDest(r)}</span>
                <span className="muted">{r.domain ?? "—"}</span>
                <span>
                  {row.status === "active" ? (
                    <button
                      className="btn btn--sm btn--danger"
                      onClick={() =>
                        setRows((prev) =>
                          prev.map((x) =>
                            x.key === row.key ? { ...x, status: "removed" } : x,
                          ),
                        )
                      }
                    >
                      Remove
                    </button>
                  ) : (
                    <button
                      className="btn btn--sm"
                      onClick={() =>
                        setRows((prev) =>
                          prev.map((x) =>
                            x.key === row.key ? { ...x, status: "active" } : x,
                          ),
                        )
                      }
                    >
                      Undo
                    </button>
                  )}
                </span>
              </div>
            );
          })}
        </div>

        <div className="rule-legend">
          <span><i className="dot dot--ok" /> Active</span>
          <span><i className="dot dot--warn" /> Reordered (draft)</span>
          <span><i className="dot dot--danger" /> Will be removed</span>
        </div>

        <div className="rule-actions">
          <button
            className="btn"
            onClick={test}
            disabled={sim.isPending || !dirty}
          >
            {sim.isPending ? "Testing…" : "Test this change"}
          </button>
          <button
            className="btn btn--primary"
            onClick={apply}
            disabled={update.isPending || !dirty}
          >
            {update.isPending ? "Saving…" : "Save changes"}
          </button>
          {dirty && (
            <button
              className="btn"
              onClick={() => {
                setRows(initial);
                sim.reset();
              }}
            >
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
            <ImpactSummary report={sim.data} removed={removedCount} reordered={reordered} />
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
  const edits: string[] = [];
  if (removed > 0) edits.push(`${removed} rule${removed === 1 ? "" : "s"} removed`);
  if (reordered) edits.push("rules reordered");

  return (
    <>
      <p>
        {edits.length > 0 && <b>{edits.join(", ")}. </b>}
        {report.changed === 0 ? (
          <>
            Replaying the last {report.total} request
            {report.total === 1 ? "" : "s"}, <b>nothing changes</b> — this edit
            looks safe to apply.
          </>
        ) : (
          <>
            Of the last {report.total} request{report.total === 1 ? "" : "s"},{" "}
            <b>{report.changed}</b> would get a different outcome, affecting{" "}
            <b>{report.affected_devices.length}</b> device
            {report.affected_devices.length === 1 ? "" : "s"}.
          </>
        )}
      </p>
      {report.transitions.length > 0 && (
        <ul className="impact-list">
          {report.transitions.map((t, i) => (
            <li key={i}>
              <Badge tone="neutral">{t.prev_verdict}</Badge> →{" "}
              <Badge tone={t.next_verdict === "deny" ? "danger" : "ok"}>
                {t.next_verdict}
              </Badge>{" "}
              for <b>{t.count}</b> request{t.count === 1 ? "" : "s"}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
