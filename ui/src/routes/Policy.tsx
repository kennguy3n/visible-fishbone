import { useMemo, useState } from "react";
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
import { PageHeader, Card, LoadingState, ErrorState, Badge } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";

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

      {graphQuery.isError && (
        <Card>
          <p className="muted">
            No policy graph exists for this tenant yet. Use the JSON tab to
            author one.
          </p>
        </Card>
      )}

      {tab === "graph" && (
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

      {tab === "json" && (
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

      {tab === "simulate" && (
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
