import { useState } from "react";
import { useGetPolicyGraph } from "@/api/generated/endpoints/policy/policy";
import {
  PageHeader,
  Card,
  LoadingState,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";

const DOMAINS = [
  { key: "ngfw", label: "NGFW", blurb: "L3–L7 firewall rules, app-id and IPS profiles." },
  { key: "swg", label: "SWG", blurb: "Secure web gateway: URL filtering, TLS inspection, content rules." },
  { key: "dns", label: "DNS", blurb: "DNS-layer security: sinkholing, category blocking, DoH control." },
  { key: "ztna", label: "ZTNA", blurb: "Identity-aware per-app access with device posture gating." },
  { key: "sdwan", label: "SD-WAN", blurb: "Path selection, link SLAs and traffic-steering policy." },
] as const;

type DomainKey = (typeof DOMAINS)[number]["key"];

interface GraphNode {
  id?: string;
  name?: string;
  label?: string;
  type?: string;
  kind?: string;
  domain?: string;
  action?: string;
  [k: string]: unknown;
}

export function NetworkPolicies() {
  return (
    <RequireTenant>
      {(tenantId) => <NetworkPoliciesInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function matchesDomain(node: GraphNode, domain: DomainKey): boolean {
  const hay = `${node.type ?? ""} ${node.kind ?? ""} ${node.domain ?? ""} ${
    node.name ?? ""
  } ${node.label ?? ""}`.toLowerCase();
  if (domain === "sdwan") return hay.includes("sdwan") || hay.includes("sd-wan");
  return hay.includes(domain);
}

function NetworkPoliciesInner({ tenantId }: { tenantId: string }) {
  const graph = useGetPolicyGraph(tenantId, { query: { retry: false } });
  const [active, setActive] = useState<DomainKey>("ngfw");

  if (graph.isLoading) return <LoadingState />;

  const raw = (graph.data?.graph ?? {}) as { nodes?: GraphNode[] };
  const nodes = Array.isArray(raw.nodes) ? raw.nodes : [];
  const domainNodes = nodes.filter((n) => matchesDomain(n, active));
  const activeMeta = DOMAINS.find((d) => d.key === active)!;

  return (
    <>
      <PageHeader
        title="Network policies"
        subtitle="Domain-specific views over the unified tenant policy graph."
      />
      <div className="pill-tabs">
        {DOMAINS.map((d) => {
          const count = nodes.filter((n) => matchesDomain(n, d.key)).length;
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

      <Card title={`${activeMeta.label} policy`}>
        <p className="muted" style={{ marginTop: 0 }}>
          {activeMeta.blurb}
        </p>
        {graph.isError ? (
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title="No policy graph yet"
            description="No policy graph has been compiled for this tenant. Author one in the Policy editor."
          />
        ) : domainNodes.length === 0 ? (
          <EmptyState
            illustration={<EmptyIllustration kind="policy" />}
            title={`No ${activeMeta.label} rules`}
            description={`The current graph (version ${graph.data?.version ?? "—"}) has no ${activeMeta.label} rules. Author rules in the Policy editor.`}
          />
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Type</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {domainNodes.map((n, i) => (
                <tr key={n.id ?? i}>
                  <td>{String(n.label ?? n.name ?? n.id ?? `rule-${i}`)}</td>
                  <td className="mono">{String(n.type ?? n.kind ?? "—")}</td>
                  <td>
                    {n.action ? (
                      <Badge tone={n.action === "deny" ? "danger" : "ok"}>
                        {String(n.action)}
                      </Badge>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
