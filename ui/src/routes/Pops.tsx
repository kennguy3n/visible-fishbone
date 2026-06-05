import { useListPoPs, useGetPoPHealth } from "@/api/generated/endpoints/pops/pops";
import type { PoP } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge, Badge } from "@/components/ui";
import { titleCase } from "@/lib/format";

export function Pops() {
  const list = useListPoPs();

  return (
    <>
      <PageHeader
        title="Points of presence"
        subtitle="Global edge PoP fleet, capacity tiers and live health beacons."
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={<p className="muted">No PoPs registered.</p>}
        >
          {(d) => (
            <table className="data">
              <thead>
                <tr>
                  <th>Region</th>
                  <th>Provider</th>
                  <th>Anycast IP</th>
                  <th>Tier</th>
                  <th>Enabled</th>
                  <th>Health</th>
                  <th>Load</th>
                </tr>
              </thead>
              <tbody>
                {(d.items ?? []).map((p) => (
                  <PopRow key={p.id} pop={p} />
                ))}
              </tbody>
            </table>
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}

function PopRow({ pop }: { pop: PoP }) {
  const health = useGetPoPHealth(pop.id, { query: { retry: false } });
  const h = health.data;
  return (
    <tr>
      <td>{pop.region}</td>
      <td>{titleCase(pop.provider)}</td>
      <td className="mono">{pop.anycast_ip}</td>
      <td>
        <Badge tone="info">{titleCase(pop.capacity_tier)}</Badge>
      </td>
      <td>
        <StatusBadge status={pop.enabled ? "enabled" : "disabled"} />
      </td>
      <td>
        {health.isLoading ? (
          "…"
        ) : h ? (
          <StatusBadge
            status={h.overloaded ? "overloaded" : h.healthy ? "healthy" : "unhealthy"}
          />
        ) : (
          <span className="muted">unknown</span>
        )}
      </td>
      <td className="mono">
        {h?.health
          ? `${h.health.cpu_pct.toFixed(0)}% cpu · ${h.health.active_connections} conn`
          : "—"}
      </td>
    </tr>
  );
}
