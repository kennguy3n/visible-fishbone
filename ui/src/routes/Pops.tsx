import { useListPoPs, useGetPoPHealth } from "@/api/generated/endpoints/pops/pops";
import type { PoP } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  StatusBadge,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { titleCase } from "@/lib/format";
import { LaneB2Intl, useT } from "./lane-b2/i18n";

export function Pops() {
  return (
    <LaneB2Intl>
      <PopsInner />
    </LaneB2Intl>
  );
}

function PopsInner() {
  const t = useT();
  const list = useListPoPs();

  return (
    <>
      <PageHeader title={t("pops.title")} subtitle={t("pops.subtitle")} />
      <Card
        title={t("pops.title")}
        actions={
          <HelpTooltip title={t("pops.help.title")} align="right">
            {t("pops.help.body")}
          </HelpTooltip>
        }
      >
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          onRetry={() => list.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="inbox" />}
              title={t("pops.empty.title")}
              description={t("pops.empty.body")}
            />
          }
        >
          {(d) => (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>{t("pops.col.region")}</th>
                    <th>{t("pops.col.provider")}</th>
                    <th>{t("pops.col.anycast")}</th>
                    <th>{t("pops.col.tier")}</th>
                    <th>{t("pops.col.status")}</th>
                    <th>{t("pops.col.health")}</th>
                    <th>{t("pops.col.load")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(d.items ?? []).map((p) => (
                    <PopRow key={p.id} pop={p} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncBoundary>
      </Card>
    </>
  );
}

function PopRow({ pop }: { pop: PoP }) {
  const t = useT();
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
          <span className="muted">{t("pops.health.checking")}</span>
        ) : h ? (
          <StatusBadge
            status={h.overloaded ? "overloaded" : h.healthy ? "healthy" : "unhealthy"}
          />
        ) : (
          <span className="muted">{t("pops.health.unknown")}</span>
        )}
      </td>
      <td className="mono">
        {h?.health
          ? t("pops.load.value", {
              cpu: h.health.cpu_pct.toFixed(0),
              conn: h.health.active_connections,
            })
          : t("pops.load.none")}
      </td>
    </tr>
  );
}
