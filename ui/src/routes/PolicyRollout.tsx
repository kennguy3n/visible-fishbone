import { useMemo, useState } from "react";
import { PageHeader, Card, Badge, Spinner } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useTenant } from "@/lib/tenant-context";
import { useToast } from "@/components/Toast";
import { titleCase, shortId, type Tone } from "@/lib/format";
import {
  usePolicyTemplateOptions,
  usePreviewPolicyRollout,
  useExecutePolicyRollout,
} from "@/api/manual/hooks";
import type {
  RolloutTargetDiff,
  RolloutOutcome,
  RolloutAction,
  RolloutStatus,
} from "@/api/manual/types";
import { LaneB2Intl, useT, type LaneB2Key } from "./lane-b2/i18n";

const ACTION_TONE: Record<RolloutAction, Tone> = {
  create: "info",
  update: "warn",
  noop: "neutral",
};

const STATUS_TONE: Record<RolloutStatus, Tone> = {
  applied: "ok",
  unchanged: "neutral",
  failed: "danger",
  cancelled: "warn",
};

const ACTION_LABEL: Record<RolloutAction, LaneB2Key> = {
  create: "rollout.action.create",
  update: "rollout.action.update",
  noop: "rollout.action.noop",
};

const STATUS_LABEL: Record<RolloutStatus, LaneB2Key> = {
  applied: "rollout.status.applied",
  unchanged: "rollout.status.unchanged",
  failed: "rollout.status.failed",
  cancelled: "rollout.status.cancelled",
};

// Cross-tenant roll-out: render one baseline (industry + country) and push it
// to many tenants at once. The operator picks the baseline, multi-selects the
// target tenants, previews the per-tenant diff, then executes — with a
// per-tenant result and rollback of any tenant whose apply fails.
export function PolicyRollout() {
  return (
    <LaneB2Intl>
      <PolicyRolloutInner />
    </LaneB2Intl>
  );
}

function PolicyRolloutInner() {
  const t = useT();
  const { tenants, isLoading: tenantsLoading } = useTenant();
  const toast = useToast();
  const options = usePolicyTemplateOptions();

  const [industry, setIndustry] = useState("");
  const [country, setCountry] = useState("");
  const [selected, setSelected] = useState<Record<string, boolean>>({});

  const preview = usePreviewPolicyRollout();
  const execute = useExecutePolicyRollout();

  const selectedIds = useMemo(
    () => Object.keys(selected).filter((id) => selected[id]),
    [selected],
  );
  const ready = !!industry && !!country && selectedIds.length > 0;
  // Execute is gated on a fresh preview for the current selection. Any
  // baseline or target-set change calls preview.reset() below, so a
  // surviving preview.data is guaranteed to match what will be applied.
  const previewed = ready && preview.isSuccess;

  const regimeForCountry = useMemo(() => {
    const map: Record<string, string> = {};
    for (const c of options.data?.countries ?? []) map[c.country] = c.regime;
    return map;
  }, [options.data]);

  function toggle(id: string) {
    setSelected((prev) => ({ ...prev, [id]: !prev[id] }));
    // A changed target set invalidates an existing preview/result.
    preview.reset();
    execute.reset();
  }

  function toggleAll() {
    const allSelected = tenants.length > 0 && selectedIds.length === tenants.length;
    setSelected(
      allSelected
        ? {}
        : Object.fromEntries(tenants.map((ten) => [ten.id, true])),
    );
    preview.reset();
    execute.reset();
  }

  function runPreview() {
    preview.mutate(
      { industry, country, tenant_ids: selectedIds },
      {
        onError: (e) =>
          toast.error(
            t("rollout.toast.preview.err"),
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  }

  function runExecute() {
    execute.mutate(
      { industry, country, tenant_ids: selectedIds },
      {
        onSuccess: (result) => {
          if (result.cancelled > 0) {
            toast.error(
              t("rollout.toast.cancelled.title"),
              t("rollout.toast.cancelled.body", {
                applied: result.applied,
                cancelled: result.cancelled,
              }),
            );
          } else if (result.failed > 0) {
            toast.error(
              t("rollout.toast.failures.title"),
              t("rollout.toast.failures.body", {
                applied: result.applied,
                failed: result.failed,
              }),
            );
          } else {
            toast.success(
              t("rollout.toast.complete.title"),
              t("rollout.toast.complete.body", {
                applied: result.applied,
                unchanged: result.unchanged,
              }),
            );
          }
        },
        onError: (e) =>
          toast.error(
            t("rollout.toast.err"),
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  }

  const diffColumns: Column<RolloutTargetDiff>[] = [
    {
      header: t("rollout.col.tenant"),
      cell: (row) => {
        const tenant = tenants.find((x) => x.id === row.tenant_id);
        return tenant ? (
          tenant.name
        ) : (
          <span className="mono">{shortId(row.tenant_id)}</span>
        );
      },
    },
    {
      header: t("rollout.col.change"),
      cell: (row) => (
        <Badge tone={ACTION_TONE[row.action]}>{t(ACTION_LABEL[row.action])}</Badge>
      ),
    },
    {
      header: t("rollout.col.currentBaseline"),
      cell: (row) =>
        row.current ? (
          <span>
            {titleCase(row.current.industry)} · {row.current.country} ·{" "}
            <span className="mono">{shortId(row.current.graph_hash)}</span>
          </span>
        ) : (
          <span style={{ color: "var(--text-dim)" }}>
            {t("rollout.current.none")}
          </span>
        ),
    },
  ];

  const outcomeColumns: Column<RolloutOutcome>[] = [
    {
      header: t("rollout.col.tenant"),
      cell: (row) => {
        const tenant = tenants.find((x) => x.id === row.tenant_id);
        return tenant ? (
          tenant.name
        ) : (
          <span className="mono">{shortId(row.tenant_id)}</span>
        );
      },
    },
    {
      header: t("rollout.col.result"),
      cell: (row) => (
        <Badge tone={STATUS_TONE[row.status]}>{t(STATUS_LABEL[row.status])}</Badge>
      ),
    },
    {
      header: t("rollout.col.detail"),
      cell: (row) => {
        if (row.status === "failed") {
          const detail = row.error ?? t("rollout.detail.failed.default");
          return (
            <span style={{ color: "var(--text-dim)" }}>
              {row.rolled_back
                ? t("rollout.detail.failed", { error: detail })
                : t("rollout.detail.failed.norollback", { error: detail })}
            </span>
          );
        }
        if (row.status === "cancelled") {
          return (
            <span style={{ color: "var(--text-dim)" }}>
              {row.error
                ? t("rollout.detail.cancelled", { error: row.error })
                : t("rollout.detail.cancelled.default")}
            </span>
          );
        }
        return <span className="mono">{shortId(row.graph_hash)}</span>;
      },
    },
  ];

  return (
    <div>
      <PageHeader title={t("rollout.title")} subtitle={t("rollout.subtitle")} />

      <Card
        title={t("rollout.step1.title")}
        actions={
          <HelpTooltip title={t("rollout.step1.help.title")} align="right">
            {t("rollout.step1.help.body")}
          </HelpTooltip>
        }
      >
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <label className="field" style={{ minWidth: 220 }}>
            <span>{t("rollout.industry")}</span>
            <select
              value={industry}
              disabled={options.isLoading}
              onChange={(e) => {
                setIndustry(e.target.value);
                preview.reset();
                execute.reset();
              }}
            >
              <option value="">{t("rollout.industry.placeholder")}</option>
              {(options.data?.industries ?? []).map((i) => (
                <option key={i.industry} value={i.industry}>
                  {i.name}
                </option>
              ))}
            </select>
          </label>

          <label className="field" style={{ minWidth: 220 }}>
            <span>{t("rollout.country")}</span>
            <select
              value={country}
              disabled={options.isLoading}
              onChange={(e) => {
                setCountry(e.target.value);
                preview.reset();
                execute.reset();
              }}
            >
              <option value="">{t("rollout.country.placeholder")}</option>
              {(options.data?.countries ?? []).map((c) => (
                <option key={c.country} value={c.country}>
                  {c.country} — {c.regime}
                </option>
              ))}
            </select>
          </label>
        </div>
        {country && regimeForCountry[country] && (
          <p style={{ marginTop: 8, color: "var(--text-dim)" }}>
            {t("rollout.regime")}:{" "}
            <Badge tone="info">{regimeForCountry[country]}</Badge>
          </p>
        )}
      </Card>

      <Card
        title={t("rollout.step2.title")}
        actions={
          tenants.length > 0 ? (
            <button className="btn btn--sm" onClick={toggleAll}>
              {selectedIds.length === tenants.length
                ? t("rollout.clearAll")
                : t("rollout.selectAll")}
            </button>
          ) : undefined
        }
      >
        {tenantsLoading ? (
          <div className="skeleton" style={{ height: 96 }} />
        ) : tenants.length === 0 ? (
          <p style={{ color: "var(--text-dim)" }}>{t("rollout.noTenants")}</p>
        ) : (
          <div className="choice-grid">
            {tenants.map((tenant) => (
              <label
                key={tenant.id}
                className={`choice${selected[tenant.id] ? " choice--selected" : ""}`}
                style={{ cursor: "pointer" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input
                    type="checkbox"
                    style={{ width: 16 }}
                    checked={!!selected[tenant.id]}
                    onChange={() => toggle(tenant.id)}
                  />
                  <span className="choice__name">{tenant.name}</span>
                </div>
                <div className="choice__desc">
                  <span className="mono">{tenant.slug}</span>
                  {tenant.region ? ` · ${tenant.region}` : ""}
                </div>
              </label>
            ))}
          </div>
        )}
        <p style={{ marginTop: 10, color: "var(--text-dim)" }}>
          {t("rollout.selectedCount", { count: selectedIds.length })}
        </p>
      </Card>

      <Card title={t("rollout.step3.title")}>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            className="btn"
            disabled={!ready || preview.isPending}
            onClick={runPreview}
          >
            {preview.isPending ? <Spinner /> : t("rollout.previewBtn")}
          </button>
          <button
            className="btn btn--primary"
            disabled={!previewed || execute.isPending}
            title={!previewed ? t("rollout.previewFirst.tip") : undefined}
            onClick={runExecute}
          >
            {execute.isPending ? (
              <Spinner />
            ) : (
              t("rollout.applyBtn", { count: selectedIds.length })
            )}
          </button>
        </div>
        {ready && !previewed && (
          <p style={{ marginTop: 8, color: "var(--text-dim)" }}>
            {t("rollout.previewFirst")}
          </p>
        )}

        {preview.data && !execute.data && (
          <div style={{ marginTop: 16 }}>
            <h3 className="card__title" style={{ marginBottom: 8 }}>
              {t("rollout.preview.heading", {
                industry: titleCase(preview.data.selection.industry),
                country: preview.data.selection.country,
                regime: preview.data.regime,
              })}
            </h3>
            <DataTable
              columns={diffColumns}
              rows={preview.data.targets}
              rowKey={(r) => r.tenant_id}
            />
          </div>
        )}

        {execute.data && (
          <div style={{ marginTop: 16 }}>
            <h3 className="card__title" style={{ marginBottom: 8 }}>
              {execute.data.cancelled > 0
                ? t("rollout.result.heading.cancelled", {
                    applied: execute.data.applied,
                    unchanged: execute.data.unchanged,
                    failed: execute.data.failed,
                    cancelled: execute.data.cancelled,
                  })
                : t("rollout.result.heading", {
                    applied: execute.data.applied,
                    unchanged: execute.data.unchanged,
                    failed: execute.data.failed,
                  })}
            </h3>
            <DataTable
              columns={outcomeColumns}
              rows={execute.data.outcomes}
              rowKey={(r) => r.tenant_id}
            />
          </div>
        )}
      </Card>
    </div>
  );
}
