import { useMemo, useState } from "react";
import { PageHeader, Card, Badge, Spinner } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
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

// Cross-tenant roll-out: render one baseline (industry + country) and push it
// to many tenants at once. The operator picks the baseline, multi-selects the
// target tenants, previews the per-tenant diff, then executes — with a
// per-tenant result and rollback of any tenant whose apply fails.
export function PolicyRollout() {
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
        : Object.fromEntries(tenants.map((t) => [t.id, true])),
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
            "Preview failed",
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
              "Roll-out cancelled",
              `${result.applied} applied · ${result.cancelled} not attempted`,
            );
          } else if (result.failed > 0) {
            toast.error(
              "Roll-out completed with failures",
              `${result.applied} applied · ${result.failed} failed (rolled back)`,
            );
          } else {
            toast.success(
              "Roll-out complete",
              `${result.applied} applied · ${result.unchanged} unchanged`,
            );
          }
        },
        onError: (e) =>
          toast.error(
            "Roll-out failed",
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  }

  const diffColumns: Column<RolloutTargetDiff>[] = [
    {
      header: "Tenant",
      cell: (row) => {
        const t = tenants.find((x) => x.id === row.tenant_id);
        return t ? t.name : <span className="mono">{shortId(row.tenant_id)}</span>;
      },
    },
    {
      header: "Change",
      cell: (row) => (
        <Badge tone={ACTION_TONE[row.action]}>{titleCase(row.action)}</Badge>
      ),
    },
    {
      header: "Current baseline",
      cell: (row) =>
        row.current ? (
          <span>
            {titleCase(row.current.industry)} · {row.current.country} ·{" "}
            <span className="mono">{shortId(row.current.graph_hash)}</span>
          </span>
        ) : (
          <span style={{ color: "var(--text-dim)" }}>None</span>
        ),
    },
  ];

  const outcomeColumns: Column<RolloutOutcome>[] = [
    {
      header: "Tenant",
      cell: (row) => {
        const t = tenants.find((x) => x.id === row.tenant_id);
        return t ? t.name : <span className="mono">{shortId(row.tenant_id)}</span>;
      },
    },
    {
      header: "Result",
      cell: (row) => (
        <Badge tone={STATUS_TONE[row.status]}>{titleCase(row.status)}</Badge>
      ),
    },
    {
      header: "Detail",
      cell: (row) => {
        if (row.status === "failed") {
          return (
            <span style={{ color: "var(--text-dim)" }}>
              {row.error ?? "apply failed"}
              {row.rolled_back ? " · rolled back" : ""}
            </span>
          );
        }
        if (row.status === "cancelled") {
          return (
            <span style={{ color: "var(--text-dim)" }}>
              {row.error ?? "cancelled"} · not attempted
            </span>
          );
        }
        return <span className="mono">{shortId(row.graph_hash)}</span>;
      },
    },
  ];

  return (
    <div>
      <PageHeader
        title="Cross-tenant roll-out"
        subtitle="Apply one security baseline to many tenants at once — preview the per-tenant change before you commit."
      />

      <Card title="1 · Choose the baseline">
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <label className="field" style={{ minWidth: 220 }}>
            <span>Industry</span>
            <select
              value={industry}
              disabled={options.isLoading}
              onChange={(e) => {
                setIndustry(e.target.value);
                preview.reset();
                execute.reset();
              }}
            >
              <option value="">Select an industry…</option>
              {(options.data?.industries ?? []).map((i) => (
                <option key={i.industry} value={i.industry}>
                  {i.name}
                </option>
              ))}
            </select>
          </label>

          <label className="field" style={{ minWidth: 220 }}>
            <span>Country / data residency</span>
            <select
              value={country}
              disabled={options.isLoading}
              onChange={(e) => {
                setCountry(e.target.value);
                preview.reset();
                execute.reset();
              }}
            >
              <option value="">Select a country…</option>
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
            Compliance regime: <Badge tone="info">{regimeForCountry[country]}</Badge>
          </p>
        )}
      </Card>

      <Card
        title="2 · Select target tenants"
        actions={
          tenants.length > 0 ? (
            <button className="btn btn--sm" onClick={toggleAll}>
              {selectedIds.length === tenants.length ? "Clear all" : "Select all"}
            </button>
          ) : undefined
        }
      >
        {tenantsLoading ? (
          <div className="skeleton" style={{ height: 96 }} />
        ) : tenants.length === 0 ? (
          <p style={{ color: "var(--text-dim)" }}>No tenants available.</p>
        ) : (
          <div className="choice-grid">
            {tenants.map((t) => (
              <label
                key={t.id}
                className={`choice${selected[t.id] ? " choice--selected" : ""}`}
                style={{ cursor: "pointer" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input
                    type="checkbox"
                    style={{ width: 16 }}
                    checked={!!selected[t.id]}
                    onChange={() => toggle(t.id)}
                  />
                  <span className="choice__name">{t.name}</span>
                </div>
                <div className="choice__desc">
                  <span className="mono">{t.slug}</span>
                  {t.region ? ` · ${t.region}` : ""}
                </div>
              </label>
            ))}
          </div>
        )}
        <p style={{ marginTop: 10, color: "var(--text-dim)" }}>
          {selectedIds.length} tenant{selectedIds.length === 1 ? "" : "s"} selected
        </p>
      </Card>

      <Card title="3 · Preview &amp; execute">
        <div style={{ display: "flex", gap: 10 }}>
          <button
            className="btn"
            disabled={!ready || preview.isPending}
            onClick={runPreview}
          >
            {preview.isPending ? <Spinner /> : "Preview diff"}
          </button>
          <button
            className="btn btn--primary"
            disabled={!previewed || execute.isPending}
            title={
              !previewed ? "Preview the diff before applying" : undefined
            }
            onClick={runExecute}
          >
            {execute.isPending ? <Spinner /> : `Apply to ${selectedIds.length} tenant${selectedIds.length === 1 ? "" : "s"}`}
          </button>
        </div>
        {ready && !previewed && (
          <p style={{ marginTop: 8, color: "var(--text-dim)" }}>
            Preview the per-tenant diff before applying.
          </p>
        )}

        {preview.data && !execute.data && (
          <div style={{ marginTop: 16 }}>
            <h3 className="card__title" style={{ marginBottom: 8 }}>
              Preview — {titleCase(preview.data.selection.industry)} ·{" "}
              {preview.data.selection.country} ({preview.data.regime})
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
              Result — {execute.data.applied} applied · {execute.data.unchanged}{" "}
              unchanged · {execute.data.failed} failed
              {execute.data.cancelled > 0
                ? ` · ${execute.data.cancelled} cancelled`
                : ""}
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
