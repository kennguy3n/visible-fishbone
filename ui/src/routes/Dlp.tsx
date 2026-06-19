import { useRef, useState } from "react";
import {
  useDlpPolicies,
  useDlpTemplates,
  useApplyDlpTemplate,
  useClassifyText,
} from "@/api/manual/hooks";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { DataTable, type Column } from "@/components/DataTable";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { formatDateTime, formatPct } from "@/lib/format";
import type { DlpMatch, DlpPolicy, DlpTemplate } from "@/api/manual/types";
import { LaneB3Intl, useB3, type B3Key } from "./lane-b3-i18n";
import "./lane-b3.css";

export function Dlp() {
  return (
    <RequireTenant>
      {(tenantId) => (
        <LaneB3Intl>
          <DlpInner tenantId={tenantId} />
        </LaneB3Intl>
      )}
    </RequireTenant>
  );
}

// DLP rule actions map to a plain-language "what happens on a match" verb.
const ACTION_KEYS: Record<string, B3Key> = {
  block: "dlp.action.block",
  audit: "dlp.action.audit",
  log: "dlp.action.audit",
  redact: "dlp.action.redact",
  warn: "dlp.action.warn",
};

function DlpInner({ tenantId }: { tenantId: string }) {
  const t = useB3();
  const toast = useToast();
  const policies = useDlpPolicies(tenantId);
  const templates = useDlpTemplates(tenantId);
  const apply = useApplyDlpTemplate(tenantId);
  const classify = useClassifyText(tenantId);
  const [sample, setSample] = useState("");
  const [applyingId, setApplyingId] = useState<string | null>(null);
  const templatesRef = useRef<HTMLDivElement>(null);

  const actionLabel = (action: string) => {
    const key = ACTION_KEYS[action.toLowerCase()];
    return key ? t(key) : action;
  };

  const applyTemplate = (tpl: DlpTemplate) => {
    setApplyingId(tpl.id);
    apply.mutate(tpl.id, {
      onSuccess: () =>
        toast.success(
          t("dlp.templates.applied.title"),
          t("dlp.templates.applied.body", { name: tpl.name }),
        ),
      onError: () =>
        toast.error(t("dlp.templates.failed.title"), t("dlp.templates.failed.body")),
      onSettled: () => setApplyingId(null),
    });
  };

  const focusTemplates = () => {
    const root = templatesRef.current;
    root?.scrollIntoView({ block: "start" });
    root?.querySelector<HTMLButtonElement>("button")?.focus();
  };

  const matchCols: Column<DlpMatch>[] = [
    { header: t("dlp.sandbox.col.detector"), cell: (m) => m.rule_type },
    { header: t("dlp.sandbox.col.match"), cell: (m) => <span className="mono">{m.snippet || m.pattern}</span> },
    { header: t("dlp.sandbox.col.confidence"), cell: (m) => formatPct(m.confidence) },
  ];

  const policyCols: Column<DlpPolicy>[] = [
    { header: t("dlp.policies.col.name"), cell: (p) => p.name },
    {
      header: t("dlp.policies.col.detectors"),
      cell: (p) => t("dlp.policies.detectors", { count: p.rules?.length ?? 0 }),
    },
    {
      header: t("dlp.policies.col.action"),
      cell: (p) => (
        <Badge tone={p.action === "block" ? "danger" : "warn"}>{actionLabel(p.action)}</Badge>
      ),
    },
    {
      header: t("dlp.policies.col.enabled"),
      cell: (p) => (
        <Badge tone={p.enabled ? "ok" : "neutral"} dot>
          {t(p.enabled ? "dlp.policies.enabled" : "dlp.policies.disabled")}
        </Badge>
      ),
    },
    { header: t("dlp.policies.col.created"), cell: (p) => formatDateTime(p.created_at) },
  ];

  const result = classify.data;
  const matchCount = result?.matches.length ?? 0;

  return (
    <div className="lane-b3">
      <PageHeader title={t("dlp.title")} subtitle={t("dlp.subtitle")} />

      <div className="grid grid--2" style={{ marginBottom: 16 }}>
        <div ref={templatesRef}>
          <Card
            title={t("dlp.templates.title")}
            actions={
              <HelpTooltip title={t("dlp.templates.help.title")} align="right">
                {t("dlp.templates.help.body")}
              </HelpTooltip>
            }
          >
            <AsyncBoundary
              isLoading={templates.isLoading}
              error={templates.error}
              data={templates.data}
              onRetry={() => templates.refetch()}
              isEmpty={(d) => (d.items?.length ?? 0) === 0}
              empty={
                <EmptyState
                  illustration={<EmptyIllustration kind="policy" />}
                  title={t("dlp.templates.empty.title")}
                  description={t("dlp.templates.empty.desc")}
                />
              }
            >
              {(d) => (
                <div className="grid" style={{ gap: 10 }}>
                  {(d.items ?? []).map((tpl: DlpTemplate) => (
                    <div
                      key={tpl.id}
                      className="card"
                      style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 700 }}>{tpl.name}</div>
                        <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>
                          {tpl.description}
                        </div>
                        <div style={{ marginTop: 6 }}>
                          <Badge tone="info">{t("dlp.templates.taxonomy", { name: tpl.taxonomy })}</Badge>
                        </div>
                      </div>
                      <button
                        className="btn btn--primary btn--sm"
                        style={{ flex: "none" }}
                        disabled={applyingId !== null}
                        onClick={() => applyTemplate(tpl)}
                      >
                        {applyingId === tpl.id ? t("dlp.templates.applying") : t("dlp.templates.apply")}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </AsyncBoundary>
          </Card>
        </div>

        <Card
          title={t("dlp.sandbox.title")}
          actions={
            <HelpTooltip title={t("dlp.sandbox.help.title")} align="right">
              {t("dlp.sandbox.help.body")}
            </HelpTooltip>
          }
        >
          <p className="muted" style={{ marginTop: 0 }}>
            {t("dlp.sandbox.desc")}
          </p>
          <label className="field">
            <span className="sr-only">{t("dlp.sandbox.label")}</span>
            <textarea
              value={sample}
              onChange={(e) => setSample(e.target.value)}
              placeholder={t("dlp.sandbox.placeholder")}
              rows={4}
            />
          </label>
          <button
            className="btn btn--primary"
            style={{ marginTop: 10 }}
            disabled={!sample.trim() || classify.isPending}
            onClick={() => classify.mutate(sample)}
          >
            {classify.isPending ? t("dlp.sandbox.running") : t("dlp.sandbox.run")}
          </button>
          {result && (
            <div style={{ marginTop: 12 }} aria-live="polite">
              <Badge tone={matchCount === 0 ? "ok" : result.action === "block" ? "danger" : "warn"} dot>
                {matchCount === 0
                  ? t("dlp.sandbox.result.clean")
                  : t("dlp.sandbox.result.flagged", {
                      action: actionLabel(result.action),
                      count: matchCount,
                    })}
              </Badge>{" "}
              {matchCount > 0 && (
                <span className="muted">{t("b3.confidence", { pct: formatPct(result.confidence) })}</span>
              )}
              {matchCount > 0 && (
                <div style={{ marginTop: 10 }}>
                  <DataTable
                    columns={matchCols}
                    rows={result.matches}
                    rowKey={(m, i) => `${m.pattern}-${m.offset}-${i}`}
                  />
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title={t("dlp.policies.title")}>
        <AsyncBoundary
          isLoading={policies.isLoading}
          error={policies.error}
          data={policies.data}
          onRetry={() => policies.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("dlp.policies.empty.title")}
              description={t("dlp.policies.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={focusTemplates}>
                  {t("dlp.templates.title")}
                </button>
              }
            />
          }
        >
          {(d) => <DataTable columns={policyCols} rows={d.items ?? []} rowKey={(p) => p.id} />}
        </AsyncBoundary>
      </Card>
    </div>
  );
}
