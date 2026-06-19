import { useEffect, useRef, useState } from "react";
import {
  useDlpReviewQueue,
  useDlpReviewEvent,
  useDlpReviewDigest,
  useApproveDlpReview,
  useBlockDlpReview,
  useDismissDlpReview,
} from "@/api/manual/hooks";
import {
  PageHeader,
  Card,
  Stat,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import {
  formatDateTime,
  formatRelative,
  formatPct,
  titleCase,
  statusTone,
  type Tone,
} from "@/lib/format";
import type {
  DlpReviewEvent,
  DlpReviewState,
  DlpSeverity,
  DlpFindingKind,
} from "@/api/manual/types";
import { LaneB3Intl, useB3, type B3Key } from "./lane-b3-i18n";
import "./lane-b3.css";

export function DlpReviewQueue() {
  return (
    <RequireTenant>
      {(tenantId) => (
        <LaneB3Intl>
          <DlpReviewQueueInner tenantId={tenantId} />
        </LaneB3Intl>
      )}
    </RequireTenant>
  );
}

const STATE_FILTERS: (DlpReviewState | "all")[] = [
  "all",
  "pending",
  "approved",
  "blocked",
  "dismissed",
];

// The list endpoint returns the most recent events (created_at DESC) up to this
// limit and exposes no pagination cursor, so we request an explicit page size
// and warn the operator when the result fills it. 200 matches MaxPageLimit.
const QUEUE_PAGE_LIMIT = 200;

// Digest windows as Go durations the backend's `?window=` parser understands.
const DIGEST_WINDOWS: { label: string; value: string }[] = [
  { label: "24h", value: "24h" },
  { label: "7d", value: "168h" },
  { label: "30d", value: "720h" },
  { label: "90d", value: "2160h" },
];

type Decision = "approve" | "block" | "dismiss";

// Each decision records a terminal state; map both to their localized label.
const DECISION: Record<Decision, { state: DlpReviewState; toast: B3Key }> = {
  approve: { state: "approved", toast: "drq.toast.approved" },
  block: { state: "blocked", toast: "drq.toast.blocked" },
  dismiss: { state: "dismissed", toast: "drq.toast.dismissed" },
};

const SEVERITY_KEYS: Record<DlpSeverity, B3Key> = {
  critical: "drq.sev.critical",
  high: "drq.sev.high",
  medium: "drq.sev.medium",
  low: "drq.sev.low",
};

const STATE_KEYS: Record<DlpReviewState, B3Key> = {
  pending: "drq.state.pending",
  approved: "drq.state.approved",
  blocked: "drq.state.blocked",
  dismissed: "drq.state.dismissed",
};

const FINDING_KIND_KEYS: Record<DlpFindingKind, B3Key> = {
  pii: "drq.finding.pii",
  secret: "drq.finding.secret",
  confidential: "drq.finding.confidential",
};

// `signal` is an open-ended code from the backend taxonomy. Map the ones we
// know to plain language; humanize anything unmapped so a raw token like
// "ai_app_exfiltration" never reaches the operator.
const SIGNAL_KEYS: Record<string, B3Key> = {
  ai_app_exfiltration: "drq.signal.aiAppExfiltration",
  bulk_download: "drq.signal.bulkDownload",
};

const SIGNAL_ACRONYMS = new Set(["ai", "pii", "ssn", "url", "api", "dlp"]);

type B3Translate = ReturnType<typeof useB3>;

function humanizeSignal(signal: string): string {
  const words = signal
    .split(/[_-]+/)
    .filter(Boolean)
    .map((w) => (SIGNAL_ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w.toLowerCase()));
  if (words.length === 0) return signal;
  const phrase = words.join(" ");
  return phrase.charAt(0).toUpperCase() + phrase.slice(1);
}

function signalLabel(t: B3Translate, signal: string): string {
  const key = SIGNAL_KEYS[signal];
  return key ? t(key) : humanizeSignal(signal);
}

function kindLabel(t: B3Translate, kind: DlpFindingKind): string {
  const key = FINDING_KIND_KEYS[kind];
  return key ? t(key) : titleCase(kind);
}

function severityTone(sev: DlpSeverity): Tone {
  switch (sev) {
    case "critical":
      return "danger";
    case "high":
      return "warn";
    case "medium":
      return "info";
    case "low":
      return "neutral";
    default:
      return "neutral";
  }
}

// "dismissed" is a noise-disposal action, so render its state badge muted.
function reviewStateTone(state: DlpReviewState): Tone {
  return state === "dismissed" ? "neutral" : statusTone(state);
}

function ReviewStateBadge({ state }: { state: DlpReviewState }) {
  const t = useB3();
  const key = STATE_KEYS[state];
  return (
    <Badge tone={reviewStateTone(state)} dot>
      {key ? t(key) : titleCase(state)}
    </Badge>
  );
}

function DlpReviewQueueInner({ tenantId }: { tenantId: string }) {
  const t = useB3();
  const toast = useToast();
  const [stateFilter, setStateFilter] = useState<DlpReviewState | "all">("pending");
  const [digestWindow, setDigestWindow] = useState<string>(DIGEST_WINDOWS[0].value);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Track in-flight rows as a set so overlapping inline decisions each keep
  // their own busy state; a single value would clear a still-pending row's
  // disabled state as soon as any other row settled.
  const [busyIds, setBusyIds] = useState<ReadonlySet<string>>(() => new Set());

  const queue = useDlpReviewQueue(
    tenantId,
    stateFilter === "all" ? undefined : stateFilter,
    QUEUE_PAGE_LIMIT,
  );
  const digest = useDlpReviewDigest(tenantId, digestWindow);
  const approve = useApproveDlpReview(tenantId);
  const block = useBlockDlpReview(tenantId);
  const dismiss = useDismissDlpReview(tenantId);

  const mutationFor = (d: Decision) =>
    d === "approve" ? approve : d === "block" ? block : dismiss;

  const decide = (id: string, d: Decision) => {
    setBusyIds((prev) => new Set(prev).add(id));
    mutationFor(d).mutate(id, {
      onSuccess: () => toast.success(t(DECISION[d].toast), t("drq.toast.recorded")),
      onError: () => toast.error(t("drq.toast.failed.title"), t("drq.toast.failed.body")),
      onSettled: () =>
        setBusyIds((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        }),
    });
  };

  const sevLabel = (s: DlpSeverity) => (SEVERITY_KEYS[s] ? t(SEVERITY_KEYS[s]) : titleCase(s));

  const columns: Column<DlpReviewEvent>[] = [
    {
      header: t("drq.col.destination"),
      cell: (e) =>
        e.destination_app === "suspected_ai_app" ? (
          <Badge tone="warn">{t("drq.suspectedAi")}</Badge>
        ) : (
          <span className="mono">{e.destination_app}</span>
        ),
    },
    {
      header: t("drq.col.signal"),
      cell: (e) => <Badge tone="info">{signalLabel(t, e.signal)}</Badge>,
    },
    {
      header: t("drq.col.severity"),
      cell: (e) => <Badge tone={severityTone(e.severity)}>{sevLabel(e.severity)}</Badge>,
    },
    { header: t("drq.col.confidence"), cell: (e) => formatPct(e.confidence) },
    { header: t("drq.col.findings"), cell: (e) => <FindingKinds event={e} sevLabel={sevLabel} /> },
    { header: t("drq.col.state"), cell: (e) => <ReviewStateBadge state={e.state} /> },
    { header: t("drq.col.created"), cell: (e) => formatRelative(e.created_at) },
    {
      header: t("drq.col.decision"),
      cell: (e) => (
        <div className="b3-actions" onClick={(ev) => ev.stopPropagation()}>
          {e.state === "pending" ? (
            <>
              <button
                className="btn btn--sm b3-approve"
                disabled={busyIds.has(e.id)}
                onClick={() => decide(e.id, "approve")}
              >
                {t("drq.action.approve")}
              </button>
              <button
                className="btn btn--sm btn--danger"
                disabled={busyIds.has(e.id)}
                onClick={() => decide(e.id, "block")}
              >
                {t("drq.action.block")}
              </button>
              <button
                className="btn btn--sm btn--ghost"
                disabled={busyIds.has(e.id)}
                onClick={() => decide(e.id, "dismiss")}
              >
                {t("drq.action.dismiss")}
              </button>
            </>
          ) : (
            <button className="btn btn--sm" onClick={() => setSelectedId(e.id)}>
              {t("drq.action.details")}
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="lane-b3">
      <PageHeader
        title={t("drq.title")}
        subtitle={t("drq.subtitle")}
        actions={
          <HelpTooltip title={t("drq.help.title")} align="right">
            {t("drq.help.body")}
          </HelpTooltip>
        }
      />

      <DigestCard
        isLoading={digest.isLoading}
        error={digest.error}
        digest={digest.data}
        onRetry={() => digest.refetch()}
        selectedWindow={digestWindow}
        onWindowChange={setDigestWindow}
        sevLabel={sevLabel}
      />

      <Card title={t("drq.queue.title")}>
        <div className="filter-bar" style={{ marginBottom: 12 }}>
          <div className="pill-tabs" role="tablist" aria-label={t("drq.filter.label")}>
            {STATE_FILTERS.map((s) => (
              <button
                key={s}
                role="tab"
                aria-selected={stateFilter === s}
                className={stateFilter === s ? "active" : ""}
                onClick={() => setStateFilter(s)}
              >
                {s === "all" ? t("drq.filter.all") : t(STATE_KEYS[s])}
              </button>
            ))}
          </div>
        </div>

        <AsyncBoundary
          isLoading={queue.isLoading}
          error={queue.error}
          data={queue.data}
          onRetry={() => queue.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t(stateFilter === "pending" ? "drq.empty.pending.title" : "drq.empty.other.title")}
              description={t(stateFilter === "pending" ? "drq.empty.pending.desc" : "drq.empty.other.desc")}
            />
          }
        >
          {(d) => (
            <>
              <p className="b3-hint">
                <span className="b3-hint__icon" aria-hidden>⌨</span>
                <span>{t("drq.queue.hint")}</span>
              </p>
              {(d.items?.length ?? 0) >= QUEUE_PAGE_LIMIT && (
                <div className="muted" style={{ marginBottom: 8, fontSize: 12.5 }}>
                  {t("drq.queue.capped", { limit: QUEUE_PAGE_LIMIT })}
                </div>
              )}
              <DataTable
                columns={columns}
                rows={d.items ?? []}
                rowKey={(e) => e.id}
                onRowClick={(e) => setSelectedId(e.id)}
              />
            </>
          )}
        </AsyncBoundary>
      </Card>

      {selectedId && (
        <ReviewDetail
          tenantId={tenantId}
          id={selectedId}
          onClose={() => setSelectedId(null)}
          sevLabel={sevLabel}
        />
      )}
    </div>
  );
}

function FindingKinds({
  event,
  sevLabel,
}: {
  event: DlpReviewEvent;
  sevLabel: (s: DlpSeverity) => string;
}) {
  const t = useB3();
  const findings = event.findings ?? [];
  if (findings.length === 0) return <span className="muted">—</span>;
  return (
    <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
      {findings.map((f, i) => (
        <span key={`${f.kind}-${f.label}-${i}`} title={sevLabel(f.severity)}>
          <Badge tone={severityTone(f.severity)}>
            {kindLabel(t, f.kind)} ×{f.count}
          </Badge>
        </span>
      ))}
    </span>
  );
}

function DigestCard({
  isLoading,
  error,
  digest,
  onRetry,
  selectedWindow,
  onWindowChange,
  sevLabel,
}: {
  isLoading: boolean;
  error: unknown;
  digest: ReturnType<typeof useDlpReviewDigest>["data"];
  onRetry: () => void;
  selectedWindow: string;
  onWindowChange: (w: string) => void;
  sevLabel: (s: DlpSeverity) => string;
}) {
  const t = useB3();
  return (
    <Card
      title={t("drq.digest.title")}
      subtitle={t("drq.digest.subtitle")}
      actions={
        <div className="pill-tabs" role="tablist" aria-label={t("drq.digest.window.label")}>
          {DIGEST_WINDOWS.map((w) => (
            <button
              key={w.value}
              role="tab"
              aria-selected={selectedWindow === w.value}
              className={selectedWindow === w.value ? "active" : ""}
              onClick={() => onWindowChange(w.value)}
            >
              {w.label}
            </button>
          ))}
        </div>
      }
    >
      <AsyncBoundary isLoading={isLoading} error={error} data={digest} onRetry={onRetry}>
        {(d) => (
          <>
            <div className="grid grid--stats" style={{ marginBottom: 12 }}>
              <Stat label={t("drq.digest.total")} value={d.total} />
              <Stat label={t("drq.digest.pending")} value={d.pending} />
              <Stat label={t("drq.digest.apps")} value={Object.keys(d.pending_by_app).length} />
              <Stat label={t("drq.digest.since")} value={formatDateTime(d.since)} />
            </div>
            <div className="grid grid--2">
              <CountBreakdown
                title={t("drq.digest.bySeverity")}
                counts={d.by_severity}
                tone={(k) => severityTone(k as DlpSeverity)}
                label={(k) => sevLabel(k as DlpSeverity)}
              />
              <CountBreakdown
                title={t("drq.digest.byState")}
                counts={d.by_state}
                label={(k) => (STATE_KEYS[k as DlpReviewState] ? t(STATE_KEYS[k as DlpReviewState]) : titleCase(k))}
              />
            </div>
            {Object.keys(d.pending_by_app).length > 0 && (
              <div style={{ marginTop: 12 }}>
                <CountBreakdown
                  title={t("drq.digest.byApp")}
                  counts={d.pending_by_app}
                  tone={() => "warn"}
                  mono
                />
              </div>
            )}
          </>
        )}
      </AsyncBoundary>
    </Card>
  );
}

function CountBreakdown({
  title,
  counts,
  tone,
  label,
  mono = false,
}: {
  title: string;
  counts: Record<string, number>;
  tone?: (key: string) => Tone;
  label?: (key: string) => string;
  mono?: boolean;
}) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return (
    <div>
      <div className="muted" style={{ fontSize: 12.5, marginBottom: 6 }}>
        {title}
      </div>
      {entries.length === 0 ? (
        <span className="muted">—</span>
      ) : (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {entries.map(([key, count]) => (
            <Badge key={key} tone={tone ? tone(key) : "neutral"}>
              <span className={mono ? "mono" : undefined}>{label ? label(key) : titleCase(key)}</span>{" "}
              {count}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function ReviewDetail({
  tenantId,
  id,
  onClose,
  sevLabel,
}: {
  tenantId: string;
  id: string;
  onClose: () => void;
  sevLabel: (s: DlpSeverity) => string;
}) {
  const t = useB3();
  const toast = useToast();
  const event = useDlpReviewEvent(tenantId, id);
  const approve = useApproveDlpReview(tenantId);
  const block = useBlockDlpReview(tenantId);
  const dismiss = useDismissDlpReview(tenantId);

  const deciding = approve.isPending || block.isPending || dismiss.isPending;
  const isPending = event.data?.state === "pending";

  const closeUnlessDeciding = () => {
    if (!deciding) onClose();
  };

  const decide = (d: Decision) => {
    const mutation = d === "approve" ? approve : d === "block" ? block : dismiss;
    mutation.mutate(id, {
      onSuccess: () => {
        toast.success(t(DECISION[d].toast), t("drq.toast.recorded"));
        onClose();
      },
      onError: () => toast.error(t("drq.toast.failed.title"), t("drq.toast.failed.body")),
    });
  };

  // The keydown listener is bound once per pending event, so route it through a
  // ref that always holds the latest decide/deciding values. This avoids both a
  // stale closure and re-subscribing on every render.
  const triageRef = useRef({ decide, deciding });
  triageRef.current = { decide, deciding };

  // Keyboard-first triage: A approve · B block · D dismiss, while the event is
  // pending and no decision is mid-flight. Modifier combos are ignored so app
  // and browser shortcuts still work.
  useEffect(() => {
    if (!isPending) return;
    const onKey = (ev: KeyboardEvent) => {
      const { decide, deciding } = triageRef.current;
      if (ev.metaKey || ev.ctrlKey || ev.altKey || deciding) return;
      const k = ev.key.toLowerCase();
      if (k === "a") decide("approve");
      else if (k === "b") decide("block");
      else if (k === "d") decide("dismiss");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isPending]);

  return (
    <Modal
      title={t("drq.detail.title")}
      onClose={closeUnlessDeciding}
      footer={
        isPending ? (
          <>
            <button className="btn btn--ghost" disabled={deciding} onClick={() => decide("dismiss")}>
              {t("drq.action.dismiss")}
            </button>
            <button className="btn btn--danger" disabled={deciding} onClick={() => decide("block")}>
              {t("drq.action.block")}
            </button>
            <button className="btn btn--primary b3-approve" disabled={deciding} onClick={() => decide("approve")}>
              {t("drq.action.approve")}
            </button>
          </>
        ) : (
          <button className="btn" onClick={onClose}>
            {t("drq.detail.close")}
          </button>
        )
      }
    >
      <AsyncBoundary
        isLoading={event.isLoading}
        error={event.error}
        data={event.data}
        onRetry={() => event.refetch()}
      >
        {(e) => (
          <>
            {isPending && (
              <p className="b3-hint">
                <span className="b3-hint__icon" aria-hidden>⌨</span>
                <span>{t("drq.detail.shortcuts")}</span>
              </p>
            )}
            <dl className="kv">
              <dt>{t("drq.field.state")}</dt>
              <dd>
                <ReviewStateBadge state={e.state} />
              </dd>
              <dt>{t("drq.field.destination")}</dt>
              <dd className="mono">{e.destination_app}</dd>
              <dt>{t("drq.field.signal")}</dt>
              <dd>{signalLabel(t, e.signal)}</dd>
              <dt>{t("drq.field.severity")}</dt>
              <dd>
                <Badge tone={severityTone(e.severity)}>{sevLabel(e.severity)}</Badge>
              </dd>
              <dt>{t("drq.field.confidence")}</dt>
              <dd>{formatPct(e.confidence)}</dd>
              <dt>{t("drq.field.created")}</dt>
              <dd>{formatDateTime(e.created_at)}</dd>
              {e.decided_at && (
                <>
                  <dt>{t("drq.field.decided")}</dt>
                  <dd>{formatDateTime(e.decided_at)}</dd>
                </>
              )}
              {e.decided_by && (
                <>
                  <dt>{t("drq.field.decidedBy")}</dt>
                  <dd className="mono">{e.decided_by}</dd>
                </>
              )}
            </dl>

            <div style={{ marginTop: 14 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 6 }}>
                {t("drq.findings.title")}
              </div>
              {(e.findings ?? []).length === 0 ? (
                <p className="muted" style={{ marginTop: 0 }}>
                  {t("drq.findings.empty")}
                </p>
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr>
                        <th>{t("drq.findings.kind")}</th>
                        <th>{t("drq.findings.detector")}</th>
                        <th>{t("drq.findings.count")}</th>
                        <th>{t("drq.findings.maxConfidence")}</th>
                        <th>{t("drq.findings.severity")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {e.findings.map((f, i) => (
                        <tr key={`${f.kind}-${f.label}-${i}`}>
                          <td>{kindLabel(t, f.kind)}</td>
                          <td className="mono">{f.label}</td>
                          <td>{f.count}</td>
                          <td>{formatPct(f.max_confidence)}</td>
                          <td>
                            <Badge tone={severityTone(f.severity)}>{sevLabel(f.severity)}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}
      </AsyncBoundary>
    </Modal>
  );
}
