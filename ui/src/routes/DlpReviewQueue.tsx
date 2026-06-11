import { useState } from "react";
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
  StatusBadge,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { formatDateTime, formatRelative, formatPct, titleCase, type Tone } from "@/lib/format";
import type {
  DlpReviewEvent,
  DlpReviewState,
  DlpSeverity,
} from "@/api/manual/types";

export function DlpReviewQueue() {
  return (
    <RequireTenant>
      {(tenantId) => <DlpReviewQueueInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

// The four lifecycle states a reviewer can filter by, plus "all".
const STATE_FILTERS: (DlpReviewState | "all")[] = [
  "all",
  "pending",
  "approved",
  "blocked",
  "dismissed",
];

// The list endpoint returns the most recent events (created_at DESC) up to
// this limit and exposes no pagination cursor, so we request an explicit page
// size and warn the operator when the result fills it — otherwise pending
// exposures past the cap would be silently invisible. 200 matches the
// repository's MaxPageLimit; the state filters are the intended way to narrow
// a backlog larger than this.
const QUEUE_PAGE_LIMIT = 200;

// Digest windows offered to the operator, expressed as Go durations the
// backend's `?window=` parser understands (it caps anything above 90 days).
const DIGEST_WINDOWS: { label: string; value: string }[] = [
  { label: "24h", value: "24h" },
  { label: "7d", value: "168h" },
  { label: "30d", value: "720h" },
  { label: "90d", value: "2160h" },
];

// Severity has its own ladder (low → critical); statusTone only knows
// "critical", so map the rest explicitly for the severity badge. The default
// guards the one untyped entry point — CountBreakdown casts digest `by_severity`
// keys (which originate from the backend) with `as DlpSeverity`, so a severity
// level added server-side later resolves to a neutral badge instead of an
// undefined tone.
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

// Column definitions are static (each `cell` reads only its row argument), so
// they live at module scope rather than being rebuilt on every render.
const QUEUE_COLUMNS: Column<DlpReviewEvent>[] = [
  {
    header: "Destination app",
    cell: (e) =>
      e.destination_app === "suspected_ai_app" ? (
        <Badge tone="warn">Suspected AI app</Badge>
      ) : (
        <span className="mono">{e.destination_app}</span>
      ),
  },
  { header: "Signal", cell: (e) => <Badge tone="info">{e.signal}</Badge> },
  {
    header: "Severity",
    cell: (e) => <Badge tone={severityTone(e.severity)}>{titleCase(e.severity)}</Badge>,
  },
  { header: "Confidence", cell: (e) => formatPct(e.confidence) },
  { header: "Findings", cell: (e) => <FindingKinds event={e} /> },
  { header: "State", cell: (e) => <StatusBadge status={e.state} /> },
  { header: "Created", cell: (e) => formatRelative(e.created_at) },
];

function DlpReviewQueueInner({ tenantId }: { tenantId: string }) {
  const [stateFilter, setStateFilter] = useState<DlpReviewState | "all">(
    "pending",
  );
  const [digestWindow, setDigestWindow] = useState<string>(
    DIGEST_WINDOWS[0].value,
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const queue = useDlpReviewQueue(
    tenantId,
    stateFilter === "all" ? undefined : stateFilter,
    QUEUE_PAGE_LIMIT,
  );
  const digest = useDlpReviewDigest(tenantId, digestWindow);

  return (
    <>
      <PageHeader
        title="DLP review queue"
        subtitle="Human-in-the-loop review of AI-app uploads the endpoint flagged but did not block."
        actions={
          <HelpTooltip title="Why a review queue?" align="right">
            The endpoint AI-app exfiltration signal is coach-first — it flags
            and coaches, but does not block. Every flagged upload lands here for
            a person to approve (a false positive or sanctioned transfer), block
            (a real exposure), or dismiss (noise). Only redacted aggregates are
            stored — never the matched content.
          </HelpTooltip>
        }
      />

      <DigestCard
        isLoading={digest.isLoading}
        error={digest.error}
        digest={digest.data}
        selectedWindow={digestWindow}
        onWindowChange={setDigestWindow}
      />

      <Card title="Queue">
        <div className="filter-bar" style={{ marginBottom: 12 }}>
          <div className="pill-tabs">
            {STATE_FILTERS.map((s) => (
              <button
                key={s}
                className={stateFilter === s ? "active" : ""}
                onClick={() => setStateFilter(s)}
              >
                {titleCase(s)}
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
              title={
                stateFilter === "pending"
                  ? "Nothing waiting on review"
                  : "No events match this filter"
              }
              description={
                stateFilter === "pending"
                  ? "When the endpoint flags an AI-app upload it can't auto-resolve, it will appear here for a decision."
                  : "Try a different state filter to see decided events."
              }
            />
          }
        >
          {(d) => (
            <>
              {(d.items?.length ?? 0) >= QUEUE_PAGE_LIMIT && (
                <div className="muted" style={{ marginBottom: 8, fontSize: 12.5 }}>
                  Showing the {QUEUE_PAGE_LIMIT} most recent events. Narrow by
                  state to see the rest of the backlog.
                </div>
              )}
              <DataTable
                columns={QUEUE_COLUMNS}
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
        />
      )}
    </>
  );
}

// Compact roll-up of a finding's classes for the list row: one badge per
// finding aggregate (kind + count), toned by the finding's own severity.
function FindingKinds({ event }: { event: DlpReviewEvent }) {
  const findings = event.findings ?? [];
  if (findings.length === 0) return <span className="muted">—</span>;
  return (
    <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
      {findings.map((f, i) => (
        <Badge key={`${f.kind}-${f.label}-${i}`} tone={severityTone(f.severity)}>
          {titleCase(f.kind)} ×{f.count}
        </Badge>
      ))}
    </span>
  );
}

function DigestCard({
  isLoading,
  error,
  digest,
  selectedWindow,
  onWindowChange,
}: {
  isLoading: boolean;
  error: unknown;
  digest: ReturnType<typeof useDlpReviewDigest>["data"];
  selectedWindow: string;
  onWindowChange: (w: string) => void;
}) {
  return (
    <Card
      title="Backlog digest"
      subtitle="A non-blocking summary of flagged uploads in the selected window."
      actions={
        <div className="pill-tabs">
          {DIGEST_WINDOWS.map((w) => (
            <button
              key={w.value}
              className={selectedWindow === w.value ? "active" : ""}
              onClick={() => onWindowChange(w.value)}
            >
              {w.label}
            </button>
          ))}
        </div>
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={digest}
      >
        {(d) => (
          <>
            <div className="grid grid--stats" style={{ marginBottom: 12 }}>
              <Stat label="Total events" value={d.total} />
              <Stat label="Pending review" value={d.pending} />
              <Stat
                label="Awaiting in apps"
                value={Object.keys(d.pending_by_app).length}
              />
              <Stat label="Since" value={formatDateTime(d.since)} />
            </div>
            <div className="grid grid--2">
              <CountBreakdown
                title="By severity"
                counts={d.by_severity}
                tone={(k) => severityTone(k as DlpSeverity)}
              />
              <CountBreakdown title="By state" counts={d.by_state} />
            </div>
            {Object.keys(d.pending_by_app).length > 0 && (
              <div style={{ marginTop: 12 }}>
                <CountBreakdown
                  title="Pending by destination app"
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
  mono = false,
}: {
  title: string;
  counts: Record<string, number>;
  tone?: (key: string) => Tone;
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
              <span className={mono ? "mono" : undefined}>{titleCase(key)}</span>{" "}
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
}: {
  tenantId: string;
  id: string;
  onClose: () => void;
}) {
  const toast = useToast();
  const event = useDlpReviewEvent(tenantId, id);
  const approve = useApproveDlpReview(tenantId);
  const block = useBlockDlpReview(tenantId);
  const dismiss = useDismissDlpReview(tenantId);

  const deciding = approve.isPending || block.isPending || dismiss.isPending;

  // Hold the modal open while a decision is in flight. All three close paths
  // (Escape, backdrop, ✕) route through this single handler, so guarding it
  // here keeps the operator from dismissing mid-write — which would otherwise
  // swallow the success toast (React Query suppresses the per-call onSuccess
  // once the component unmounts) and leave them unsure the decision landed.
  const closeUnlessDeciding = () => {
    if (!deciding) onClose();
  };

  const decide = (
    mutation: typeof approve,
    label: string,
  ) =>
    mutation.mutate(id, {
      onSuccess: () => {
        toast.success(`Marked ${label}`, "The decision has been recorded.");
        onClose();
      },
      onError: () =>
        toast.error("Decision failed", `Could not mark the event ${label}.`),
    });

  return (
    <Modal
      title="Review event"
      onClose={closeUnlessDeciding}
      footer={
        event.data && event.data.state === "pending" ? (
          <>
            <button
              className="btn"
              disabled={deciding}
              onClick={() => decide(dismiss, "dismissed")}
            >
              Dismiss
            </button>
            <button
              className="btn btn--danger"
              disabled={deciding}
              onClick={() => decide(block, "blocked")}
            >
              Block
            </button>
            <button
              className="btn btn--primary"
              disabled={deciding}
              onClick={() => decide(approve, "approved")}
            >
              Approve
            </button>
          </>
        ) : (
          <button className="btn" onClick={onClose}>
            Close
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
            <dl className="kv">
              <dt>State</dt>
              <dd>
                <StatusBadge status={e.state} />
              </dd>
              <dt>Destination app</dt>
              <dd className="mono">{e.destination_app}</dd>
              <dt>Signal</dt>
              <dd className="mono">{e.signal}</dd>
              <dt>Severity</dt>
              <dd>
                <Badge tone={severityTone(e.severity)}>{titleCase(e.severity)}</Badge>
              </dd>
              <dt>Confidence</dt>
              <dd>{formatPct(e.confidence)}</dd>
              <dt>Created</dt>
              <dd>{formatDateTime(e.created_at)}</dd>
              {e.decided_at && (
                <>
                  <dt>Decided</dt>
                  <dd>{formatDateTime(e.decided_at)}</dd>
                </>
              )}
              {e.decided_by && (
                <>
                  <dt>Decided by</dt>
                  <dd className="mono">{e.decided_by}</dd>
                </>
              )}
            </dl>

            <div style={{ marginTop: 14 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 6 }}>
                Findings (redacted aggregates)
              </div>
              {(e.findings ?? []).length === 0 ? (
                <p className="muted" style={{ marginTop: 0 }}>
                  No finding aggregates were recorded for this event.
                </p>
              ) : (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Detector</th>
                      <th>Count</th>
                      <th>Max confidence</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {e.findings.map((f, i) => (
                      <tr key={`${f.kind}-${f.label}-${i}`}>
                        <td>{titleCase(f.kind)}</td>
                        <td className="mono">{f.label}</td>
                        <td>{f.count}</td>
                        <td>{formatPct(f.max_confidence)}</td>
                        <td>
                          <Badge tone={severityTone(f.severity)}>
                            {titleCase(f.severity)}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}
      </AsyncBoundary>
    </Modal>
  );
}
