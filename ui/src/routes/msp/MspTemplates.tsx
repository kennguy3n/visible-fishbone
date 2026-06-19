import { useEffect, useMemo, useState } from "react";
import { useIntl } from "react-intl";
import {
  useBulkApplyPolicyTemplate,
  useListMSPs,
} from "@/api/generated/endpoints/msps/msps";
import {
  PageHeader,
  Card,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { useToast } from "@/components/Toast";
import { MspPicker } from "./MspPicker";
import { M } from "./lane-b6.messages";
import {
  LanePage,
  LaneModal,
  MspScopeBanner,
  ConfirmDialog,
  LabelText,
} from "./_lane";

// Cross-tenant policy templates are authored once and pushed to an MSP's
// entire tenant cohort. The library is persisted locally so operators can
// curate reusable baselines; applying a template fans out via the MSP bulk
// endpoint.

interface Template {
  id: string;
  name: string;
  description: string;
  graph: string;
}

const STORAGE_KEY = "sng.msp.templates";

function isTemplate(value: unknown): value is Template {
  if (typeof value !== "object" || value === null) return false;
  const t = value as Record<string, unknown>;
  return (
    typeof t.id === "string" &&
    typeof t.name === "string" &&
    typeof t.description === "string" &&
    typeof t.graph === "string"
  );
}

function load(): Template[] {
  try {
    const parsed: unknown = JSON.parse(
      localStorage.getItem(STORAGE_KEY) ?? "[]",
    );
    return Array.isArray(parsed) ? parsed.filter(isTemplate) : [];
  } catch {
    return [];
  }
}

// Returns false if the write fails (e.g. localStorage quota exceeded) so the
// caller can warn the operator instead of silently losing the change.
function persist(t: Template[]): boolean {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(t));
    return true;
  } catch {
    return false;
  }
}

/** Best-effort node/edge counts for the card meta; null if the graph won't parse. */
function graphCounts(graph: string): { nodes: number; edges: number } | null {
  try {
    const g = JSON.parse(graph) as { nodes?: unknown; edges?: unknown };
    return {
      nodes: Array.isArray(g.nodes) ? g.nodes.length : 0,
      edges: Array.isArray(g.edges) ? g.edges.length : 0,
    };
  } catch {
    return null;
  }
}

export function MspTemplates() {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const msps = useListMSPs(undefined);
  const [templates, setTemplates] = useState<Template[]>(load);
  const [mspId, setMspId] = useState<string | null>(null);
  const [editing, setEditing] = useState<Template | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<Template | null>(null);
  const [confirmApply, setConfirmApply] = useState<Template | null>(null);
  const apply = useBulkApplyPolicyTemplate();
  // `appliedId` tracks the in-flight apply (for the spinner); `lastAppliedId`
  // is the template that last succeeded and is NOT cleared on settle, so the
  // "Applied" badge is scoped to that one card.
  const [appliedId, setAppliedId] = useState<string | null>(null);
  const [lastAppliedId, setLastAppliedId] = useState<string | null>(null);

  const mspName = useMemo(
    () => msps.data?.items?.find((m) => m.id === mspId)?.name ?? "",
    [msps.data?.items, mspId],
  );

  useEffect(() => {
    if (localStorage.getItem(STORAGE_KEY) === JSON.stringify(templates)) {
      return;
    }
    if (!persist(templates)) {
      toast.error(fm(M.tplErrQuota));
    }
  }, [templates, toast, fm]);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY || e.key === null) setTemplates(load());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const upsert = (t: Template) => {
    setTemplates((prev) =>
      prev.some((p) => p.id === t.id)
        ? prev.map((p) => (p.id === t.id ? t : p))
        : [...prev, t],
    );
  };

  const remove = (id: string) => {
    setTemplates((prev) => prev.filter((p) => p.id !== id));
  };

  const applyTemplate = (t: Template) => {
    if (!mspId) return;
    let graph: Record<string, unknown>;
    try {
      graph = JSON.parse(t.graph);
    } catch {
      toast.error(fm(M.tplErrJson));
      return;
    }
    setAppliedId(t.id);
    apply.mutate(
      { mspId, data: { template: graph } },
      {
        onSuccess: () => {
          setLastAppliedId(t.id);
          setConfirmApply(null);
          toast.success(fm(M.tplAppliedToast), fm(M.tplAppliedToastBody, { name: t.name }));
        },
        onError: () => toast.error(fm(M.tplApplyError)),
        onSettled: () => setAppliedId(null),
      },
    );
  };

  const newTemplateBtn = (
    <button
      className="btn btn--primary"
      onClick={() => {
        setEditing(null);
        setShowEditor(true);
      }}
    >
      {fm(M.tplNew)}
    </button>
  );

  return (
    <LanePage>
      <PageHeader
        title={fm(M.tplTitle)}
        subtitle={fm(M.tplSubtitle)}
        actions={newTemplateBtn}
      />
      <Card>
        <MspPicker value={mspId} onChange={setMspId} />
      </Card>
      {mspId && mspName && <MspScopeBanner name={mspName} />}

      {templates.length === 0 ? (
        <div style={{ marginTop: 16 }}>
          <Card>
            <EmptyState
              illustration={<EmptyIllustration kind="policy" />}
              title={fm(M.tplEmptyTitle)}
              description={fm(M.tplEmptyBody)}
              action={newTemplateBtn}
            />
          </Card>
        </div>
      ) : (
        <div className="grid grid--2" style={{ marginTop: 16 }}>
          {templates.map((t) => {
            const counts = graphCounts(t.graph);
            return (
              <Card
                key={t.id}
                title={t.name}
                actions={
                  <div className="lb6-card-actions">
                    <button
                      className="btn btn--sm"
                      onClick={() => {
                        setEditing(t);
                        setShowEditor(true);
                      }}
                    >
                      {fm(M.tplEdit)}
                    </button>
                    <button
                      className="btn btn--danger btn--sm"
                      onClick={() => setConfirmDelete(t)}
                    >
                      {fm(M.tplDelete)}
                    </button>
                  </div>
                }
              >
                <p className="muted" style={{ marginTop: 0 }}>
                  {t.description || fm(M.tplNoDescription)}
                </p>
                <div className="lb6-card-foot">
                  {counts && (
                    <span className="muted" style={{ fontSize: 12 }}>
                      {fm(M.tplNodesEdges, {
                        nodes: counts.nodes,
                        edges: counts.edges,
                      })}
                    </span>
                  )}
                  <div className="lb6-card-actions">
                    {lastAppliedId === t.id && appliedId === null && (
                      <Badge tone="ok">{fm(M.tplApplied)}</Badge>
                    )}
                    <button
                      className="btn btn--primary btn--sm"
                      disabled={!mspId || (apply.isPending && appliedId === t.id)}
                      onClick={() => setConfirmApply(t)}
                    >
                      {apply.isPending && appliedId === t.id
                        ? fm(M.tplApplying)
                        : fm(M.tplApply)}
                    </button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {showEditor && (
        <TemplateEditor
          template={editing}
          onClose={() => setShowEditor(false)}
          onSave={(t) => {
            upsert(t);
            setShowEditor(false);
          }}
        />
      )}

      {confirmDelete && (
        <ConfirmDialog
          title={fm(M.tplDeleteTitle, { name: confirmDelete.name })}
          confirmLabel={fm(M.tplDeleteCta)}
          tone="danger"
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => {
            remove(confirmDelete.id);
            setConfirmDelete(null);
          }}
        >
          <p>{fm(M.tplDeleteBody)}</p>
        </ConfirmDialog>
      )}

      {confirmApply && (
        <ConfirmDialog
          title={fm(M.tplApplyConfirmTitle, { name: confirmApply.name })}
          confirmLabel={fm(M.tplApplyConfirmCta)}
          busy={apply.isPending}
          onClose={() => (apply.isPending ? undefined : setConfirmApply(null))}
          onConfirm={() => applyTemplate(confirmApply)}
        >
          <p>{fm(M.tplApplyConfirmBody, { msp: mspName })}</p>
        </ConfirmDialog>
      )}
    </LanePage>
  );
}

function TemplateEditor({
  template,
  onClose,
  onSave,
}: {
  template: Template | null;
  onClose: () => void;
  onSave: (t: Template) => void;
}) {
  const { formatMessage: fm } = useIntl();
  const [name, setName] = useState(template?.name ?? "");
  const [description, setDescription] = useState(template?.description ?? "");
  const [graph, setGraph] = useState(
    template?.graph ?? '{\n  "nodes": [],\n  "edges": []\n}',
  );
  const [err, setErr] = useState<string | null>(null);

  const save = () => {
    setErr(null);
    if (!name.trim()) {
      setErr(fm(M.tplErrName));
      return;
    }
    try {
      JSON.parse(graph);
    } catch {
      setErr(fm(M.tplErrJson));
      return;
    }
    onSave({
      id: template?.id ?? crypto.randomUUID(),
      name,
      description,
      graph,
    });
  };

  return (
    <LaneModal
      title={template ? fm(M.tplEditTitle) : fm(M.tplCreateTitle)}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {fm(M.cancel)}
          </button>
          <button
            className="btn btn--primary"
            disabled={!name.trim()}
            onClick={save}
          >
            {fm(M.tplSave)}
          </button>
        </>
      }
    >
      <label className="field">
        <LabelText>{fm(M.tplName)}</LabelText>
        <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </label>
      <label className="field">
        <LabelText help={fm(M.tplDescriptionHelp)}>
          {fm(M.tplDescription)}
        </LabelText>
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </label>
      <label className="field">
        <LabelText help={fm(M.tplGraphHelp)}>{fm(M.tplGraph)}</LabelText>
        <textarea
          style={{ minHeight: 180, fontFamily: "var(--mono)" }}
          value={graph}
          onChange={(e) => setGraph(e.target.value)}
        />
      </label>
      {err && (
        <p className="error-text" role="alert">
          {err}
        </p>
      )}
    </LaneModal>
  );
}
