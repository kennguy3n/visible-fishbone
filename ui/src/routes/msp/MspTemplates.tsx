import { useEffect, useState } from "react";
import { useBulkApplyPolicyTemplate } from "@/api/generated/endpoints/msps/msps";
import { PageHeader, Card, Badge } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { MspPicker } from "./MspPicker";

// Cross-tenant policy templates are authored once and pushed to an
// MSP's entire tenant cohort. The library is persisted locally so
// operators can curate reusable baselines; applying a template fans
// out via the MSP bulk endpoint.

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
    // A corrupted or tampered entry must not flow through as Template[]:
    // keep only well-shaped records and drop the rest.
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

export function MspTemplates() {
  const [templates, setTemplates] = useState<Template[]>(load);
  const [mspId, setMspId] = useState<string | null>(null);
  const [editing, setEditing] = useState<Template | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const apply = useBulkApplyPolicyTemplate();
  // `appliedId` tracks the in-flight apply (for the spinner); `lastAppliedId`
  // is the template that last succeeded and is NOT cleared on settle, so the
  // "Applied" badge is scoped to that one card. Using the shared
  // `apply.isSuccess` flag instead would light up every card in the .map().
  const [appliedId, setAppliedId] = useState<string | null>(null);
  const [lastAppliedId, setLastAppliedId] = useState<string | null>(null);

  // Persisting the library is a side effect, so it lives in an effect rather
  // than inside the state updaters (which stay pure and are double-invoked
  // under StrictMode). Updaters use the functional form so rapid successive
  // edits compose off the freshest list instead of a stale closure snapshot.
  // The effect writes whatever was committed and warns once if the write fails
  // (e.g. quota exceeded). We skip the write when storage already holds this
  // exact value: that covers both the initial mount (the state came straight
  // from localStorage) and a value we just adopted from another tab's `storage`
  // event — without this guard those two tabs would ping-pong setItem calls
  // (each write fires a `storage` event in the other tab) forever.
  useEffect(() => {
    if (localStorage.getItem(STORAGE_KEY) === JSON.stringify(templates)) {
      return;
    }
    if (!persist(templates)) {
      alert(
        "Couldn't save the template library: browser storage is full. " +
          "Delete some templates and try again.",
      );
    }
  }, [templates]);

  // Keep multiple admin tabs in sync. Without this, a second tab keeps its
  // stale in-memory list and its next edit persists that stale list, silently
  // clobbering templates the first tab added (last write wins, no merge). The
  // `storage` event fires only in the *other* tabs, so we reload the committed
  // library there; the persist effect above no-ops on the adopted value.
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
      alert("Template graph is not valid JSON.");
      return;
    }
    setAppliedId(t.id);
    apply.mutate(
      { mspId, data: { template: graph } },
      {
        onSuccess: () => setLastAppliedId(t.id),
        onSettled: () => setAppliedId(null),
      },
    );
  };

  return (
    <>
      <PageHeader
        title="Cross-tenant policy templates"
        subtitle="Curate reusable policy baselines and roll them out to an MSP cohort."
        actions={
          <button
            className="btn btn--primary"
            onClick={() => {
              setEditing(null);
              setShowEditor(true);
            }}
          >
            + New template
          </button>
        }
      />
      <Card>
        <MspPicker value={mspId} onChange={setMspId} />
      </Card>

      <div className="grid grid--2" style={{ marginTop: 16 }}>
        {templates.length === 0 && (
          <Card>
            <p className="muted">
              No templates yet. Create one to define a reusable policy baseline.
            </p>
          </Card>
        )}
        {templates.map((t) => (
          <Card
            key={t.id}
            title={t.name}
            actions={
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  className="btn btn--sm"
                  onClick={() => {
                    setEditing(t);
                    setShowEditor(true);
                  }}
                >
                  Edit
                </button>
                <button className="btn btn--danger btn--sm" onClick={() => remove(t.id)}>
                  Delete
                </button>
              </div>
            }
          >
            <p className="muted" style={{ marginTop: 0 }}>
              {t.description || "No description."}
            </p>
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <button
                className="btn btn--primary btn--sm"
                disabled={!mspId || (apply.isPending && appliedId === t.id)}
                onClick={() => applyTemplate(t)}
              >
                {apply.isPending && appliedId === t.id ? "Applying…" : "Apply to cohort"}
              </button>
              {lastAppliedId === t.id && appliedId === null && (
                <Badge tone="ok">Applied</Badge>
              )}
            </div>
          </Card>
        ))}
      </div>

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
    </>
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
  const [name, setName] = useState(template?.name ?? "");
  const [description, setDescription] = useState(template?.description ?? "");
  const [graph, setGraph] = useState(
    template?.graph ?? '{\n  "nodes": [],\n  "edges": []\n}',
  );
  const [err, setErr] = useState<string | null>(null);

  const save = () => {
    setErr(null);
    try {
      JSON.parse(graph);
    } catch {
      setErr("Graph must be valid JSON.");
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
    <Modal
      title={template ? "Edit template" : "New template"}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn--primary" disabled={!name} onClick={save}>
            Save
          </button>
        </>
      }
    >
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="field">
        <span>Description</span>
        <input value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label className="field">
        <span>Policy graph (JSON)</span>
        <textarea
          style={{ minHeight: 180, fontFamily: "var(--mono)" }}
          value={graph}
          onChange={(e) => setGraph(e.target.value)}
        />
      </label>
      {err && <p className="error-text">{err}</p>}
    </Modal>
  );
}
