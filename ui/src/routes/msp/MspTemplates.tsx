import { useState } from "react";
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
  const [appliedId, setAppliedId] = useState<string | null>(null);

  // Persistence is a side effect, so it runs outside the state updater (which
  // must stay pure / can run twice under StrictMode). A failed save surfaces
  // a warning rather than silently dropping the change.
  const upsert = (t: Template) => {
    const next = templates.some((p) => p.id === t.id)
      ? templates.map((p) => (p.id === t.id ? t : p))
      : [...templates, t];
    setTemplates(next);
    if (!persist(next)) {
      alert(
        "Couldn't save the template library: browser storage is full. " +
          "Delete some templates and try again.",
      );
    }
  };

  const remove = (id: string) => {
    const next = templates.filter((p) => p.id !== id);
    setTemplates(next);
    persist(next); // a delete frees space, so ignore any write failure
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
      { onSettled: () => setAppliedId(null) },
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
              {apply.isSuccess && appliedId === null && (
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
