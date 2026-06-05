import { useState } from "react";
import {
  useListSites,
  useCreateSite,
  useDeleteSite,
} from "@/api/generated/endpoints/sites/sites";
import { SiteCreateRequestTemplate } from "@/api/generated/model";
import type { Site } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime, titleCase } from "@/lib/format";

type TemplateValue =
  (typeof SiteCreateRequestTemplate)[keyof typeof SiteCreateRequestTemplate];

const TEMPLATE_BLURB: Record<string, string> = {
  branch: "Branch office with on-prem LAN, local breakout and a resilient tunnel pair.",
  hub: "Regional aggregation hub terminating site-to-site tunnels and east-west policy.",
  cloud_only: "Agentless cloud edge — SWG + ZTNA only, no physical site hardware.",
  home_office: "Single-user remote worker site provisioned from the device agent.",
};

export function Sites() {
  return <RequireTenant>{(tenantId) => <SitesInner tenantId={tenantId} />}</RequireTenant>;
}

function SitesInner({ tenantId }: { tenantId: string }) {
  const list = useListSites(tenantId);
  const del = useDeleteSite();
  const [wizard, setWizard] = useState(false);

  const columns: Column<Site>[] = [
    { header: "Name", cell: (s) => s.name },
    { header: "Slug", cell: (s) => <span className="mono">{s.slug}</span> },
    {
      header: "Template",
      cell: (s) => <Badge tone="info">{titleCase(s.template)}</Badge>,
    },
    { header: "Created", cell: (s) => formatDateTime(s.created_at) },
    {
      header: "",
      cell: (s) => (
        <button
          className="btn btn--danger btn--sm"
          disabled={del.isPending}
          onClick={() => {
            if (confirm(`Delete site "${s.name}"?`))
              del.mutate({ tenantId, id: s.id });
          }}
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Sites"
        subtitle="Network sites and their enforcement templates."
        actions={
          <button className="btn btn--primary" onClick={() => setWizard(true)}>
            + New site
          </button>
        }
      />
      <Card>
        <AsyncBoundary
          isLoading={list.isLoading}
          error={list.error}
          data={list.data}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
        >
          {(d) => (
            <DataTable columns={columns} rows={d.items ?? []} rowKey={(s) => s.id} />
          )}
        </AsyncBoundary>
      </Card>
      {wizard && (
        <SiteWizard tenantId={tenantId} onClose={() => setWizard(false)} />
      )}
    </>
  );
}

function SiteWizard({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const create = useCreateSite();
  const [step, setStep] = useState<1 | 2>(1);
  const [template, setTemplate] = useState<TemplateValue>(
    SiteCreateRequestTemplate.branch,
  );
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  const templates = Object.values(SiteCreateRequestTemplate) as TemplateValue[];

  const submit = () => {
    create.mutate(
      { tenantId, data: { name, slug: slug || undefined, template } },
      { onSuccess: onClose },
    );
  };

  return (
    <Modal
      title={`New site · step ${step} of 2`}
      onClose={onClose}
      footer={
        step === 1 ? (
          <button className="btn btn--primary" onClick={() => setStep(2)}>
            Next →
          </button>
        ) : (
          <>
            <button className="btn" onClick={() => setStep(1)}>
              ← Back
            </button>
            <button
              className="btn btn--primary"
              disabled={!name || create.isPending}
              onClick={submit}
            >
              {create.isPending ? "Provisioning…" : "Create site"}
            </button>
          </>
        )
      }
    >
      {step === 1 ? (
        <div className="grid" style={{ gap: 10 }}>
          <p className="muted">Choose a deployment template.</p>
          {templates.map((t) => (
            <button
              key={t}
              className="card"
              style={{
                textAlign: "left",
                cursor: "pointer",
                borderColor:
                  template === t ? "var(--brand)" : "var(--border-soft)",
              }}
              onClick={() => setTemplate(t)}
            >
              <div style={{ fontWeight: 700 }}>{titleCase(t)}</div>
              <div className="muted" style={{ fontSize: 12.5 }}>
                {TEMPLATE_BLURB[t] ?? ""}
              </div>
            </button>
          ))}
        </div>
      ) : (
        <>
          <label className="field">
            <span>Site name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="HQ — San Francisco"
            />
          </label>
          <label className="field">
            <span>Slug (optional)</span>
            <input value={slug} onChange={(e) => setSlug(e.target.value)} />
          </label>
          <p className="muted" style={{ fontSize: 12.5 }}>
            Template: <Badge tone="info">{titleCase(template)}</Badge>
          </p>
          {create.isError && (
            <p className="error-text">
              {create.error instanceof Error
                ? create.error.message
                : "Failed to create site"}
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
