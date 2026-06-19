import { useState } from "react";
import {
  useListSites,
  useCreateSite,
  useDeleteSite,
} from "@/api/generated/endpoints/sites/sites";
import { SiteCreateRequestTemplate } from "@/api/generated/model";
import type { Site } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  AsyncBoundary,
  Badge,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { RequireTenant } from "@/components/RequireTenant";
import { formatDateTime } from "@/lib/format";
import { LaneB2Intl, useT, type LaneB2Key } from "./lane-b2/i18n";
import { ConfirmDialog } from "./lane-b2/ConfirmDialog";
import { useDialogA11y } from "./lane-b2/useDialogA11y";

type TemplateValue =
  (typeof SiteCreateRequestTemplate)[keyof typeof SiteCreateRequestTemplate];

const TEMPLATE_KEYS: Record<
  TemplateValue,
  { label: LaneB2Key; blurb: LaneB2Key }
> = {
  branch: { label: "sites.template.branch", blurb: "sites.template.branch.blurb" },
  hub: { label: "sites.template.hub", blurb: "sites.template.hub.blurb" },
  cloud_only: {
    label: "sites.template.cloud_only",
    blurb: "sites.template.cloud_only.blurb",
  },
  home_office: {
    label: "sites.template.home_office",
    blurb: "sites.template.home_office.blurb",
  },
};

export function Sites() {
  return (
    <LaneB2Intl>
      <RequireTenant>
        {(tenantId) => <SitesInner tenantId={tenantId} />}
      </RequireTenant>
    </LaneB2Intl>
  );
}

function SitesInner({ tenantId }: { tenantId: string }) {
  const t = useT();
  const list = useListSites(tenantId);
  const del = useDeleteSite();
  const [wizard, setWizard] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<Site | null>(null);

  const columns: Column<Site>[] = [
    { header: t("sites.col.name"), cell: (s) => s.name },
    {
      header: t("sites.col.slug"),
      cell: (s) => <span className="mono">{s.slug}</span>,
    },
    {
      header: t("sites.col.template"),
      cell: (s) => (
        <Badge tone="info">
          {t(TEMPLATE_KEYS[s.template as TemplateValue]?.label ?? "common.none")}
        </Badge>
      ),
    },
    { header: t("sites.col.created"), cell: (s) => formatDateTime(s.created_at) },
    {
      header: t("sites.col.actions"),
      cell: (s) => (
        <button
          className="btn btn--danger btn--sm"
          aria-label={t("sites.delete.aria", { name: s.name })}
          disabled={del.isPending}
          onClick={() => setPendingDelete(s)}
        >
          {t("sites.delete")}
        </button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t("sites.title")}
        subtitle={t("sites.subtitle")}
        actions={
          <button className="btn btn--primary" onClick={() => setWizard(true)}>
            {t("sites.new")}
          </button>
        }
      />
      <Card
        title={t("sites.title")}
        actions={
          <HelpTooltip title={t("sites.help.title")} align="right">
            {t("sites.help.body")}
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
              illustration={<EmptyIllustration kind="shield" />}
              title={t("sites.empty.title")}
              description={t("sites.empty.body")}
              action={
                <button
                  className="btn btn--primary"
                  onClick={() => setWizard(true)}
                >
                  {t("sites.new")}
                </button>
              }
            />
          }
        >
          {(d) => (
            <DataTable
              columns={columns}
              rows={d.items ?? []}
              rowKey={(s) => s.id}
            />
          )}
        </AsyncBoundary>
      </Card>
      {wizard && (
        <SiteWizard tenantId={tenantId} onClose={() => setWizard(false)} />
      )}
      {pendingDelete && (
        <ConfirmDialog
          title={t("sites.delete.title")}
          message={t("sites.delete.confirm", { name: pendingDelete.name })}
          confirmLabel={t("sites.delete.cta")}
          cancelLabel={t("common.cancel")}
          busy={del.isPending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() =>
            del.mutate(
              { tenantId, id: pendingDelete.id },
              { onSuccess: () => setPendingDelete(null) },
            )
          }
        />
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
  const t = useT();
  const create = useCreateSite();
  const [step, setStep] = useState<1 | 2>(1);
  const [template, setTemplate] = useState<TemplateValue>(
    SiteCreateRequestTemplate.branch,
  );
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  // Move focus into the wizard on open, trap Tab, and restore it on close.
  useDialogA11y({ focusFirst: true });

  const templates = Object.values(SiteCreateRequestTemplate) as TemplateValue[];

  const submit = () => {
    create.mutate(
      { tenantId, data: { name, slug: slug || undefined, template } },
      { onSuccess: onClose },
    );
  };

  return (
    <Modal
      title={t("sites.wizard.title", { step })}
      onClose={onClose}
      footer={
        step === 1 ? (
          <button className="btn btn--primary" onClick={() => setStep(2)}>
            {t("common.next")}
          </button>
        ) : (
          <>
            <button className="btn" onClick={() => setStep(1)}>
              {t("common.back")}
            </button>
            <button
              className="btn btn--primary"
              disabled={!name || create.isPending}
              onClick={submit}
            >
              {create.isPending
                ? t("sites.wizard.creating")
                : t("sites.wizard.create")}
            </button>
          </>
        )
      }
    >
      {step === 1 ? (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("sites.wizard.step1.help")}
          </p>
          <div
            className="choice-grid"
            role="group"
            aria-label={t("sites.wizard.step1.legend")}
            style={{ marginTop: 6 }}
          >
            {templates.map((tpl) => (
              <button
                key={tpl}
                type="button"
                className={`choice${template === tpl ? " choice--selected" : ""}`}
                aria-pressed={template === tpl}
                onClick={() => setTemplate(tpl)}
              >
                <div className="choice__name">
                  {t(TEMPLATE_KEYS[tpl].label)}
                </div>
                <div className="choice__desc">
                  {t(TEMPLATE_KEYS[tpl].blurb)}
                </div>
              </button>
            ))}
          </div>
        </>
      ) : (
        <>
          <label className="field">
            <span>{t("sites.wizard.name.label")}</span>
            <input
              value={name}
              autoFocus
              onChange={(e) => setName(e.target.value)}
              placeholder={t("sites.wizard.name.placeholder")}
            />
            <small
              className="muted"
              style={{ display: "block", marginTop: 4 }}
            >
              {t("sites.wizard.name.hint")}
            </small>
          </label>
          <label className="field">
            <span>
              {t("sites.wizard.slug.label")}{" "}
              <span className="muted">({t("sites.wizard.slug.optional")})</span>
            </span>
            <input
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder={t("sites.wizard.slug.placeholder")}
            />
            <small
              className="muted"
              style={{ display: "block", marginTop: 4 }}
            >
              {t("sites.wizard.slug.hint")}
            </small>
          </label>
          <p className="muted" style={{ fontSize: 12.5 }}>
            {t("sites.wizard.template.summary")}:{" "}
            <Badge tone="info">{t(TEMPLATE_KEYS[template].label)}</Badge>
          </p>
          {create.isError && (
            <p className="error-text" role="alert">
              {t("sites.wizard.error")}
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
