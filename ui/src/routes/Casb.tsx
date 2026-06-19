import { useState } from "react";
import {
  useCasbConnectors,
  useCasbApps,
  useCreateCasbConnector,
  useSyncCasbConnector,
} from "@/api/manual/hooks";
import {
  PageHeader,
  Card,
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
import { formatRelative } from "@/lib/format";
import type { CasbApp, CasbAppVerdict, CasbConnector } from "@/api/manual/types";
import { LaneB3Intl, useB3, type B3Key } from "./lane-b3-i18n";
import "./lane-b3.css";

export function Casb() {
  return (
    <RequireTenant>
      {(tenantId) => (
        <LaneB3Intl>
          <CasbInner tenantId={tenantId} />
        </LaneB3Intl>
      )}
    </RequireTenant>
  );
}

function riskTone(score: number) {
  if (score >= 70) return "danger" as const;
  if (score >= 40) return "warn" as const;
  return "ok" as const;
}

function sanctionTone(sanction: string) {
  switch (sanction) {
    case "unsanctioned":
      return "danger" as const;
    case "tolerated":
      return "warn" as const;
    case "sanctioned":
      return "ok" as const;
    default:
      return "neutral" as const;
  }
}

const SANCTION_KEYS: Record<string, B3Key> = {
  unsanctioned: "casb.sanction.unsanctioned",
  tolerated: "casb.sanction.tolerated",
  sanctioned: "casb.sanction.sanctioned",
};

const ENFORCEMENT_KEYS: Record<string, B3Key> = {
  none: "casb.enforcement.none",
  throttle: "casb.enforcement.throttle",
  protect: "casb.enforcement.protect",
  route: "casb.enforcement.route",
  enforce: "casb.enforcement.enforce",
};

// Connector source types are vendor proper nouns — not localizable strings.
const CONNECTOR_TYPES: { value: string; label: string }[] = [
  { value: "google_workspace", label: "Google Workspace" },
  { value: "microsoft365", label: "Microsoft 365" },
  { value: "okta", label: "Okta" },
  { value: "salesforce", label: "Salesforce" },
  { value: "box", label: "Box" },
];

const CONNECTOR_TYPE_LABEL: Record<string, string> = Object.fromEntries(
  CONNECTOR_TYPES.map((c) => [c.value, c.label]),
);

// VerdictCell renders the NoOps recommendation inline: the enforcement verb,
// whether it was auto-applied or is a recommendation, the confidence, and the
// plain-language rationale on hover. Apps not yet classified show a muted hint.
function VerdictCell({ verdict }: { verdict?: CasbAppVerdict }) {
  const t = useB3();
  if (!verdict) return <span className="muted">{t("casb.verdict.none")}</span>;
  const action = verdict.action;
  const enforcement = action?.enforcement ?? "none";
  const label = ENFORCEMENT_KEYS[enforcement]
    ? t(ENFORCEMENT_KEYS[enforcement])
    : enforcement;
  const applied = action?.applied ?? false;
  const auto = action?.mode === "auto";
  // Three NoOps states: already auto-applied, will auto-apply (auto mode, not
  // yet enforced), or a recommendation awaiting an operator. Only an applied
  // verdict reads as active chrome; the rest stay neutral.
  const stateLabel = applied
    ? t("casb.verdict.applied")
    : auto
      ? t("casb.verdict.auto")
      : t("casb.verdict.recommended");
  return (
    <span title={verdict.rationale} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
      <Badge tone={applied ? "info" : "neutral"}>{label}</Badge>
      <span className="muted" style={{ fontSize: "0.8em" }}>
        {stateLabel} · {verdict.confidence}%
      </span>
    </span>
  );
}

function CasbInner({ tenantId }: { tenantId: string }) {
  const t = useB3();
  const toast = useToast();
  const connectors = useCasbConnectors(tenantId);
  const apps = useCasbApps(tenantId);
  const sync = useSyncCasbConnector(tenantId);
  const [showCreate, setShowCreate] = useState(false);
  const [syncingId, setSyncingId] = useState<string | null>(null);

  const runSync = (c: CasbConnector) => {
    setSyncingId(c.id);
    sync.mutate(c.id, {
      onSuccess: () => toast.success(t("casb.sync.done.title"), t("casb.sync.done.body")),
      onError: () => toast.error(t("casb.sync.failed.title"), t("casb.sync.failed.body")),
      onSettled: () => setSyncingId(null),
    });
  };

  const appCols: Column<CasbApp>[] = [
    { header: t("casb.col.app"), cell: (a) => a.name },
    { header: t("casb.col.vendor"), cell: (a) => a.vendor },
    { header: t("casb.col.category"), cell: (a) => <Badge tone="neutral">{a.category}</Badge> },
    { header: t("casb.col.risk"), cell: (a) => <Badge tone={riskTone(a.risk_score)}>{a.risk_score}</Badge> },
    {
      header: t("casb.col.sanction"),
      cell: (a) =>
        a.verdict ? (
          <Badge tone={sanctionTone(a.verdict.sanction)} dot>
            {SANCTION_KEYS[a.verdict.sanction] ? t(SANCTION_KEYS[a.verdict.sanction]) : a.verdict.sanction}
          </Badge>
        ) : (
          <span className="muted">{t("casb.verdict.none")}</span>
        ),
    },
    { header: t("casb.col.recommendation"), cell: (a) => <VerdictCell verdict={a.verdict} /> },
    { header: t("casb.col.users"), cell: (a) => a.users_count },
    { header: t("casb.col.devices"), cell: (a) => a.active_device_count },
    { header: t("casb.col.lastSeen"), cell: (a) => formatRelative(a.last_seen) },
  ];

  const connCols: Column<CasbConnector>[] = [
    { header: t("casb.col.connName"), cell: (c) => c.name },
    {
      header: t("casb.col.connType"),
      cell: (c) => <Badge tone="info">{CONNECTOR_TYPE_LABEL[c.type] ?? c.type}</Badge>,
    },
    { header: t("casb.col.connStatus"), cell: (c) => <StatusBadge status={c.status} /> },
    { header: t("casb.col.lastSync"), cell: (c) => formatRelative(c.last_sync_at ?? null) },
    {
      header: t("b3.actions"),
      cell: (c) => (
        <button
          className="btn btn--sm"
          disabled={syncingId !== null}
          aria-label={`${t("casb.sync")} — ${c.name}`}
          onClick={() => runSync(c)}
        >
          {syncingId === c.id ? t("casb.syncing") : t("casb.sync")}
        </button>
      ),
    },
  ];

  return (
    <div className="lane-b3">
      <PageHeader
        title={t("casb.title")}
        subtitle={t("casb.subtitle")}
        actions={
          <button className="btn btn--primary" onClick={() => setShowCreate(true)}>
            {t("casb.addConnector")}
          </button>
        }
      />

      <Card
        title={t("casb.apps.title")}
        actions={
          <span style={{ display: "inline-flex", gap: 8 }}>
            <HelpTooltip title={t("casb.apps.help.title")} align="right">
              {t("casb.apps.help.body")}
            </HelpTooltip>
            <HelpTooltip title={t("casb.risk.help.title")} align="right">
              {t("casb.risk.help.body")}
            </HelpTooltip>
          </span>
        }
      >
        <AsyncBoundary
          isLoading={apps.isLoading}
          error={apps.error}
          data={apps.data}
          onRetry={() => apps.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="search" />}
              title={t("casb.apps.empty.title")}
              description={t("casb.apps.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setShowCreate(true)}>
                  {t("casb.addConnector")}
                </button>
              }
            />
          }
        >
          {(d) => <DataTable columns={appCols} rows={d.items ?? []} rowKey={(a) => a.id} />}
        </AsyncBoundary>
      </Card>

      <Card
        title={t("casb.connectors.title")}
        actions={
          <HelpTooltip title={t("casb.connectors.help.title")} align="right">
            {t("casb.connectors.help.body")}
          </HelpTooltip>
        }
      >
        <AsyncBoundary
          isLoading={connectors.isLoading}
          error={connectors.error}
          data={connectors.data}
          onRetry={() => connectors.refetch()}
          isEmpty={(d) => (d.items?.length ?? 0) === 0}
          empty={
            <EmptyState
              illustration={<EmptyIllustration kind="inbox" />}
              title={t("casb.connectors.empty.title")}
              description={t("casb.connectors.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setShowCreate(true)}>
                  {t("casb.addConnector")}
                </button>
              }
            />
          }
        >
          {(d) => <DataTable columns={connCols} rows={d.items ?? []} rowKey={(c) => c.id} />}
        </AsyncBoundary>
      </Card>

      {showCreate && (
        <CreateConnector tenantId={tenantId} onClose={() => setShowCreate(false)} />
      )}
    </div>
  );
}

function CreateConnector({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const t = useB3();
  const toast = useToast();
  const create = useCreateCasbConnector(tenantId);
  const [name, setName] = useState("");
  const [type, setType] = useState(CONNECTOR_TYPES[0].value);

  const submit = () =>
    create.mutate(
      { name, type },
      {
        onSuccess: () => {
          toast.success(t("casb.create.success.title"), t("casb.create.success.body"));
          onClose();
        },
      },
    );

  return (
    <Modal
      title={t("casb.create.title")}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {t("casb.create.cancel")}
          </button>
          <button className="btn btn--primary" disabled={!name.trim() || create.isPending} onClick={submit}>
            {create.isPending ? t("casb.create.submitting") : t("casb.create.submit")}
          </button>
        </>
      }
    >
      <label className="field">
        <span>{t("casb.create.name")}</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("casb.create.namePlaceholder")}
          autoFocus
        />
      </label>
      <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
        {t("casb.create.name.help")}
      </p>
      <label className="field">
        <span>{t("casb.create.type")}</span>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {CONNECTOR_TYPES.map((ct) => (
            <option key={ct.value} value={ct.value}>
              {ct.label}
            </option>
          ))}
        </select>
      </label>
      {create.isError && (
        <p className="error-text" role="alert">
          {t("casb.create.error")}
        </p>
      )}
    </Modal>
  );
}
