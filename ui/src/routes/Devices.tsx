import { useEffect, useRef, useState } from "react";
import { useListDevices, useCreateClaimToken } from "@/api/generated/endpoints/devices/devices";
import {
  exportDevicesCSV,
  useBulkRevokeDevices,
} from "@/api/generated/endpoints/bulk-device/bulk-device";
import type { Device, ClaimToken } from "@/api/generated/model";
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
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { formatDateTime, formatRelative, summarizePosture, type Tone } from "@/lib/format";
import { LaneB3Intl, useB3, type B3Key } from "./lane-b3-i18n";
import "./lane-b3.css";

export function Devices() {
  return (
    <RequireTenant>
      {(tenantId) => (
        <LaneB3Intl>
          <DevicesInner tenantId={tenantId} />
        </LaneB3Intl>
      )}
    </RequireTenant>
  );
}

const PLATFORM_KEYS: Record<string, B3Key> = {
  windows: "dev.platform.windows",
  macos: "dev.platform.macos",
  linux: "dev.platform.linux",
  ios: "dev.platform.ios",
  android: "dev.platform.android",
};

// A device's posture maps to a single, plain-language access outcome so the
// admin can read "what can this device reach?" straight off the row. We key the
// mapping off the foundation's posture tone (a stable enum) rather than its
// English label.
function postureView(posture: unknown): {
  postureKey: B3Key;
  accessKey: B3Key;
  tone: Tone;
} {
  const { tone } = summarizePosture(posture);
  switch (tone) {
    case "ok":
      return { postureKey: "dev.posture.healthy", accessKey: "dev.access.allowed", tone: "ok" };
    case "warn":
      return { postureKey: "dev.posture.atrisk", accessKey: "dev.access.limited", tone: "warn" };
    case "danger":
      return { postureKey: "dev.posture.compromised", accessKey: "dev.access.blocked", tone: "danger" };
    default:
      return { postureKey: "dev.posture.unknown", accessKey: "dev.access.unknown", tone: "neutral" };
  }
}

function DevicesInner({ tenantId }: { tenantId: string }) {
  const t = useB3();
  const toast = useToast();
  const list = useListDevices(tenantId, undefined);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [claim, setClaim] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [exporting, setExporting] = useState(false);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const onExport = async () => {
    setExporting(true);
    try {
      const blob = await exportDevicesCSV(tenantId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `devices-${tenantId}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="lane-b3">
      <PageHeader
        title={t("dev.title")}
        subtitle={t("dev.subtitle")}
        actions={
          <>
            <button className="btn" onClick={onExport} disabled={exporting}>
              {exporting ? t("dev.exporting") : t("dev.export")}
            </button>
            <button
              className="btn btn--danger"
              onClick={() => setRevoke(true)}
              disabled={selected.size === 0}
            >
              {t("dev.revoke", { count: selected.size })}
            </button>
            <button className="btn btn--primary" onClick={() => setClaim(true)}>
              {t("dev.claim")}
            </button>
          </>
        }
      />
      <Card
        actions={
          <HelpTooltip title={t("dev.posture.help.title")} align="right">
            {t("dev.posture.help.body")}
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
              illustration={<EmptyIllustration kind="inbox" />}
              title={t("dev.empty.title")}
              description={t("dev.empty.desc")}
              action={
                <button className="btn btn--primary btn--sm" onClick={() => setClaim(true)}>
                  {t("dev.claim")}
                </button>
              }
            />
          }
        >
          {(d) => (
            <DevicesTable
              devices={d.items ?? []}
              selected={selected}
              onToggle={toggle}
              onToggleAll={(ids, checked) =>
                setSelected((prev) => {
                  const next = new Set(prev);
                  ids.forEach((id) => (checked ? next.add(id) : next.delete(id)));
                  return next;
                })
              }
            />
          )}
        </AsyncBoundary>
      </Card>
      {claim && <ClaimTokenModal tenantId={tenantId} onClose={() => setClaim(false)} />}
      {revoke && (
        <RevokeModal
          tenantId={tenantId}
          ids={[...selected]}
          onClose={() => setRevoke(false)}
          onDone={() => {
            setSelected(new Set());
            setRevoke(false);
          }}
          onSuccess={(n) => toast.success(t("dev.revoke.success.title"), t("dev.revoke.success.body", { count: n }))}
          onError={() => toast.error(t("dev.revoke.failed.title"), t("dev.revoke.failed.body"))}
        />
      )}
    </div>
  );
}

function DevicesTable({
  devices,
  selected,
  onToggle,
  onToggleAll,
}: {
  devices: Device[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  onToggleAll: (ids: string[], checked: boolean) => void;
}) {
  const t = useB3();
  const ids = devices.map((d) => d.id);
  const selectedCount = ids.filter((id) => selected.has(id)).length;
  const allSelected = ids.length > 0 && selectedCount === ids.length;
  const someSelected = selectedCount > 0 && !allSelected;
  const selectAllRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = someSelected;
  }, [someSelected]);

  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th style={{ width: 36 }}>
              <input
                ref={selectAllRef}
                type="checkbox"
                style={{ width: 16 }}
                aria-label={t("dev.col.selectAll")}
                checked={allSelected}
                onChange={(e) => onToggleAll(ids, e.target.checked)}
              />
            </th>
            <th>{t("dev.col.name")}</th>
            <th>{t("dev.col.platform")}</th>
            <th>{t("dev.col.status")}</th>
            <th>{t("dev.col.posture")}</th>
            <th>{t("dev.col.access")}</th>
            <th>{t("dev.col.lastSeen")}</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => {
            const view = postureView(d.posture);
            return (
              <tr key={d.id}>
                <td>
                  <input
                    type="checkbox"
                    style={{ width: 16 }}
                    aria-label={t("dev.col.selectRow", { name: d.name })}
                    checked={selected.has(d.id)}
                    onChange={() => onToggle(d.id)}
                  />
                </td>
                <td>{d.name}</td>
                <td>
                  <Badge tone="neutral">
                    {PLATFORM_KEYS[d.platform?.toLowerCase()] ? t(PLATFORM_KEYS[d.platform.toLowerCase()]) : d.platform}
                  </Badge>
                </td>
                <td>
                  <StatusBadge status={d.status} />
                </td>
                <td>
                  <Badge tone={view.tone}>{t(view.postureKey)}</Badge>
                </td>
                <td>
                  <Badge tone={view.tone} dot>
                    {t(view.accessKey)}
                  </Badge>
                </td>
                <td>{formatRelative(d.last_seen_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RevokeModal({
  tenantId,
  ids,
  onClose,
  onDone,
  onSuccess,
  onError,
}: {
  tenantId: string;
  ids: string[];
  onClose: () => void;
  onDone: () => void;
  onSuccess: (count: number) => void;
  onError: () => void;
}) {
  const t = useB3();
  const bulkRevoke = useBulkRevokeDevices();

  const submit = () =>
    bulkRevoke.mutate(
      { tenantId, data: { device_ids: ids } },
      {
        onSuccess: () => {
          onSuccess(ids.length);
          onDone();
        },
        onError: () => onError(),
      },
    );

  return (
    <Modal
      title={t("dev.revoke.confirm.title", { count: ids.length })}
      onClose={() => {
        if (!bulkRevoke.isPending) onClose();
      }}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={bulkRevoke.isPending}>
            {t("dev.revoke.confirm.cancel")}
          </button>
          <button className="btn btn--danger" onClick={submit} disabled={bulkRevoke.isPending}>
            {bulkRevoke.isPending ? t("dev.revoke.revoking") : t("dev.revoke.confirm.submit")}
          </button>
        </>
      }
    >
      <p style={{ marginTop: 0 }}>{t("dev.revoke.confirm.body")}</p>
    </Modal>
  );
}

function ClaimTokenModal({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const t = useB3();
  const toast = useToast();
  const create = useCreateClaimToken();
  const [ttl, setTtl] = useState(3600);
  const [token, setToken] = useState<ClaimToken | null>(null);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error(t("dev.claim.failed.title"), t("dev.claim.failed.body"));
    }
  };

  return (
    <Modal
      title={t("dev.claim.title")}
      onClose={onClose}
      footer={
        token ? (
          <button className="btn btn--primary" onClick={onClose}>
            {t("dev.claim.done")}
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {t("dev.claim.cancel")}
            </button>
            <button
              className="btn btn--primary"
              disabled={create.isPending}
              onClick={() =>
                create.mutate(
                  { tenantId, data: { ttl_seconds: ttl } },
                  {
                    onSuccess: setToken,
                    onError: () => toast.error(t("dev.claim.failed.title"), t("dev.claim.failed.body")),
                  },
                )
              }
            >
              {create.isPending ? t("dev.claim.generating") : t("dev.claim.generate")}
            </button>
          </>
        )
      }
    >
      {token ? (
        <>
          <p style={{ marginTop: 0, fontWeight: 600 }}>{t("dev.claim.token.title")}</p>
          <div className="b3-token">
            <pre className="code-block">{token.token}</pre>
            <button className="btn btn--sm" onClick={copy}>
              {copied ? t("dev.claim.token.copied") : t("dev.claim.token.copy")}
            </button>
          </div>
          <p className="muted" style={{ marginTop: 10 }}>
            {t("dev.claim.token.warn")}
          </p>
          <p className="muted" style={{ fontSize: 12 }}>
            {t("dev.claim.token.expires", { datetime: formatDateTime(token.expires_at) })}
          </p>
        </>
      ) : (
        <>
          <p style={{ marginTop: 0 }}>{t("dev.claim.intro")}</p>
          <label className="field">
            <span>{t("dev.claim.ttl")}</span>
            <input
              type="number"
              min={60}
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
            />
          </label>
          <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
            {t("dev.claim.ttl.help")}
          </p>
        </>
      )}
    </Modal>
  );
}
