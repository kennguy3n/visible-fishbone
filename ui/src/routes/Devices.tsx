import { useState } from "react";
import { useListDevices, useCreateClaimToken } from "@/api/generated/endpoints/devices/devices";
import {
  exportDevicesCSV,
  useBulkRevokeDevices,
} from "@/api/generated/endpoints/bulk-device/bulk-device";
import type { Device, ClaimToken } from "@/api/generated/model";
import { PageHeader, Card, AsyncBoundary, StatusBadge, Badge } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { Modal } from "@/components/Modal";
import { RequireTenant } from "@/components/RequireTenant";
import { formatRelative, titleCase, summarizePosture } from "@/lib/format";

export function Devices() {
  return (
    <RequireTenant>{(tenantId) => <DevicesInner tenantId={tenantId} />}</RequireTenant>
  );
}

function DevicesInner({ tenantId }: { tenantId: string }) {
  const list = useListDevices(tenantId, undefined);
  const bulkRevoke = useBulkRevokeDevices();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [claim, setClaim] = useState(false);
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

  const onBulkRevoke = () => {
    if (selected.size === 0) return;
    if (!confirm(`Revoke ${selected.size} device(s)?`)) return;
    bulkRevoke.mutate(
      { tenantId, data: { device_ids: [...selected] } },
      { onSuccess: () => setSelected(new Set()) },
    );
  };

  const columns: Column<Device>[] = [
    {
      header: "",
      width: 36,
      cell: (d) => (
        <input
          type="checkbox"
          style={{ width: 16 }}
          checked={selected.has(d.id)}
          onChange={() => toggle(d.id)}
        />
      ),
    },
    { header: "Name", cell: (d) => d.name },
    { header: "Platform", cell: (d) => <Badge tone="neutral">{titleCase(d.platform)}</Badge> },
    { header: "Status", cell: (d) => <StatusBadge status={d.status} /> },
    {
      header: "Posture",
      cell: (d) => {
        const { tone, label } = summarizePosture(d.posture);
        return <Badge tone={tone}>{label}</Badge>;
      },
    },
    { header: "Last seen", cell: (d) => formatRelative(d.last_seen_at) },
  ];

  return (
    <>
      <PageHeader
        title="Devices"
        subtitle="Enrolled endpoints, posture and bulk lifecycle operations."
        actions={
          <>
            <button className="btn" onClick={onExport} disabled={exporting}>
              {exporting ? "Exporting…" : "Export CSV"}
            </button>
            <button
              className="btn btn--danger"
              onClick={onBulkRevoke}
              disabled={selected.size === 0 || bulkRevoke.isPending}
            >
              Revoke selected ({selected.size})
            </button>
            <button className="btn btn--primary" onClick={() => setClaim(true)}>
              + Claim token
            </button>
          </>
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
            <DataTable columns={columns} rows={d.items ?? []} rowKey={(x) => x.id} />
          )}
        </AsyncBoundary>
      </Card>
      {claim && <ClaimTokenModal tenantId={tenantId} onClose={() => setClaim(false)} />}
    </>
  );
}

function ClaimTokenModal({
  tenantId,
  onClose,
}: {
  tenantId: string;
  onClose: () => void;
}) {
  const create = useCreateClaimToken();
  const [ttl, setTtl] = useState(3600);
  const [token, setToken] = useState<ClaimToken | null>(null);

  return (
    <Modal
      title="Generate device claim token"
      onClose={onClose}
      footer={
        token ? (
          <button className="btn btn--primary" onClick={onClose}>
            Done
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn--primary"
              disabled={create.isPending}
              onClick={() =>
                create.mutate(
                  { tenantId, data: { ttl_seconds: ttl } },
                  { onSuccess: setToken },
                )
              }
            >
              {create.isPending ? "Generating…" : "Generate"}
            </button>
          </>
        )
      }
    >
      {token ? (
        <>
          <p className="muted">
            Copy this token now — it is shown only once. Provide it to the
            enrolling device agent.
          </p>
          <pre className="code-block">{token.token}</pre>
          <p className="muted" style={{ fontSize: 12 }}>
            Expires {new Date(token.expires_at).toLocaleString()}
          </p>
        </>
      ) : (
        <label className="field">
          <span>Time-to-live (seconds)</span>
          <input
            type="number"
            min={60}
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
          />
        </label>
      )}
    </Modal>
  );
}
