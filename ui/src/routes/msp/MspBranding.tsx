import { useEffect, useState } from "react";
import {
  useGetTenantBranding,
  useSetTenantBranding,
  useClearTenantBranding,
} from "@/api/generated/endpoints/msps/msps";
import type { MSPBranding } from "@/api/generated/model";
import { PageHeader, Card } from "@/components/ui";
import { useTenant } from "@/lib/tenant-context";

const EMPTY: MSPBranding = {
  logo_url: "",
  primary_color: "#3b82f6",
  secondary_color: "#22d3ee",
  custom_domain: "",
  portal_support_to: "",
};

export function MspBranding() {
  const { tenants, selectedTenantId, setSelectedTenantId } = useTenant();
  const tenantId = selectedTenantId ?? "";

  return (
    <>
      <PageHeader
        title="MSP branding"
        subtitle="Per-tenant white-label portal configuration."
      />
      <Card>
        <label className="field" style={{ maxWidth: 360 }}>
          <span>Tenant</span>
          <select
            value={tenantId}
            onChange={(e) => setSelectedTenantId(e.target.value)}
          >
            {tenants.length === 0 && <option value="">No tenants</option>}
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
      </Card>
      {tenantId && <BrandingEditor key={tenantId} tenantId={tenantId} />}
    </>
  );
}

function BrandingEditor({ tenantId }: { tenantId: string }) {
  const current = useGetTenantBranding(tenantId, { query: { retry: false } });
  const save = useSetTenantBranding();
  const clear = useClearTenantBranding();
  const [form, setForm] = useState<MSPBranding>(EMPTY);

  useEffect(() => {
    if (current.data) setForm({ ...EMPTY, ...current.data });
  }, [current.data]);

  const set = (k: keyof MSPBranding, v: string) =>
    setForm((prev) => ({ ...prev, [k]: v }));

  return (
    <div className="grid grid--2" style={{ marginTop: 16 }}>
      <Card title="Configuration">
        <label className="field">
          <span>Logo URL</span>
          <input value={form.logo_url ?? ""} onChange={(e) => set("logo_url", e.target.value)} />
        </label>
        <div className="field-row">
          <label className="field">
            <span>Primary color</span>
            <input
              type="color"
              value={form.primary_color || "#3b82f6"}
              onChange={(e) => set("primary_color", e.target.value)}
            />
          </label>
          <label className="field">
            <span>Secondary color</span>
            <input
              type="color"
              value={form.secondary_color || "#22d3ee"}
              onChange={(e) => set("secondary_color", e.target.value)}
            />
          </label>
        </div>
        <label className="field">
          <span>Custom domain</span>
          <input
            value={form.custom_domain ?? ""}
            onChange={(e) => set("custom_domain", e.target.value)}
            placeholder="portal.acme.com"
          />
        </label>
        <label className="field">
          <span>Support email</span>
          <input
            value={form.portal_support_to ?? ""}
            onChange={(e) => set("portal_support_to", e.target.value)}
            placeholder="support@acme.com"
          />
        </label>
        <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
          <button
            className="btn btn--primary"
            disabled={save.isPending}
            onClick={() => save.mutate({ tenantId, data: form })}
          >
            {save.isPending ? "Saving…" : "Save branding"}
          </button>
          <button
            className="btn btn--danger"
            disabled={clear.isPending}
            onClick={() => clear.mutate({ tenantId }, { onSuccess: () => setForm(EMPTY) })}
          >
            Reset to default
          </button>
        </div>
        {save.isSuccess && <p style={{ color: "var(--ok)" }}>Branding saved.</p>}
      </Card>

      <Card title="Live preview">
        <div
          className="brand-preview"
          style={{
            borderTop: `4px solid ${form.primary_color || "#3b82f6"}`,
          }}
        >
          <div
            className="brand-preview__bar"
            style={{ background: form.primary_color || "#3b82f6" }}
          >
            {form.logo_url ? (
              <img src={form.logo_url} alt="logo" style={{ height: 28 }} />
            ) : (
              <span style={{ fontWeight: 800, color: "#fff" }}>ShieldNet</span>
            )}
          </div>
          <div className="brand-preview__body">
            <button
              className="btn"
              style={{
                background: form.secondary_color || "#22d3ee",
                color: "#04121f",
                border: "none",
              }}
            >
              Primary action
            </button>
            <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
              {form.custom_domain ? (
                <>
                  Served at <span className="mono">{form.custom_domain}</span>
                </>
              ) : (
                "Default platform domain"
              )}
              {form.portal_support_to && (
                <>
                  {" "}
                  · support <span className="mono">{form.portal_support_to}</span>
                </>
              )}
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}
