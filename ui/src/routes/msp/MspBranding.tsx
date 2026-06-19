import { useEffect, useState } from "react";
import { useIntl, FormattedMessage } from "react-intl";
import {
  useGetTenantBranding,
  useSetTenantBranding,
  useClearTenantBranding,
} from "@/api/generated/endpoints/msps/msps";
import type { MSPBranding } from "@/api/generated/model";
import {
  PageHeader,
  Card,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { useToast } from "@/components/Toast";
import { useTenant } from "@/lib/tenant-context";
import { M } from "./lane-b6.messages";
import {
  LanePage,
  TenantScopeBanner,
  ConfirmDialog,
  LabelText,
} from "./_lane";
import { readableTextOn } from "./lane-utils";

// The branding API persists literal hex colours (not CSS vars), so the
// defaults are spelled out here. They mirror the ShieldNet brand tokens
// (`--brand` / `--brand-strong`) — never the cyan data-viz ramp.
const DEFAULT_PRIMARY = "#255fe5";
const DEFAULT_ACCENT = "#1e4fc4";

const EMPTY: MSPBranding = {
  logo_url: "",
  primary_color: DEFAULT_PRIMARY,
  secondary_color: DEFAULT_ACCENT,
  custom_domain: "",
  portal_support_to: "",
};

export function MspBranding() {
  const { formatMessage: fm } = useIntl();
  const { selectedTenant, selectedTenantId } = useTenant();
  const tenantId = selectedTenantId ?? "";

  return (
    <LanePage>
      <PageHeader title={fm(M.brandTitle)} subtitle={fm(M.brandSubtitle)} />
      {tenantId ? (
        <>
          <TenantScopeBanner name={selectedTenant?.name ?? tenantId} />
          <BrandingEditor key={tenantId} tenantId={tenantId} />
        </>
      ) : (
        <Card>
          <EmptyState
            illustration={<EmptyIllustration kind="shield" />}
            title={fm(M.scopeNoTenantTitle)}
            description={fm(M.scopeNoTenantBody)}
          />
        </Card>
      )}
    </LanePage>
  );
}

function BrandingEditor({ tenantId }: { tenantId: string }) {
  const { formatMessage: fm } = useIntl();
  const toast = useToast();
  const current = useGetTenantBranding(tenantId, { query: { retry: false } });
  const save = useSetTenantBranding();
  const clear = useClearTenantBranding();
  const [form, setForm] = useState<MSPBranding>(EMPTY);
  const [confirmReset, setConfirmReset] = useState(false);

  useEffect(() => {
    if (current.data) setForm({ ...EMPTY, ...current.data });
  }, [current.data]);

  const set = (k: keyof MSPBranding, v: string) =>
    setForm((prev) => ({ ...prev, [k]: v }));

  const primary = form.primary_color || DEFAULT_PRIMARY;
  const accent = form.secondary_color || DEFAULT_ACCENT;

  const onSave = () =>
    save.mutate(
      { tenantId, data: form },
      {
        onSuccess: () =>
          toast.success(fm(M.brandSavedTitle), fm(M.brandSavedBody)),
        onError: () => toast.error(fm(M.brandError)),
      },
    );

  const onReset = () =>
    clear.mutate(
      { tenantId },
      {
        onSuccess: () => {
          setForm(EMPTY);
          setConfirmReset(false);
          toast.success(fm(M.brandResetTitle), fm(M.brandResetBody));
        },
        onError: () => toast.error(fm(M.brandError)),
      },
    );

  return (
    <div className="grid grid--2" style={{ marginTop: 16 }}>
      <Card title={fm(M.brandConfig)}>
        <label className="field">
          <LabelText help={fm(M.brandLogoHelp)}>{fm(M.brandLogo)}</LabelText>
          <input
            value={form.logo_url ?? ""}
            onChange={(e) => set("logo_url", e.target.value)}
            placeholder="https://acme.com/logo.svg"
          />
        </label>
        <div className="field-row">
          <label className="field">
            <LabelText>{fm(M.brandPrimary)}</LabelText>
            <input
              type="color"
              value={primary}
              onChange={(e) => set("primary_color", e.target.value)}
            />
          </label>
          <label className="field">
            <LabelText>{fm(M.brandSecondary)}</LabelText>
            <input
              type="color"
              value={accent}
              onChange={(e) => set("secondary_color", e.target.value)}
            />
          </label>
        </div>
        <label className="field">
          <LabelText>{fm(M.brandDomain)}</LabelText>
          <input
            value={form.custom_domain ?? ""}
            onChange={(e) => set("custom_domain", e.target.value)}
            placeholder="portal.acme.com"
          />
        </label>
        <label className="field">
          <LabelText>{fm(M.brandSupport)}</LabelText>
          <input
            value={form.portal_support_to ?? ""}
            onChange={(e) => set("portal_support_to", e.target.value)}
            placeholder="support@acme.com"
          />
        </label>
        <div className="lb6-actions">
          <button className="btn btn--primary" disabled={save.isPending} onClick={onSave}>
            {save.isPending ? fm(M.brandSaving) : fm(M.brandSave)}
          </button>
          <button
            className="btn"
            disabled={clear.isPending}
            onClick={() => setConfirmReset(true)}
          >
            {fm(M.brandReset)}
          </button>
        </div>
      </Card>

      <Card title={fm(M.brandPreview)} subtitle={fm(M.brandPreviewSub)}>
        <div
          className="brand-preview"
          style={{ borderTop: `4px solid ${primary}` }}
        >
          <div
            className="brand-preview__bar"
            style={{ background: primary, color: readableTextOn(primary) }}
          >
            {form.logo_url ? (
              <img
                src={form.logo_url}
                alt={fm(M.brandPreviewLogoAlt)}
                style={{ height: 28 }}
              />
            ) : (
              <span style={{ fontWeight: 800 }}>ShieldNet</span>
            )}
          </div>
          <div className="brand-preview__body">
            <button
              className="btn"
              type="button"
              style={{
                background: accent,
                color: readableTextOn(accent),
                border: "none",
              }}
            >
              {fm(M.brandPreviewAction)}
            </button>
            <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
              {form.custom_domain ? (
                <FormattedMessage
                  {...M.brandPreviewServedAt}
                  values={{
                    domain: <span className="mono">{form.custom_domain}</span>,
                  }}
                />
              ) : (
                fm(M.brandPreviewDefaultDomain)
              )}
              {form.portal_support_to && (
                <>
                  {" · "}
                  <FormattedMessage
                    {...M.brandPreviewSupport}
                    values={{
                      email: (
                        <span className="mono">{form.portal_support_to}</span>
                      ),
                    }}
                  />
                </>
              )}
            </p>
          </div>
        </div>
      </Card>

      {confirmReset && (
        <ConfirmDialog
          title={fm(M.brandResetConfirmTitle)}
          confirmLabel={fm(M.brandReset)}
          busy={clear.isPending}
          onClose={() => setConfirmReset(false)}
          onConfirm={onReset}
        >
          <p>{fm(M.brandResetConfirmBody)}</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
