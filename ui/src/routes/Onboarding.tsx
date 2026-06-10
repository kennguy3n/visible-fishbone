import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useListSites, useCreateSite } from "@/api/generated/endpoints/sites/sites";
import {
  useCreateTenant,
  getListTenantsQueryKey,
} from "@/api/generated/endpoints/tenants/tenants";
import {
  useListDevices,
  useCreateClaimToken,
} from "@/api/generated/endpoints/devices/devices";
import {
  SiteCreateRequestTemplate,
  TenantCreateRequestTier,
} from "@/api/generated/model";
import type { ClaimToken, TenantResponse } from "@/api/generated/model";
import { useDlpTemplates, useApplyDlpTemplate } from "@/api/manual/hooks";
import { PageHeader, Card, Badge, Spinner } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { QrCode } from "@/components/QrCode";
import { useTenant } from "@/lib/tenant-context";
import { useToast } from "@/components/Toast";
import { runtimeConfig } from "@/lib/runtime-config";
import { titleCase } from "@/lib/format";

type TemplateValue =
  (typeof SiteCreateRequestTemplate)[keyof typeof SiteCreateRequestTemplate];
type TierValue =
  (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];

const SITE_TEMPLATE_BLURB: Record<string, string> = {
  branch: "A physical office with its own network — staff on-site share one internet breakout.",
  hub: "A central location that other sites connect back through.",
  cloud_only: "No hardware — protect cloud apps and remote staff only.",
  home_office: "A single remote worker, set up from their device.",
};

const TIER_BLURB: Record<string, string> = {
  starter: "Small teams getting started — core protection, sensible defaults.",
  professional: "Growing businesses — full policy control and integrations.",
  enterprise: "Large or regulated organisations — advanced controls and scale.",
};

// The wizard mirrors the operator's natural setup order: pick the tenant they
// are configuring, give it a site to route traffic through, federate identity,
// apply a baseline policy, then hand out the artefacts needed to deploy.
const STEPS = [
  "Tenant",
  "Site",
  "Identity",
  "Policy template",
  "Deploy",
] as const;

export function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const { selectedTenantId } = useTenant();

  // Steps 2–5 are tenant-scoped. Step 1 is where a tenant is chosen/created,
  // so we only assert a non-null id once the operator has advanced past it.
  // Guard against landing on a later step without a tenant (e.g. the active
  // tenant was deleted in another tab) by snapping back to the tenant step.
  useEffect(() => {
    if (step > 1 && !selectedTenantId) setStep(1);
  }, [step, selectedTenantId]);

  return (
    <div className="onboard">
      <PageHeader
        title="Get protected"
        subtitle="A five-step guided setup. You can leave and resume any time."
      />

      <ol className="stepper" aria-label="Onboarding progress">
        {STEPS.map((name, i) => {
          const n = i + 1;
          const state = n === step ? "active" : n < step ? "done" : "todo";
          return (
            <li key={name} className={`stepper__step stepper__step--${state}`}>
              <span className="stepper__dot">{n < step ? "✓" : n}</span>
              <span className="stepper__name">{name}</span>
              {i < STEPS.length - 1 && <span className="stepper__bar" />}
            </li>
          );
        })}
      </ol>

      {step === 1 && <StepTenant onNext={() => setStep(2)} />}
      {step === 2 && selectedTenantId && (
        <StepSite
          tenantId={selectedTenantId}
          onBack={() => setStep(1)}
          onNext={() => setStep(3)}
        />
      )}
      {step === 3 && selectedTenantId && (
        <StepIdentity onBack={() => setStep(2)} onNext={() => setStep(4)} />
      )}
      {step === 4 && selectedTenantId && (
        <StepPolicyTemplate
          tenantId={selectedTenantId}
          onBack={() => setStep(3)}
          onNext={() => setStep(5)}
        />
      )}
      {step === 5 && selectedTenantId && (
        <StepDeploy
          tenantId={selectedTenantId}
          onBack={() => setStep(4)}
          onFinish={() => navigate({ to: "/" })}
        />
      )}
    </div>
  );
}

// --- Step 1: Tenant --------------------------------------------------------

function StepTenant({ onNext }: { onNext: () => void }) {
  const { tenants, selectedTenantId, setSelectedTenantId, isLoading } =
    useTenant();
  const toast = useToast();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const create = useCreateTenant({
    mutation: {
      onSuccess: async (tenant: TenantResponse) => {
        // The generated mutation doesn't know about the tenant-list query, so
        // refetch it and make the freshly-created tenant the active one before
        // advancing — otherwise step 2 would run against the previous tenant.
        // react-query keeps the mutation in `pending` (isPending === true) until
        // this awaited onSuccess resolves, so the buttons below stay disabled
        // across the whole invalidate-then-select window with no extra latch.
        await qc.invalidateQueries({ queryKey: getListTenantsQueryKey() });
        setSelectedTenantId(tenant.id);
        toast.success("Tenant created", `${tenant.name} is now active.`);
        onNext();
      },
      onError: (e) =>
        toast.error(
          "Could not create tenant",
          e instanceof Error ? e.message : undefined,
        ),
    },
  });
  const busy = create.isPending;

  return (
    <Card title="Choose the tenant to set up">
      <p>
        ShieldNet protects your business's internet traffic — blocking threats,
        stopping data leaks and keeping remote staff safe — without needing an
        IT team to run it. Everything in this wizard applies to the tenant you
        pick here.
      </p>
      <div className="overview-anim" aria-hidden>
        <div className="overview-anim__node overview-anim__node--user">Staff</div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--sng">ShieldNet</div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--net">Internet</div>
      </div>

      {isLoading ? (
        <div className="skeleton" style={{ height: 96 }} />
      ) : tenants.length > 0 ? (
        <>
          <div className="field">
            <span>Existing tenants</span>
            <div className="choice-grid" style={{ marginTop: 6 }}>
              {tenants.map((t) => (
                <button
                  key={t.id}
                  className={`choice${selectedTenantId === t.id ? " choice--selected" : ""}`}
                  onClick={() => setSelectedTenantId(t.id)}
                  aria-pressed={selectedTenantId === t.id}
                >
                  <div className="choice__name">{t.name}</div>
                  <div className="choice__desc">
                    <span className="mono">{t.slug}</span>
                    {t.region ? ` · ${t.region}` : ""}
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <Badge tone="info">{titleCase(t.tier)}</Badge>
                  </div>
                </button>
              ))}
            </div>
          </div>
          {!creating && (
            <button
              className="btn"
              style={{ marginTop: 12 }}
              onClick={() => setCreating(true)}
            >
              + Create a new tenant instead
            </button>
          )}
        </>
      ) : (
        <p className="muted">
          You don't have any tenants yet. Create your first one to begin.
        </p>
      )}

      {!isLoading && (creating || tenants.length === 0) && (
        <NewTenantForm
          busy={busy}
          onCancel={tenants.length > 0 ? () => setCreating(false) : undefined}
          onCreate={(data) => create.mutate({ data })}
        />
      )}

      <div className="onboard__actions">
        <button
          className="btn btn--primary"
          onClick={onNext}
          disabled={!selectedTenantId || busy}
        >
          Continue →
        </button>
      </div>
    </Card>
  );
}

function NewTenantForm({
  busy,
  onCancel,
  onCreate,
}: {
  busy: boolean;
  onCancel?: () => void;
  onCreate: (data: {
    name: string;
    slug?: string;
    region?: string;
    tier: TierValue;
  }) => void;
}) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [region, setRegion] = useState("");
  const [tier, setTier] = useState<TierValue>(TenantCreateRequestTier.starter);
  const tiers = Object.values(TenantCreateRequestTier) as TierValue[];

  return (
    <div
      style={{
        marginTop: 16,
        paddingTop: 16,
        borderTop: "1px solid var(--border-soft)",
      }}
    >
      <h3 style={{ margin: "0 0 10px", fontSize: 14 }}>New tenant</h3>
      <label className="field">
        <span>
          Business name{" "}
          <HelpTooltip title="Business name">
            The organisation this tenant represents, e.g. "Acme Ltd". Shown
            throughout the console.
          </HelpTooltip>
        </span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Acme Ltd"
        />
      </label>
      <label className="field">
        <span>
          Slug (optional){" "}
          <HelpTooltip title="Slug">
            A short, lowercase identifier used in URLs and configs. Leave blank
            and we'll generate one from the name.
          </HelpTooltip>
        </span>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="acme"
        />
      </label>
      <label className="field">
        <span>
          Region (optional){" "}
          <HelpTooltip title="Region">
            Where this tenant's data is processed. Leave blank to use the
            platform default.
          </HelpTooltip>
        </span>
        <input
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          placeholder="e.g. eu-west-1"
        />
      </label>
      <div className="field">
        <span>Plan tier</span>
        <div className="choice-grid" style={{ marginTop: 6 }}>
          {tiers.map((t) => (
            <button
              key={t}
              className={`choice${tier === t ? " choice--selected" : ""}`}
              onClick={() => setTier(t)}
              aria-pressed={tier === t}
            >
              <div className="choice__name">{titleCase(t)}</div>
              <div className="choice__desc">{TIER_BLURB[t] ?? ""}</div>
            </button>
          ))}
        </div>
      </div>
      <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
        <button
          className="btn btn--primary"
          disabled={!name.trim() || busy}
          onClick={() =>
            onCreate({
              name: name.trim(),
              slug: slug.trim() || undefined,
              region: region.trim() || undefined,
              tier,
            })
          }
        >
          {busy ? "Creating…" : "Create tenant →"}
        </button>
        {onCancel && (
          <button className="btn" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}

// --- Step 2: Site ----------------------------------------------------------

function StepSite({
  tenantId,
  onBack,
  onNext,
}: {
  tenantId: string;
  onBack: () => void;
  onNext: () => void;
}) {
  const sites = useListSites(tenantId);
  const create = useCreateSite();
  const toast = useToast();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [template, setTemplate] = useState<TemplateValue>(
    SiteCreateRequestTemplate.branch,
  );

  const existing = sites.data?.items?.length ?? 0;
  const templates = Object.values(SiteCreateRequestTemplate) as TemplateValue[];

  const submit = () => {
    create.mutate(
      {
        tenantId,
        data: { name: name.trim(), slug: slug.trim() || undefined, template },
      },
      {
        onSuccess: () => {
          toast.success("Site created", `${name.trim()} is now connected.`);
          onNext();
        },
        onError: (e) =>
          toast.error(
            "Could not create site",
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  return (
    <Card title="Add your first site">
      {existing > 0 && (
        <p className="muted">
          You already have {existing} site{existing === 1 ? "" : "s"}. Add
          another or continue.
        </p>
      )}
      <label className="field">
        <span>
          Site name{" "}
          <HelpTooltip title="Site name">
            A friendly name for this location, e.g. "London HQ" or "Warehouse".
            It's just for you to recognise it.
          </HelpTooltip>
        </span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. London HQ"
        />
      </label>
      <label className="field">
        <span>
          Slug (optional){" "}
          <HelpTooltip title="Slug">
            A short, lowercase identifier used in URLs and configs. Leave blank
            and we'll generate one from the name.
          </HelpTooltip>
        </span>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="london-hq"
        />
      </label>
      <div className="field">
        <span>
          Deployment type{" "}
          <HelpTooltip title="Deployment type">
            How this location connects. Most offices are a "Branch". Choose
            "Cloud only" if there's no physical network to protect.
          </HelpTooltip>
        </span>
        <div className="choice-grid" style={{ marginTop: 6 }}>
          {templates.map((t) => (
            <button
              key={t}
              className={`choice${template === t ? " choice--selected" : ""}`}
              onClick={() => setTemplate(t)}
              aria-pressed={template === t}
            >
              <div className="choice__name">{titleCase(t)}</div>
              <div className="choice__desc">{SITE_TEMPLATE_BLURB[t] ?? ""}</div>
            </button>
          ))}
        </div>
      </div>
      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          ← Back
        </button>
        <div style={{ display: "flex", gap: 10 }}>
          {existing > 0 && (
            <button className="btn" onClick={onNext} disabled={create.isPending}>
              Skip →
            </button>
          )}
          <button
            className="btn btn--primary"
            onClick={submit}
            disabled={!name.trim() || create.isPending}
          >
            {create.isPending ? "Creating…" : "Create site →"}
          </button>
        </div>
      </div>
    </Card>
  );
}

// --- Step 3: Identity (SSO) ------------------------------------------------

async function fetchDiscovery(
  issuer: string,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const base = issuer.replace(/\/+$/, "");
  const url = base.endsWith("/.well-known/openid-configuration")
    ? base
    : `${base}/.well-known/openid-configuration`;
  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`Discovery failed (${res.status})`);
  return (await res.json()) as Record<string, unknown>;
}

function StepIdentity({
  onBack,
  onNext,
}: {
  onBack: () => void;
  onNext: () => void;
}) {
  const cfg = runtimeConfig();
  const [discovery, setDiscovery] = useState<Record<string, unknown> | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Bumped by the Retry button to re-run verification without leaving the step;
  // a transient network/issuer blip shouldn't force the operator to navigate
  // away and back.
  const [reloadKey, setReloadKey] = useState(0);

  // SSO is wired in at deploy time via runtime config (the static console image
  // reads window.__SNG_CONFIG__), not through a per-tenant API — so this step
  // verifies the live federation rather than writing config. We confirm the
  // issuer is reachable and its discovery document is well-formed before the
  // operator relies on it for sign-in.
  useEffect(() => {
    if (cfg.authMode !== "oidc" || !cfg.oidcIssuer) return;
    // Abort the in-flight discovery GET when the step unmounts or re-runs, so a
    // slow/hung issuer can't keep a request open after the operator has moved
    // on — mirrors how the generated hooks thread `signal` into `sngRequest`.
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    fetchDiscovery(cfg.oidcIssuer, controller.signal)
      .then((d) => {
        if (!controller.signal.aborted) setDiscovery(d);
      })
      .catch((e) => {
        // An abort is our own cleanup, not a verification failure — ignore it.
        if (controller.signal.aborted) return;
        setError(e instanceof Error ? e.message : "Discovery failed");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => {
      controller.abort();
    };
  }, [cfg.authMode, cfg.oidcIssuer, reloadKey]);

  return (
    <Card
      title="Connect your identity provider"
      actions={
        <HelpTooltip title="Single sign-on" align="right">
          ShieldNet federates sign-in to your identity provider (Okta, Entra ID,
          Google Workspace, …) over OIDC, and can sync users and groups via
          SCIM. SSO is configured when the console is deployed; here we verify
          it's live.
        </HelpTooltip>
      }
    >
      {cfg.authMode === "oidc" ? (
        <>
          <div style={{ marginBottom: 12 }}>
            <Badge tone="ok">OIDC / SSO enabled</Badge>
          </div>
          <dl className="kv">
            <dt>Issuer</dt>
            <dd className="mono">{cfg.oidcIssuer || "—"}</dd>
            <dt>Client ID</dt>
            <dd className="mono">{cfg.oidcClientId || "—"}</dd>
            <dt>Scopes</dt>
            <dd className="mono">{cfg.oidcScope}</dd>
          </dl>
          <div style={{ marginTop: 12 }}>
            {loading ? (
              <div
                style={{ display: "flex", gap: 8, alignItems: "center" }}
              >
                <Spinner />
                <span className="muted">Verifying issuer…</span>
              </div>
            ) : error ? (
              <>
                <p className="error-text">
                  Could not reach the issuer's discovery document: {error}.
                  Check the issuer URL and that it's reachable from the browser.
                </p>
                <button
                  className="btn"
                  style={{ marginTop: 8 }}
                  onClick={() => setReloadKey((k) => k + 1)}
                >
                  Retry verification
                </button>
              </>
            ) : discovery ? (
              <>
                <p style={{ color: "var(--ok)", fontSize: 13 }}>
                  ✓ Discovery document verified — single sign-on is ready.
                </p>
                <dl className="kv">
                  <dt>Authorization</dt>
                  <dd className="mono">
                    {String(discovery.authorization_endpoint ?? "—")}
                  </dd>
                  <dt>Token</dt>
                  <dd className="mono">
                    {String(discovery.token_endpoint ?? "—")}
                  </dd>
                  <dt>JWKS</dt>
                  <dd className="mono">{String(discovery.jwks_uri ?? "—")}</dd>
                </dl>
              </>
            ) : null}
          </div>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
            To provision users and groups automatically, configure SCIM on the{" "}
            <Link to="/scim">directory sync</Link> page. Full federation details
            live on the <Link to="/idp">identity provider</Link> page.
          </p>
        </>
      ) : (
        <>
          <div style={{ marginBottom: 12 }}>
            <Badge tone="info">JWT bearer (development)</Badge>
          </div>
          <p>
            This console is running in development authentication mode, where it
            accepts a pasted HMAC-signed JWT. To federate sign-in to your
            identity provider, set <span className="mono">auth_mode=oidc</span>{" "}
            with the issuer and client ID in the deploy-time runtime config, then
            re-run this step to verify the connection.
          </p>
          <p className="muted" style={{ fontSize: 12.5 }}>
            You can still continue and finish onboarding — SSO can be enabled
            later without redoing the rest of the setup.
          </p>
        </>
      )}

      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          ← Back
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          Continue →
        </button>
      </div>
    </Card>
  );
}

// --- Step 4: Policy template -----------------------------------------------

function StepPolicyTemplate({
  tenantId,
  onBack,
  onNext,
}: {
  tenantId: string;
  onBack: () => void;
  onNext: () => void;
}) {
  const templates = useDlpTemplates(tenantId);
  const apply = useApplyDlpTemplate(tenantId);
  const toast = useToast();
  const [selected, setSelected] = useState<string | null>(null);

  const items = templates.data?.items ?? [];

  const applyAndContinue = () => {
    if (!selected) {
      onNext();
      return;
    }
    apply.mutate(selected, {
      onSuccess: () => {
        toast.success(
          "Protection applied",
          "Your data-loss policy is now active.",
        );
        onNext();
      },
      onError: (e) =>
        toast.error(
          "Could not apply template",
          e instanceof Error ? e.message : undefined,
        ),
    });
  };

  return (
    <Card
      title="Apply a policy template"
      actions={
        <HelpTooltip title="Policy templates" align="right">
          These are pre-built data-loss prevention (DLP) policies. They decide
          what sensitive information — card numbers, ID numbers, secrets —
          ShieldNet watches for and blocks. You can fine-tune everything later.
        </HelpTooltip>
      }
    >
      {templates.isLoading ? (
        <div className="skeleton" style={{ height: 120 }} />
      ) : items.length === 0 ? (
        <p className="muted">
          No policy templates are published for this tenant yet. You can skip
          this step and configure DLP later from the DLP page.
        </p>
      ) : (
        <div className="choice-grid">
          {items.map((t) => (
            <button
              key={t.id}
              className={`choice${selected === t.id ? " choice--selected" : ""}`}
              onClick={() => setSelected(t.id)}
              aria-pressed={selected === t.id}
            >
              <div className="choice__name">{titleCase(t.name)}</div>
              <div className="choice__desc">{t.description}</div>
              <div style={{ marginTop: 8 }}>
                <Badge tone="info">{t.rules?.length ?? 0} rules</Badge>
              </div>
            </button>
          ))}
        </div>
      )}
      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          ← Back
        </button>
        <button
          className="btn btn--primary"
          onClick={applyAndContinue}
          disabled={apply.isPending}
        >
          {apply.isPending
            ? "Applying…"
            : selected
              ? "Apply & continue →"
              : "Skip for now →"}
        </button>
      </div>
    </Card>
  );
}

// --- Step 5: Deploy --------------------------------------------------------

function StepDeploy({
  tenantId,
  onBack,
  onFinish,
}: {
  tenantId: string;
  onBack: () => void;
  onFinish: () => void;
}) {
  const create = useCreateClaimToken();
  const devices = useListDevices(tenantId, undefined);
  const toast = useToast();
  const [token, setToken] = useState<ClaimToken | null>(null);
  const [copied, setCopied] = useState(false);
  // Track the "Copied" reset timer so we can clear it before re-arming (rapid
  // re-clicks) and on unmount, mirroring the async-cleanup discipline used in
  // QrCode rather than leaving a stray timer to fire setState after unmount.
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (copyTimer.current) clearTimeout(copyTimer.current);
    },
    [],
  );

  const enrolled = devices.data?.items?.length ?? 0;

  const generate = () => {
    create.mutate(
      { tenantId, data: { ttl_seconds: 3600 } },
      {
        onSuccess: setToken,
        onError: (e) =>
          toast.error(
            "Could not generate token",
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  const copy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token.token);
      setCopied(true);
      toast.success("Copied", "Claim token copied to your clipboard.");
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Copy failed", "Select the token and copy it manually.");
    }
  };

  return (
    <Card title="Deploy & enrol your first device">
      <p className="muted">
        A claim token lets a device join this tenant securely. Generate one,
        then install the ShieldNet agent on the device and paste the token (or
        scan the QR) when it asks.
      </p>
      {enrolled > 0 && (
        <p className="muted">
          {enrolled} device{enrolled === 1 ? "" : "s"} already enrolled.
        </p>
      )}

      {!token ? (
        <button
          className="btn btn--primary"
          onClick={generate}
          disabled={create.isPending}
        >
          {create.isPending ? "Generating…" : "Generate claim token"}
        </button>
      ) : (
        <div className="grid grid--2" style={{ marginTop: 4 }}>
          <div>
            <label className="field">
              <span>Claim token (shown once)</span>
              <div className="copy-field">
                <input readOnly value={token.token} className="mono" />
                <button className="btn" onClick={copy}>
                  {copied ? "Copied ✓" : "Copy"}
                </button>
              </div>
            </label>
            <p className="muted" style={{ fontSize: 12 }}>
              Expires {new Date(token.expires_at).toLocaleString()}. Generate a
              fresh token if it lapses.
            </p>
            <p style={{ fontSize: 13 }}>
              On the device, install the ShieldNet agent and choose{" "}
              <b>Enrol with token</b>, then paste the value above. Mobile agents
              can scan the QR instead.
            </p>
          </div>
          <div style={{ display: "grid", placeItems: "center" }}>
            <QrCode value={token.token} size={168} />
            <span className="muted" style={{ fontSize: 12, marginTop: 8 }}>
              Scan with the mobile agent
            </span>
          </div>
        </div>
      )}

      <div
        style={{
          marginTop: 18,
          paddingTop: 16,
          borderTop: "1px solid var(--border-soft)",
        }}
      >
        <h3 style={{ margin: "0 0 6px", fontSize: 14 }}>
          You're protected 🎉
        </h3>
        <p className="muted" style={{ fontSize: 13 }}>
          ShieldNet is now watching this tenant's traffic. Here's where to go
          next:
        </p>
        <ul className="done-links">
          <li>
            <Link to="/">Dashboard</Link> — your security posture at a glance.
          </li>
          <li>
            <Link to="/alerts">Alerts</Link> — anomalies and threats as they're
            detected.
          </li>
          <li>
            <Link to="/policy">Policy</Link> — review and fine-tune what's
            allowed.
          </li>
          <li>
            <Link to="/devices">Devices</Link> — enrol more devices any time.
          </li>
        </ul>
      </div>

      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          ← Back
        </button>
        <button className="btn btn--primary" onClick={onFinish}>
          Go to dashboard →
        </button>
      </div>
    </Card>
  );
}
