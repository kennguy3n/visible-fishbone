import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { FormattedMessage, useIntl } from "react-intl";
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
import { LaneB1Intl } from "./lane-b1-intl";
import { Stepper } from "./lane-b1-stepper";
import "./lane-b1.css";

type TemplateValue =
  (typeof SiteCreateRequestTemplate)[keyof typeof SiteCreateRequestTemplate];
type TierValue =
  (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];

// The wizard mirrors the operator's natural setup order: pick the tenant they
// are configuring, give it a site to route traffic through, federate identity,
// apply a baseline policy, then hand out the artefacts needed to deploy.
export function Onboarding() {
  return (
    <LaneB1Intl>
      <OnboardingInner />
    </LaneB1Intl>
  );
}

function OnboardingInner() {
  const intl = useIntl();
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

  // Steps are pipe-delimited (not comma) so a translated label can safely
  // contain a comma without changing the number of steps.
  const steps = intl.formatMessage({ id: "b1.onboard.steps" }).split("|");

  return (
    <div className="onboard lane-b1">
      <PageHeader
        title={intl.formatMessage({ id: "b1.onboard.title" })}
        subtitle={intl.formatMessage({ id: "b1.onboard.subtitle" })}
      />

      <Stepper steps={steps} current={step} />

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
  const intl = useIntl();
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
        toast.success(
          intl.formatMessage({ id: "b1.onboard.toast.tenantCreated.title" }),
          intl.formatMessage(
            { id: "b1.onboard.toast.tenantCreated.body" },
            { name: tenant.name },
          ),
        );
        onNext();
      },
      onError: (e) =>
        toast.error(
          intl.formatMessage({ id: "b1.onboard.toast.tenantFailed" }),
          e instanceof Error ? e.message : undefined,
        ),
    },
  });
  const busy = create.isPending;

  return (
    <Card title={intl.formatMessage({ id: "b1.onboard.tenant.title" })}>
      <p>
        <FormattedMessage id="b1.onboard.tenant.intro" />
      </p>
      <div className="overview-anim" aria-hidden>
        <div className="overview-anim__node overview-anim__node--user">
          <FormattedMessage id="b1.onboard.anim.staff" />
        </div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--sng">
          <FormattedMessage id="b1.onboard.anim.sng" />
        </div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--net">
          <FormattedMessage id="b1.onboard.anim.internet" />
        </div>
      </div>

      {isLoading ? (
        <div className="skeleton" style={{ height: 96 }} />
      ) : tenants.length > 0 ? (
        <>
          <div className="field">
            <span>
              <FormattedMessage id="b1.onboard.tenant.existing" />
            </span>
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
              + <FormattedMessage id="b1.onboard.tenant.createInstead" />
            </button>
          )}
        </>
      ) : (
        <p className="muted">
          <FormattedMessage id="b1.onboard.tenant.none" />
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
          <FormattedMessage id="b1.onboard.cta.continue" />
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
  const intl = useIntl();
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
      <h3 style={{ margin: "0 0 10px", fontSize: 14 }}>
        <FormattedMessage id="b1.onboard.newTenant.title" />
      </h3>
      <label className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.businessName" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.businessName" })}>
            <FormattedMessage id="b1.onboard.field.businessName.help" />
          </HelpTooltip>
        </span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={intl.formatMessage({
            id: "b1.onboard.field.businessName.placeholder",
          })}
        />
      </label>
      <label className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.slug" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.slug" })}>
            <FormattedMessage id="b1.onboard.field.slug.help" />
          </HelpTooltip>
        </span>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder={intl.formatMessage({ id: "b1.onboard.field.slug.placeholder" })}
        />
      </label>
      <label className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.region" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.region" })}>
            <FormattedMessage id="b1.onboard.field.region.help" />
          </HelpTooltip>
        </span>
        <input
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          placeholder={intl.formatMessage({ id: "b1.onboard.field.region.placeholder" })}
        />
      </label>
      <div className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.planTier" />
        </span>
        <div className="choice-grid" style={{ marginTop: 6 }}>
          {tiers.map((t) => (
            <button
              key={t}
              className={`choice${tier === t ? " choice--selected" : ""}`}
              onClick={() => setTier(t)}
              aria-pressed={tier === t}
            >
              <div className="choice__name">{titleCase(t)}</div>
              <div className="choice__desc">
                <FormattedMessage id={`b1.onboard.tier.${t}.blurb`} />
              </div>
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
          {busy ? (
            <FormattedMessage id="b1.onboard.cta.creating" />
          ) : (
            <FormattedMessage id="b1.onboard.cta.createTenant" />
          )}
        </button>
        {onCancel && (
          <button className="btn" onClick={onCancel} disabled={busy}>
            <FormattedMessage id="b1.common.cancel" />
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
  const intl = useIntl();
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
          toast.success(
            intl.formatMessage({ id: "b1.onboard.toast.siteCreated.title" }),
            intl.formatMessage(
              { id: "b1.onboard.toast.siteCreated.body" },
              { name: name.trim() },
            ),
          );
          onNext();
        },
        onError: (e) =>
          toast.error(
            intl.formatMessage({ id: "b1.onboard.toast.siteFailed" }),
            e instanceof Error ? e.message : undefined,
          ),
      },
    );
  };

  return (
    <Card title={intl.formatMessage({ id: "b1.onboard.site.title" })}>
      {existing > 0 && (
        <p className="muted">
          <FormattedMessage id="b1.onboard.site.existing" values={{ count: existing }} />
        </p>
      )}
      <label className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.siteName" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.siteName" })}>
            <FormattedMessage id="b1.onboard.field.siteName.help" />
          </HelpTooltip>
        </span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={intl.formatMessage({ id: "b1.onboard.field.siteName.placeholder" })}
        />
      </label>
      <label className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.slug" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.slug" })}>
            <FormattedMessage id="b1.onboard.field.siteSlug.help" />
          </HelpTooltip>
        </span>
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder={intl.formatMessage({ id: "b1.onboard.field.siteSlug.placeholder" })}
        />
      </label>
      <div className="field">
        <span>
          <FormattedMessage id="b1.onboard.field.deployment" />{" "}
          <HelpTooltip title={intl.formatMessage({ id: "b1.onboard.field.deployment" })}>
            <FormattedMessage id="b1.onboard.field.deployment.help" />
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
              <div className="choice__desc">
                <FormattedMessage id={`b1.onboard.template.${t}.blurb`} />
              </div>
            </button>
          ))}
        </div>
      </div>
      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          <FormattedMessage id="b1.common.back" />
        </button>
        <div style={{ display: "flex", gap: 10 }}>
          {existing > 0 && (
            <button className="btn" onClick={onNext} disabled={create.isPending}>
              <FormattedMessage id="b1.onboard.cta.skip" />
            </button>
          )}
          <button
            className="btn btn--primary"
            onClick={submit}
            disabled={!name.trim() || create.isPending}
          >
            {create.isPending ? (
              <FormattedMessage id="b1.onboard.cta.creatingSite" />
            ) : (
              <FormattedMessage id="b1.onboard.cta.createSite" />
            )}
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
  const intl = useIntl();
  // Read the latest intl from a ref inside the discovery effect so the effect
  // doesn't take intl as a dependency: intl changes identity on every locale
  // switch, and depending on it would re-run discovery and flash the spinner
  // over an already-verified connection.
  const intlRef = useRef(intl);
  intlRef.current = intl;
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
        setError(
          e instanceof Error
            ? e.message
            : intlRef.current.formatMessage({
                id: "b1.onboard.identity.discoveryFailed",
              }),
        );
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
      title={intl.formatMessage({ id: "b1.onboard.identity.title" })}
      actions={
        <HelpTooltip
          title={intl.formatMessage({ id: "b1.onboard.identity.enabled" })}
          align="right"
        >
          <FormattedMessage id="b1.onboard.identity.help" />
        </HelpTooltip>
      }
    >
      {cfg.authMode === "oidc" ? (
        <>
          <div style={{ marginBottom: 12 }}>
            <Badge tone="ok">
              <FormattedMessage id="b1.onboard.identity.enabled" />
            </Badge>
          </div>
          <dl className="kv">
            <dt>
              <FormattedMessage id="b1.onboard.identity.issuer" />
            </dt>
            <dd className="mono">{cfg.oidcIssuer || "—"}</dd>
            <dt>
              <FormattedMessage id="b1.onboard.identity.clientId" />
            </dt>
            <dd className="mono">{cfg.oidcClientId || "—"}</dd>
            <dt>
              <FormattedMessage id="b1.onboard.identity.scopes" />
            </dt>
            <dd className="mono">{cfg.oidcScope}</dd>
          </dl>
          <div style={{ marginTop: 12 }}>
            {loading ? (
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <Spinner />
                <span className="muted">
                  <FormattedMessage id="b1.onboard.identity.verifying" />
                </span>
              </div>
            ) : error ? (
              <>
                <p className="error-text" role="alert">
                  <FormattedMessage
                    id="b1.onboard.identity.verifyFailed"
                    values={{ detail: error }}
                  />
                </p>
                <button
                  className="btn"
                  style={{ marginTop: 8 }}
                  onClick={() => setReloadKey((k) => k + 1)}
                >
                  <FormattedMessage id="b1.common.retry" />
                </button>
              </>
            ) : discovery ? (
              <>
                <p style={{ color: "var(--ok)", fontSize: 13 }}>
                  ✓ <FormattedMessage id="b1.onboard.identity.verified" />
                </p>
                <dl className="kv">
                  <dt>
                    <FormattedMessage id="b1.onboard.identity.authorization" />
                  </dt>
                  <dd className="mono">
                    {String(discovery.authorization_endpoint ?? "—")}
                  </dd>
                  <dt>
                    <FormattedMessage id="b1.onboard.identity.token" />
                  </dt>
                  <dd className="mono">
                    {String(discovery.token_endpoint ?? "—")}
                  </dd>
                  <dt>
                    <FormattedMessage id="b1.onboard.identity.jwks" />
                  </dt>
                  <dd className="mono">{String(discovery.jwks_uri ?? "—")}</dd>
                </dl>
              </>
            ) : null}
          </div>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 12 }}>
            <FormattedMessage
              id="b1.onboard.identity.scimHint"
              values={{
                scim: (chunks: ReactNode) => <Link to="/scim">{chunks}</Link>,
                idp: (chunks: ReactNode) => <Link to="/idp">{chunks}</Link>,
              }}
            />
          </p>
        </>
      ) : (
        <>
          <div style={{ marginBottom: 12 }}>
            <Badge tone="info">
              <FormattedMessage id="b1.onboard.identity.devBadge" />
            </Badge>
          </div>
          <p>
            <FormattedMessage id="b1.onboard.identity.devBody" />
          </p>
          <p className="muted" style={{ fontSize: 12.5 }}>
            <FormattedMessage id="b1.onboard.identity.devNote" />
          </p>
        </>
      )}

      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          <FormattedMessage id="b1.common.back" />
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          <FormattedMessage id="b1.onboard.cta.continue" />
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
  const intl = useIntl();
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
          intl.formatMessage({ id: "b1.onboard.toast.protectionApplied.title" }),
          intl.formatMessage({ id: "b1.onboard.toast.protectionApplied.body" }),
        );
        onNext();
      },
      onError: (e) =>
        toast.error(
          intl.formatMessage({ id: "b1.onboard.toast.policyFailed" }),
          e instanceof Error ? e.message : undefined,
        ),
    });
  };

  return (
    <Card
      title={intl.formatMessage({ id: "b1.onboard.policy.title" })}
      actions={
        <HelpTooltip
          title={intl.formatMessage({ id: "b1.onboard.policy.title" })}
          align="right"
        >
          <FormattedMessage id="b1.onboard.policy.help" />
        </HelpTooltip>
      }
    >
      {templates.isLoading ? (
        <div className="skeleton" style={{ height: 120 }} />
      ) : items.length === 0 ? (
        <p className="muted">
          <FormattedMessage id="b1.onboard.policy.none" />
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
                <Badge tone="info">
                  <FormattedMessage
                    id="b1.onboard.policy.rules"
                    values={{ count: t.rules?.length ?? 0 }}
                  />
                </Badge>
              </div>
            </button>
          ))}
        </div>
      )}
      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          <FormattedMessage id="b1.common.back" />
        </button>
        <button
          className="btn btn--primary"
          onClick={applyAndContinue}
          disabled={apply.isPending}
        >
          {apply.isPending ? (
            <FormattedMessage id="b1.onboard.cta.applyingPolicy" />
          ) : selected ? (
            <FormattedMessage id="b1.onboard.cta.applyContinue" />
          ) : (
            <FormattedMessage id="b1.onboard.cta.skipForNow" />
          )}
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
  const intl = useIntl();
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
            intl.formatMessage({ id: "b1.onboard.toast.tokenFailed" }),
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
      toast.success(
        intl.formatMessage({ id: "b1.onboard.toast.copied.title" }),
        intl.formatMessage({ id: "b1.onboard.toast.copied.body" }),
      );
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error(
        intl.formatMessage({ id: "b1.onboard.toast.copyFailed.title" }),
        intl.formatMessage({ id: "b1.onboard.toast.copyFailed.body" }),
      );
    }
  };

  return (
    <Card title={intl.formatMessage({ id: "b1.onboard.deploy.title" })}>
      <p className="muted">
        <FormattedMessage id="b1.onboard.deploy.intro" />
      </p>
      {enrolled > 0 && (
        <p className="muted">
          <FormattedMessage id="b1.onboard.deploy.enrolled" values={{ count: enrolled }} />
        </p>
      )}

      {!token ? (
        <button
          className="btn btn--primary"
          onClick={generate}
          disabled={create.isPending}
        >
          {create.isPending ? (
            <FormattedMessage id="b1.onboard.cta.generating" />
          ) : (
            <FormattedMessage id="b1.onboard.cta.generateToken" />
          )}
        </button>
      ) : (
        <div className="grid grid--2" style={{ marginTop: 4 }}>
          <div>
            <label className="field">
              <span>
                <FormattedMessage id="b1.onboard.deploy.tokenLabel" />
              </span>
              <div className="copy-field">
                <input readOnly value={token.token} className="mono" />
                <button className="btn" onClick={copy}>
                  {copied ? (
                    <FormattedMessage id="b1.onboard.cta.copied" />
                  ) : (
                    <FormattedMessage id="b1.onboard.cta.copy" />
                  )}
                </button>
              </div>
            </label>
            <p className="muted" style={{ fontSize: 12 }}>
              <FormattedMessage
                id="b1.onboard.deploy.expires"
                values={{ date: new Date(token.expires_at).toLocaleString() }}
              />
            </p>
            <p style={{ fontSize: 13 }}>
              <FormattedMessage id="b1.onboard.deploy.instructions" />
            </p>
          </div>
          <div style={{ display: "grid", placeItems: "center" }}>
            <QrCode value={token.token} size={168} />
            <span className="muted" style={{ fontSize: 12, marginTop: 8 }}>
              <FormattedMessage id="b1.onboard.deploy.scanHint" />
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
          <FormattedMessage id="b1.onboard.deploy.doneTitle" />
        </h3>
        <p className="muted" style={{ fontSize: 13 }}>
          <FormattedMessage id="b1.onboard.deploy.doneSub" />
        </p>
        <ul className="done-links">
          <li>
            <FormattedMessage
              id="b1.onboard.deploy.link.dashboard"
              values={{ link: (chunks: ReactNode) => <Link to="/">{chunks}</Link> }}
            />
          </li>
          <li>
            <FormattedMessage
              id="b1.onboard.deploy.link.alerts"
              values={{ link: (chunks: ReactNode) => <Link to="/alerts">{chunks}</Link> }}
            />
          </li>
          <li>
            <FormattedMessage
              id="b1.onboard.deploy.link.policy"
              values={{ link: (chunks: ReactNode) => <Link to="/policy">{chunks}</Link> }}
            />
          </li>
          <li>
            <FormattedMessage
              id="b1.onboard.deploy.link.devices"
              values={{ link: (chunks: ReactNode) => <Link to="/devices">{chunks}</Link> }}
            />
          </li>
        </ul>
      </div>

      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          <FormattedMessage id="b1.common.back" />
        </button>
        <button className="btn btn--primary" onClick={onFinish}>
          <FormattedMessage id="b1.onboard.cta.goDashboard" />
        </button>
      </div>
    </Card>
  );
}
