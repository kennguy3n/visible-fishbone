import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { FormattedMessage, useIntl } from "react-intl";
import {
  useCreateTenant,
  getListTenantsQueryKey,
} from "@/api/generated/endpoints/tenants/tenants";
import { TenantCreateRequestTier } from "@/api/generated/model";
import type { TenantResponse } from "@/api/generated/model";
import { PageHeader, Card, Badge, Spinner } from "@/components/ui";
import { useToast } from "@/components/Toast";
import { useTenant } from "@/lib/tenant-context";
import { titleCase } from "@/lib/format";
import {
  usePolicyTemplateOptions,
  usePreviewPolicyTemplate,
  useApplyPolicyTemplate,
} from "@/api/manual/hooks";
import type { PolicyTemplatePreview } from "@/api/manual/types";
import { LaneB1Intl } from "./lane-b1-intl";
import { Stepper } from "./lane-b1-stepper";
import "./lane-b1.css";

type TierValue =
  (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];

// Guided onboarding wizard — mirrors what the seed harness does over the API:
// create a tenant, choose its data-residency country, pick an industry, render
// and apply the first baseline policy, then finish. Each step validates before
// it lets the operator advance.
export function GuidedOnboarding() {
  return (
    <LaneB1Intl>
      <GuidedOnboardingInner />
    </LaneB1Intl>
  );
}

function GuidedOnboardingInner() {
  const intl = useIntl();
  const navigate = useNavigate();
  const { setSelectedTenantId } = useTenant();
  const toast = useToast();
  const options = usePolicyTemplateOptions();

  const [step, setStep] = useState(1);
  const [tenant, setTenant] = useState<TenantResponse | null>(null);
  const [country, setCountry] = useState("");
  const [industry, setIndustry] = useState("");
  const [preview, setPreview] = useState<PolicyTemplatePreview | null>(null);

  // Tenant-scoped mutations target the tenant created in step 1. They are only
  // invoked from step 4, by which point `tenant` is non-null.
  const previewBaseline = usePreviewPolicyTemplate(tenant?.id ?? "");
  const applyBaseline = useApplyPolicyTemplate(tenant?.id ?? "");

  // Steps are pipe-delimited (not comma) so a translated label can safely
  // contain a comma without changing the number of steps.
  const steps = intl.formatMessage({ id: "b1.guided.steps" }).split("|");
  const regimeForCountry = (c: string) =>
    (options.data?.countries ?? []).find((x) => x.country === c)?.regime;

  return (
    <div className="onboard lane-b1">
      <PageHeader
        title={intl.formatMessage({ id: "b1.guided.title" })}
        subtitle={intl.formatMessage({ id: "b1.guided.subtitle" })}
      />

      <Stepper steps={steps} current={step} />

      {step === 1 && (
        <StepTenant
          onCreated={(t) => {
            setTenant(t);
            setStep(2);
          }}
        />
      )}

      {step === 2 && tenant && (
        <Card
          title={intl.formatMessage(
            { id: "b1.guided.step.residency.title" },
            { name: tenant.name },
          )}
        >
          <p>
            <FormattedMessage id="b1.guided.step.residency.desc" />
          </p>
          <label className="field field--narrow">
            <span>
              <FormattedMessage id="b1.guided.field.country" />
            </span>
            <select
              value={country}
              disabled={options.isLoading}
              onChange={(e) => setCountry(e.target.value)}
            >
              <option value="">
                {intl.formatMessage({ id: "b1.guided.field.country.placeholder" })}
              </option>
              {(options.data?.countries ?? []).map((c) => (
                <option key={c.country} value={c.country}>
                  {c.country} — {c.regime}
                </option>
              ))}
            </select>
          </label>
          {country && (
            <p style={{ marginTop: 8 }}>
              <Badge tone="info">
                <FormattedMessage
                  id="b1.guided.residency.regime"
                  values={{ regime: regimeForCountry(country) }}
                />
              </Badge>
            </p>
          )}
          <WizardNav
            onBack={() => setStep(1)}
            onNext={() => setStep(3)}
            nextDisabled={!country}
          />
        </Card>
      )}

      {step === 3 && tenant && (
        <Card title={intl.formatMessage({ id: "b1.guided.step.industry.title" })}>
          <p>
            <FormattedMessage id="b1.guided.step.industry.desc" />
          </p>
          <div className="choice-grid">
            {(options.data?.industries ?? []).map((i) => (
              <button
                key={i.industry}
                className={`choice${industry === i.industry ? " choice--selected" : ""}`}
                onClick={() => setIndustry(i.industry)}
                aria-pressed={industry === i.industry}
              >
                <div className="choice__name">{i.name}</div>
                <div className="choice__desc mono">{i.template_id}</div>
              </button>
            ))}
          </div>
          <WizardNav
            onBack={() => setStep(2)}
            onNext={() => {
              previewBaseline.mutate(
                { industry, country },
                {
                  onSuccess: (p) => {
                    setPreview(p);
                    setStep(4);
                  },
                  onError: (e) =>
                    toast.error(
                      intl.formatMessage({ id: "b1.guided.toast.renderFailed" }),
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              );
            }}
            nextDisabled={!industry || previewBaseline.isPending}
            nextLabel={intl.formatMessage({
              id: previewBaseline.isPending
                ? "b1.guided.cta.previewing"
                : "b1.guided.cta.preview",
            })}
          />
        </Card>
      )}

      {step === 4 && tenant && preview && (
        <Card title={intl.formatMessage({ id: "b1.guided.step.review.title" })}>
          <p>
            <FormattedMessage
              id="b1.guided.review.summary"
              values={{
                industry: titleCase(industry),
                country,
                regime: preview.regime,
              }}
            />
          </p>
          <div className="field">
            <span>
              <FormattedMessage id="b1.guided.review.composedFrom" />
            </span>
            <ul style={{ margin: "6px 0" }}>
              {preview.template_ids.map((id) => (
                <li key={id} className="mono">
                  {id}
                </li>
              ))}
            </ul>
          </div>
          <p style={{ color: "var(--text-dim)" }}>
            <FormattedMessage id="b1.guided.review.fingerprint" />:{" "}
            <span className="mono">{preview.graph_hash}</span>
          </p>
          <WizardNav
            onBack={() => setStep(3)}
            onNext={() => {
              applyBaseline.mutate(
                { industry, country },
                {
                  onSuccess: () => {
                    toast.success(
                      intl.formatMessage({ id: "b1.guided.toast.applied.title" }),
                      intl.formatMessage(
                        { id: "b1.guided.toast.applied.body" },
                        { name: tenant.name },
                      ),
                    );
                    setStep(5);
                  },
                  onError: (e) =>
                    toast.error(
                      intl.formatMessage({ id: "b1.guided.toast.applyFailed" }),
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              );
            }}
            nextDisabled={applyBaseline.isPending}
            nextLabel={intl.formatMessage({
              id: applyBaseline.isPending
                ? "b1.guided.cta.applying"
                : "b1.guided.cta.apply",
            })}
          />
        </Card>
      )}

      {step === 5 && tenant && (
        <Card title={intl.formatMessage({ id: "b1.guided.step.done.title" })}>
          <p>
            <FormattedMessage
              id="b1.guided.step.done.desc"
              values={{ name: <strong>{tenant.name}</strong> }}
            />
          </p>
          <div style={{ display: "flex", gap: 10, marginTop: 12, flexWrap: "wrap" }}>
            <button
              className="btn btn--primary"
              onClick={() => {
                setSelectedTenantId(tenant.id);
                navigate({ to: "/" });
              }}
            >
              <FormattedMessage id="b1.guided.cta.goDashboard" />
            </button>
            <Link className="btn" to="/onboarding">
              <FormattedMessage id="b1.guided.cta.fullSetup" />
            </Link>
          </div>
        </Card>
      )}
    </div>
  );
}

// --- Step 1: create the tenant ---------------------------------------------
function StepTenant({ onCreated }: { onCreated: (t: TenantResponse) => void }) {
  const intl = useIntl();
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [tier, setTier] = useState<TierValue>(TenantCreateRequestTier.starter);
  const tiers = Object.values(TenantCreateRequestTier) as TierValue[];

  const create = useCreateTenant({
    mutation: {
      onSuccess: async (t: TenantResponse) => {
        await qc.invalidateQueries({ queryKey: getListTenantsQueryKey() });
        toast.success(
          intl.formatMessage({ id: "b1.guided.toast.created.title" }),
          intl.formatMessage({ id: "b1.guided.toast.created.body" }, { name: t.name }),
        );
        onCreated(t);
      },
      onError: (e) =>
        toast.error(
          intl.formatMessage({ id: "b1.guided.toast.createFailed" }),
          e instanceof Error ? e.message : undefined,
        ),
    },
  });

  const trimmed = name.trim();
  return (
    <Card title={intl.formatMessage({ id: "b1.guided.step.tenant.title" })}>
      <p>
        <FormattedMessage id="b1.guided.step.tenant.desc" />
      </p>
      <label className="field field--narrow">
        <span>
          <FormattedMessage id="b1.guided.field.businessName" />
        </span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={intl.formatMessage({
            id: "b1.guided.field.businessName.placeholder",
          })}
        />
      </label>
      <label className="field field--narrow">
        <span>
          <FormattedMessage id="b1.guided.field.plan" />
        </span>
        <select value={tier} onChange={(e) => setTier(e.target.value as TierValue)}>
          {tiers.map((t) => (
            <option key={t} value={t}>
              {titleCase(t)}
            </option>
          ))}
        </select>
      </label>
      <div style={{ marginTop: 12 }}>
        <button
          className="btn btn--primary"
          disabled={!trimmed || create.isPending}
          onClick={() => create.mutate({ data: { name: trimmed, tier } })}
        >
          {create.isPending ? (
            <Spinner />
          ) : (
            <FormattedMessage id="b1.guided.cta.create" />
          )}
        </button>
      </div>
    </Card>
  );
}

function WizardNav({
  onBack,
  onNext,
  nextDisabled,
  nextLabel,
}: {
  onBack: () => void;
  onNext: () => void;
  nextDisabled?: boolean;
  nextLabel?: string;
}) {
  const intl = useIntl();
  return (
    <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
      <button className="btn" onClick={onBack}>
        <FormattedMessage id="b1.common.back" />
      </button>
      <button className="btn btn--primary" disabled={nextDisabled} onClick={onNext}>
        {nextLabel ?? intl.formatMessage({ id: "b1.common.next" })}
      </button>
    </div>
  );
}
