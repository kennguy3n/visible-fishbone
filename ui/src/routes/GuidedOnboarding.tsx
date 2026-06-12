import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
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

type TierValue =
  (typeof TenantCreateRequestTier)[keyof typeof TenantCreateRequestTier];

const STEPS = ["Tenant", "Residency", "Industry", "First policy", "Done"] as const;

// Guided onboarding wizard — mirrors what the seed harness does over the API:
// create a tenant, choose its data-residency country, pick an industry, render
// and apply the first baseline policy, then finish. Each step validates before
// it lets the operator advance.
export function GuidedOnboarding() {
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

  const regimeForCountry = (c: string) =>
    (options.data?.countries ?? []).find((x) => x.country === c)?.regime;

  return (
    <div className="onboard">
      <PageHeader
        title="Guided onboarding"
        subtitle="Stand up a new tenant and its first security baseline in five steps."
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

      {step === 1 && (
        <StepTenant
          onCreated={(t) => {
            setTenant(t);
            setStep(2);
          }}
        />
      )}

      {step === 2 && tenant && (
        <Card title={`Where does ${tenant.name} operate?`}>
          <p>
            The country sets the data-residency region and the compliance regime
            the baseline enforces.
          </p>
          <label className="field" style={{ maxWidth: 320 }}>
            <span>Country / data residency</span>
            <select
              value={country}
              disabled={options.isLoading}
              onChange={(e) => setCountry(e.target.value)}
            >
              <option value="">Select a country…</option>
              {(options.data?.countries ?? []).map((c) => (
                <option key={c.country} value={c.country}>
                  {c.country} — {c.regime}
                </option>
              ))}
            </select>
          </label>
          {country && (
            <p style={{ marginTop: 8 }}>
              Regime: <Badge tone="info">{regimeForCountry(country)}</Badge>
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
        <Card title="What does the business do?">
          <p>The industry sets the acceptable-use posture and any sector DLP detectors.</p>
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
                      "Could not render the baseline",
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              );
            }}
            nextDisabled={!industry || previewBaseline.isPending}
            nextLabel={previewBaseline.isPending ? "Rendering…" : "Preview policy"}
          />
        </Card>
      )}

      {step === 4 && tenant && preview && (
        <Card title="Review the first baseline policy">
          <p>
            {titleCase(industry)} · {country} ·{" "}
            <Badge tone="info">{preview.regime}</Badge>
          </p>
          <div className="field">
            <span>Composed from templates</span>
            <ul style={{ margin: "6px 0" }}>
              {preview.template_ids.map((id) => (
                <li key={id} className="mono">
                  {id}
                </li>
              ))}
            </ul>
          </div>
          <p style={{ color: "var(--text-dim)" }}>
            Policy-Graph hash: <span className="mono">{preview.graph_hash}</span>
          </p>
          <WizardNav
            onBack={() => setStep(3)}
            onNext={() => {
              applyBaseline.mutate(
                { industry, country },
                {
                  onSuccess: () => {
                    toast.success("Baseline applied", `${tenant.name} is protected.`);
                    setStep(5);
                  },
                  onError: (e) =>
                    toast.error(
                      "Could not apply the baseline",
                      e instanceof Error ? e.message : undefined,
                    ),
                },
              );
            }}
            nextDisabled={applyBaseline.isPending}
            nextLabel={applyBaseline.isPending ? "Applying…" : "Apply baseline"}
          />
        </Card>
      )}

      {step === 5 && tenant && (
        <Card title="You're all set">
          <p>
            <strong>{tenant.name}</strong> has its first security baseline applied.
            You can now add sites, enrol devices, or refine the policy.
          </p>
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <button
              className="btn btn--primary"
              onClick={() => {
                setSelectedTenantId(tenant.id);
                navigate({ to: "/" });
              }}
            >
              Go to dashboard
            </button>
            <Link className="btn" to="/onboarding">
              Continue full setup
            </Link>
          </div>
        </Card>
      )}
    </div>
  );
}

// --- Step 1: create the tenant ---------------------------------------------
function StepTenant({ onCreated }: { onCreated: (t: TenantResponse) => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [tier, setTier] = useState<TierValue>(TenantCreateRequestTier.starter);
  const tiers = Object.values(TenantCreateRequestTier) as TierValue[];

  const create = useCreateTenant({
    mutation: {
      onSuccess: async (t: TenantResponse) => {
        await qc.invalidateQueries({ queryKey: getListTenantsQueryKey() });
        toast.success("Tenant created", `${t.name} is ready to configure.`);
        onCreated(t);
      },
      onError: (e) =>
        toast.error(
          "Could not create tenant",
          e instanceof Error ? e.message : undefined,
        ),
    },
  });

  const trimmed = name.trim();
  return (
    <Card title="Create the tenant">
      <p>A tenant is the isolated workspace everything else hangs off.</p>
      <label className="field" style={{ maxWidth: 320 }}>
        <span>Business name</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme Ltd"
        />
      </label>
      <label className="field" style={{ maxWidth: 320 }}>
        <span>Plan</span>
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
          {create.isPending ? <Spinner /> : "Create tenant"}
        </button>
      </div>
    </Card>
  );
}

function WizardNav({
  onBack,
  onNext,
  nextDisabled,
  nextLabel = "Next",
}: {
  onBack: () => void;
  onNext: () => void;
  nextDisabled?: boolean;
  nextLabel?: string;
}) {
  return (
    <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
      <button className="btn" onClick={onBack}>
        Back
      </button>
      <button className="btn btn--primary" disabled={nextDisabled} onClick={onNext}>
        {nextLabel}
      </button>
    </div>
  );
}
