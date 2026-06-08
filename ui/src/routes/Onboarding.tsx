import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useListSites, useCreateSite } from "@/api/generated/endpoints/sites/sites";
import {
  useListDevices,
  useCreateClaimToken,
} from "@/api/generated/endpoints/devices/devices";
import { SiteCreateRequestTemplate } from "@/api/generated/model";
import type { ClaimToken } from "@/api/generated/model";
import { useDlpTemplates, useApplyDlpTemplate } from "@/api/manual/hooks";
import { PageHeader, Card, Badge } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { QrCode } from "@/components/QrCode";
import { RequireTenant } from "@/components/RequireTenant";
import { useToast } from "@/components/Toast";
import { titleCase } from "@/lib/format";

type TemplateValue =
  (typeof SiteCreateRequestTemplate)[keyof typeof SiteCreateRequestTemplate];

const SITE_TEMPLATE_BLURB: Record<string, string> = {
  branch: "A physical office with its own network — staff on-site share one internet breakout.",
  hub: "A central location that other sites connect back through.",
  cloud_only: "No hardware — protect cloud apps and remote staff only.",
  home_office: "A single remote worker, set up from their device.",
};

const STEPS = [
  "Welcome",
  "Protection level",
  "First site",
  "First device",
  "Done",
] as const;

export function Onboarding() {
  return (
    <RequireTenant>
      {(tenantId) => <OnboardingInner tenantId={tenantId} />}
    </RequireTenant>
  );
}

function OnboardingInner({ tenantId }: { tenantId: string }) {
  const [step, setStep] = useState(1);

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

      {step === 1 && <StepWelcome onNext={() => setStep(2)} />}
      {step === 2 && (
        <StepProtection
          tenantId={tenantId}
          onBack={() => setStep(1)}
          onNext={() => setStep(3)}
        />
      )}
      {step === 3 && (
        <StepSite
          tenantId={tenantId}
          onBack={() => setStep(2)}
          onNext={() => setStep(4)}
        />
      )}
      {step === 4 && (
        <StepDevice
          tenantId={tenantId}
          onBack={() => setStep(3)}
          onNext={() => setStep(5)}
        />
      )}
      {step === 5 && <StepDone />}
    </div>
  );
}

function StepWelcome({ onNext }: { onNext: () => void }) {
  return (
    <Card title="Welcome to ShieldNet Gateway">
      <p>
        ShieldNet protects your business's internet traffic — blocking threats,
        stopping data leaks and keeping remote staff safe — without needing an
        IT team to run it.
      </p>
      <div className="overview-anim" aria-hidden>
        <div className="overview-anim__node overview-anim__node--user">Staff</div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--sng">ShieldNet</div>
        <div className="overview-anim__flow" />
        <div className="overview-anim__node overview-anim__node--net">Internet</div>
      </div>
      <p className="muted" style={{ fontSize: 13 }}>
        In the next few minutes you'll choose a protection level, connect your
        first site, and enrol your first device. That's all it takes to go live.
      </p>
      <div className="onboard__actions">
        <button className="btn btn--primary" onClick={onNext}>
          Let's go →
        </button>
      </div>
    </Card>
  );
}

function StepProtection({
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
        toast.success("Protection applied", "Your data-loss policy is now active.");
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
      title="Choose a protection level"
      actions={
        <HelpTooltip title="Protection levels" align="right">
          These are data-loss prevention (DLP) templates. They decide what
          sensitive information — card numbers, ID numbers, secrets — ShieldNet
          watches for and blocks. You can fine-tune everything later.
        </HelpTooltip>
      }
    >
      {templates.isLoading ? (
        <div className="skeleton" style={{ height: 120 }} />
      ) : items.length === 0 ? (
        <p className="muted">
          No protection templates are published for this tenant yet. You can
          skip this step and configure DLP later from the DLP page.
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
      { tenantId, data: { name, slug: slug || undefined, template } },
      {
        onSuccess: () => {
          toast.success("Site created", `${name} is now connected.`);
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
        <button
          className="btn btn--primary"
          onClick={submit}
          disabled={!name || create.isPending}
        >
          {create.isPending ? "Creating…" : "Create site →"}
        </button>
      </div>
    </Card>
  );
}

function StepDevice({
  tenantId,
  onBack,
  onNext,
}: {
  tenantId: string;
  onBack: () => void;
  onNext: () => void;
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
    <Card title="Enrol your first device">
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

      <div className="onboard__actions">
        <button className="btn" onClick={onBack}>
          ← Back
        </button>
        <button className="btn btn--primary" onClick={onNext}>
          {token || enrolled > 0 ? "Continue →" : "Skip for now →"}
        </button>
      </div>
    </Card>
  );
}

function StepDone() {
  const navigate = useNavigate();
  return (
    <Card title="You're protected 🎉">
      <p>
        Nice work. ShieldNet is now watching your traffic. Here's where to go
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
          <Link to="/policy">Policy</Link> — review and fine-tune what's allowed.
        </li>
        <li>
          <Link to="/devices">Devices</Link> — enrol more devices any time.
        </li>
      </ul>
      <div className="onboard__actions">
        <button className="btn btn--primary" onClick={() => navigate({ to: "/" })}>
          Go to dashboard →
        </button>
      </div>
    </Card>
  );
}
