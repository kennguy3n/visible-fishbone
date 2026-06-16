# Compliance baselines in minutes

> **Business series, Post 4 of 5.** Buyer: **Mara**, the MSP owner onboarding a
> new tenant. Job-to-be-done: *"stand up a new client on a compliant, sensible
> default — without a security consultant and without two weeks of config."*
> Capability: smart-default policy templates + continuous compliance evidence.
> Evidence:
> [`policy-templates-catalog.json`](../../artifacts/payloads/policy-templates-catalog.json),
> [`complianceauto-acme-posture.json`](../../artifacts/payloads/complianceauto-acme-posture.json),
> [`complianceauto-acme-evidence-pack-soc2.csv`](../../artifacts/payloads/complianceauto-acme-evidence-pack-soc2.csv);
> screenshots [`new-guided-onboarding-wizard.png`](../../artifacts/screenshots/new-guided-onboarding-wizard.png),
> [`s2-policy-graph.png`](../../artifacts/screenshots/s2-policy-graph.png).

When Mara wins a new client, the clock starts. The client expects to be protected
*today*, and "today" can't mean a two-week engagement with a security consultant
drawing up firewall rules. SNG's answer: a tenant's `(industry, country)`
coordinates render a **jurisdiction-correct baseline policy graph** automatically.

## Pick the coordinates, get a baseline

The guided onboarding wizard asks the questions that matter — what industry, what
country — and renders the rest:

![Guided onboarding](../../artifacts/screenshots/new-guided-onboarding-wizard.png)

Behind it is the template catalog
([`policy-templates-catalog.json`](../../artifacts/payloads/policy-templates-catalog.json)),
captured verbatim from the API: a baseline plus industry overlays plus
compliance-regime overlays. A US healthcare tenant gets HIPAA-shaped defaults; a
German finance tenant gets GDPR-shaped ones; a UK tenant gets uk-dpa. Across the
seeded fleet that's **five live regimes** — us-baseline, uk-dpa, eu-gdpr,
ca-pipeda, au-privacy — each producing a different starting graph.

## It's a real policy graph, not a checklist

The template doesn't produce a PDF of recommendations — it produces the actual
typed policy graph the edge enforces (the engineering series' Post 1):

![The rendered policy graph](../../artifacts/screenshots/s2-policy-graph.png)

So "compliant baseline" means *enforced* baseline from minute one, with every
node and edge auditable. Mara can hand the client a working, compliant posture on
the kickoff call, then refine specifics later — instead of shipping nothing until
everything is perfect.

## The baseline keeps proving itself

A starting policy is only half the job; Mara's client also needs to *show* an
auditor that controls stay in place. SNG collects a **continuous compliance
posture** on a schedule and turns it into a downloadable evidence pack — no
manual screenshot-gathering before an audit. For the walkthrough tenant the
live posture
([`complianceauto-acme-posture.json`](../../artifacts/payloads/complianceauto-acme-posture.json))
tracks **16 controls — 10 SOC 2 and 6 ISO 27001** — gathered by three automated
collectors, and the evidence pack exports as CSV or JSON straight from the API.

The number we *don't* hide: on a bare dev stack this tenant scores **6/10 SOC 2
and 4/6 ISO 27001** — the failing controls (encryption at rest/in transit,
federated SSO, data retention, identity management, use of cryptography) are
real gaps a fresh deployment has until those services are wired. That is the
point: the posture reports what is *actually* true, so Mara sees exactly which
boxes still need attention rather than a green checkmark that means nothing.

## One MSP, many jurisdictions, one motion

The same wizard works for every tenant regardless of where they are, so Mara's
onboarding motion doesn't fork per country. And for the MSP rolling the same
refinement across many clients, the cross-tenant roll-out surface (engineering
Post 2/8) previews a per-tenant diff before applying — the multi-tenant version
of the same "safe default, fast" promise.

## Where it falls short

- **A template is a starting point, not a compliance certification.** It encodes
  sensible, jurisdiction-aware defaults; it does not *certify* the tenant as
  HIPAA- or GDPR-compliant. That still requires the client's own controls and
  audit. SNG gives the enforced baseline, not the auditor's signature.
- **The catalog covers the common regimes, not all of them.** Five regimes and
  eight industries cover most SME cases; an unusual jurisdiction still needs
  manual graph work.
- **Defaults drift from best practice over time.** A template encodes today's
  good defaults; keeping the catalog current as regulations change is ongoing
  work, not a one-time build.
