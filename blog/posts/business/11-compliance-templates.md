# Compliance baselines in minutes

> **Business series, Post 4 of 5.** Buyer: **Mara**, the MSP owner onboarding a
> new tenant. Job-to-be-done: *"stand up a new client on a compliant, sensible
> default — without a security consultant and without two weeks of config."*
> Capability: smart-default policy templates. Evidence:
> [`policy-templates-catalog.json`](../../artifacts/payloads/policy-templates-catalog.json);
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
