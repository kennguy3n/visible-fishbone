# ShieldNet Gateway for the business: five jobs, one platform, real evidence

> **Business series, Post 0 of 5 — the intro and the evidence contract.**
>
> The eight-post [engineering series](../README.md) walks SNG end-to-end for a
> technical reader. This *business* series is for the buyer: the MSP owner, the
> SME IT lead, the compliance officer, the CFO. It answers one question per
> post — *"what job does this do for me, and can you prove it?"* — using the
> **same live, seeded control plane**, the same console, and the same audit
> trail an operator sees. Every screenshot below is a real page; every number
> traces to a captured API payload or a database row this session produced.

## Who this is for (personas + jobs-to-be-done)

| Persona | Role | The job they're hiring SNG to do |
| --- | --- | --- |
| **Mara** | MSP owner, runs security for 80+ SMEs | "Make a free trial cost me almost nothing until the customer is actually using it." |
| **Sam** | IT lead at a 200-person retailer | "Show me what SaaS and AI apps my staff use, and tell me what to do — without a SOC team." |
| **Lena** | Security analyst (the rare SME that has one) | "Stop sensitive data leaking into AI tools without my helpdesk drowning in angry tickets." |
| **Mara (again)** | Onboarding a new SME | "Get a new customer to a compliant, deny-by-default posture before the kickoff call ends." |
| **Tom** | Fractional CFO across the MSP's book | "Prove the spend, prove the posture, and tell me honestly where you lose to the incumbents." |

## The five posts

| # | Post | Job-to-be-done | Capability |
| --- | --- | --- | --- |
| 1 | [The NoOps trial that costs almost nothing](08-noops-dormant-trials.md) | Trials that don't bleed money | Activity-tiered dormancy |
| 2 | [Shadow-IT discovery without the noise](09-shadow-it-noops.md) | See + act on unknown apps | CASB NoOps pipeline |
| 3 | [PII at the AI edge: coach, don't block](10-ai-dlp-coaching.md) | Stop AI leaks, keep staff happy | Long-tail AI-app DLP + HITL |
| 4 | [Compliance baselines in minutes](11-compliance-templates.md) | Onboard to a safe default fast | Smart-default policy templates |
| 5 | [Prove the spend, prove the posture](12-cost-and-competition.md) | CFO sign-off + honest comparison | Self-hosted AI + metering + competitive critique |

## The evidence contract (unchanged from the engineering series)

1. **Screenshots are of real, seeded pages** — captured this session from the
   console on `:5173` against four seeded tenants under one MSP. They live in
   [`../../artifacts/business/`](../../artifacts/business).
2. **Numbers trace to a source** — every figure is either a captured API
   payload in [`../../artifacts/payloads/`](../../artifacts/payloads) or a
   database row produced by a harness in [`../../harness/`](../../harness).
3. **The CASB classifications and recommendations are produced by the real
   engine** — not hand-written. The harness in
   [`../../harness/casb`](../../harness/casb) seeds a shadow-IT inventory and
   then runs the production `AppNoOpsEngine` over it; the verdicts you see are
   what the classifier actually emitted.
4. **The critique is honest** — Post 5 names exactly where SNG loses to
   Zscaler, Cloudflare, Netskope, Cato, and Fortinet, with their published
   datasheet figures (and the caveat that ASIC appliances aren't apples-to-apples
   with software-on-a-VM).

## The cast (seeded data)

One MSP, **Northwind Managed Security**, manages four tenants across three
tiers — so every screenshot shows real, tier-shaped data:

| Tenant | Tier | Vertical | Monthly cost (projected) | Margin |
| --- | --- | --- | ---: | ---: |
| Acme Retail Group | Enterprise | retail / PCI | $1,047.59 | 47.6% |
| Globex Health Systems | Enterprise | healthcare / HIPAA | $658.69 | 67.0% |
| Initech Financial | Professional | finance | $418.97 | 16.0% |
| Umbrella Logistics | Starter | logistics | $56.47 | 43.0% |

Source: the **Fleet cost & margin** table on the Metering page, captured live in
[`biz-10-fleet-margin.png`](../../artifacts/business/biz-10-fleet-margin.png).

Read on — Post 1 starts with the job that decides whether an MSP can afford to
offer free trials at all.
