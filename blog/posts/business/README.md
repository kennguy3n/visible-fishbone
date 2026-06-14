# ShieldNet Gateway — the business series

A five-post, buyer-facing companion to the [engineering series](../README.md).
Where the engineering series proves the product to a technical reader, this
series answers one buyer question per post — *"what job does this do for me, and
can you prove it?"* — using the same live, seeded control plane, console, and
audit trail.

This cycle's headline is **economics at scale**: a twelve-workstream push merged
into `main` (`65824c75`) to run 5,000 SME tenants — most of them dormant trials —
at near-zero marginal cost and near-zero operations. Every figure is re-measured
on the merged code and grounded in real console screenshots and captured
API/DB evidence (no fabricated screenshots).

## The posts

| # | Post | Persona | Job-to-be-done | Capability |
| --- | --- | --- | --- | --- |
| 0 | [Business series intro + evidence contract](00-business-series-intro.md) | — | — | — |
| 1 | [The NoOps trial that costs almost nothing](08-noops-dormant-trials.md) | Mara (MSP) | Trials that don't bleed money | Dormancy tiering + hibernation (WS-1/3) |
| 2 | [Shadow-IT discovery without the noise](09-shadow-it-noops.md) | Sam (IT lead) | See + act on unknown apps | CASB NoOps (WS-10c) |
| 3 | [PII at the AI edge: coach, don't block](10-ai-dlp-coaching.md) | Lena (analyst) | Stop AI leaks, keep staff happy | AI-app DLP + HITL |
| 4 | [Compliance baselines in minutes](11-compliance-templates.md) | Mara (MSP) | Onboard to a safe default fast | Smart-default templates |
| 5 | [Prove the spend, prove the posture](12-cost-and-competition.md) | Tom (CFO) | Sign-off + honest comparison | Shared AI (WS-9) + metering + critique |

## Evidence sources (all in-repo, refreshed this cycle)

- **Screenshots:** [`../../artifacts/screenshots/`](../../artifacts/screenshots/)
  — live console captures via CDP against the seeded fleet (fleet dashboard,
  metering/margin, CASB NoOps shadow-IT, DLP, browser isolation, alerts, audit).
- **CASB payloads:** the discover→classify→recommend verdicts are produced by the
  **real** `AppNoOpsEngine`, not hand-written —
  [`casb-classifications-acme.json`](../../artifacts/payloads/casb-classifications-acme.json)
  and [`casb-noops-actions-acme.json`](../../artifacts/payloads/casb-noops-actions-acme.json).
- **Policy-template catalog:** captured verbatim from `GET /api/v1/policy-templates`
  — [`policy-templates-catalog.json`](../../artifacts/payloads/policy-templates-catalog.json).
- **Scale economics:** [`../../artifacts/capacity-plan-5000/report.md`](../../artifacts/capacity-plan-5000/report.md)
  — the 5,000-tenant dormancy dividend and shared-AI footprint.
- **Cost & margin:** [`s7-admin-cost-report.json`](../../artifacts/payloads/s7-admin-cost-report.json).
- **Competitor figures:** published datasheet numbers with `source_url` + caveat
  in [`../../../bench/business-report/competitors.json`](../../../bench/business-report/competitors.json).

## The evidence contract

1. Screenshots are of real, seeded console pages.
2. Every number traces to a captured payload, a database row, or a harness run.
3. CASB classifications/recommendations are the production engine's output.
4. Every post names where SNG falls short; Post 5 carries the honest competitive
   critique.
