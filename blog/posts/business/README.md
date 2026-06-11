# ShieldNet Gateway — the business series

A five-post, buyer-facing companion to the [engineering series](../README.md).
Where the engineering series proves the product to a technical reader, this
series answers one buyer question per post — *"what job does this do for me, and
can you prove it?"* — using the same live, seeded control plane, console, and
audit trail.

All five new capabilities shipped this cycle are covered, each grounded in real
console screenshots and captured API/DB evidence (no fabricated screenshots).

## The posts

| # | Post | Persona | Job-to-be-done | Capability |
| --- | --- | --- | --- | --- |
| 0 | [Business series intro + evidence contract](00-business-series-intro.md) | — | — | — |
| 1 | [The NoOps trial that costs almost nothing](08-noops-dormant-trials.md) | Mara (MSP) | Trials that don't bleed money | Activity-tiered dormancy ([#154](https://github.com/kennguy3n/visible-fishbone/pull/154)) |
| 2 | [Shadow-IT discovery without the noise](09-shadow-it-noops.md) | Sam (IT lead) | See + act on unknown apps | CASB NoOps ([#159](https://github.com/kennguy3n/visible-fishbone/pull/159), [#172](https://github.com/kennguy3n/visible-fishbone/pull/172)) |
| 3 | [PII at the AI edge: coach, don't block](10-ai-dlp-coaching.md) | Lena (analyst) | Stop AI leaks, keep staff happy | AI-app DLP + HITL ([#158](https://github.com/kennguy3n/visible-fishbone/pull/158)) |
| 4 | [Compliance baselines in minutes](11-compliance-templates.md) | Mara (MSP) | Onboard to a safe default fast | Smart-default templates ([#157](https://github.com/kennguy3n/visible-fishbone/pull/157)) |
| 5 | [Prove the spend, prove the posture](12-cost-and-competition.md) | Tom (CFO) | Sign-off + honest comparison | Self-hosted AI ([#155](https://github.com/kennguy3n/visible-fishbone/pull/155)) + metering + critique |

## Evidence sources (all in-repo, captured this cycle)

- **Screenshots:** [`../../artifacts/business/`](../../artifacts/business) — 11
  live console captures (`biz-01` … `biz-11`) across the dashboard, policy
  editor/graph, DLP taxonomy, CASB shadow-IT (before/after), browser protection,
  alerts, metering, fleet margin, and audit log.
- **CASB payloads:** the discover→classify→recommend verdicts are produced by the
  **real** `AppNoOpsEngine`, not hand-written —
  [`casb-classifications-acme.json`](../../artifacts/payloads/casb-classifications-acme.json)
  and [`casb-noops-actions-acme.json`](../../artifacts/payloads/casb-noops-actions-acme.json).
- **Policy-template catalog:** captured verbatim from `GET /api/v1/policy-templates`
  — [`policy-templates-catalog.json`](../../artifacts/payloads/policy-templates-catalog.json)
  (14 templates: 1 baseline + 8 industries + 5 compliance regimes).
- **Competitor figures:** published datasheet numbers with `source_url` + caveat
  in [`../../../bench/business-report/competitors.json`](../../../bench/business-report/competitors.json).

## Reproducing the CASB evidence

With the stack up (control plane `:8080`, console `:5173`) and the four tenants
seeded (`blog/harness/seed`), the CASB shadow-IT evidence is produced by:

```bash
# Seeds a per-tenant shadow-IT inventory, then drives the REAL CASB NoOps
# engine (Reconcile + RunDigests) over it — classifier verdicts + audit trail
# are the production code's output, not fixtures.
(cd blog/harness/casb && go run .)
```

## The evidence contract

1. Screenshots are of real, seeded console pages.
2. Every number traces to a captured payload or a database row.
3. CASB classifications/recommendations are the production engine's output.
4. Every post names where SNG falls short; Post 5 carries the honest competitive
   critique.
