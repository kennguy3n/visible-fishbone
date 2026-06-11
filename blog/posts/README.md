# ShieldNet Gateway — the measured SASE series

An eight-post engineering series that walks the real product end-to-end across
seven executive scenarios, with live screenshots, verbatim API payloads, and an
in-repo efficacy/performance harness. Every figure traces to an evidence source;
every post ends with an honest "where we fall short."

**Refreshed this cycle:** six new capabilities are folded into the relevant posts
— activity-tiered dormancy (#154, Posts 2/7), ClamAV + safe-browsing (#156, Post
5), shadow-IT NoOps (#159/#172, Post 5), coach-first AI-app DLP + HITL queue
(#158, Posts 5/6), smart-default policy templates (#157, Posts 2/7), and the
self-hosted Bonsai-8B Q2_0 bake (#155, Posts 6/7). Most are code-complete and
tested on `main` but not yet wired into the running control plane, so they're
backed by real engine output and tests rather than live-enforcement screenshots —
Post 0 has the per-capability "what's actually wired" table.

## The posts

| # | Post | Scenario | Persona |
| --- | --- | --- | --- |
| 0 | [Series intro + the honesty contract](00-series-intro.md) | — | — |
| 1 | [One typed policy graph lights up a branch](01-s2-policy-graph.md) | S2 | Devraj |
| 2 | [Stand up a new tenant before the kickoff call ends](02-s1-multitenant-msp.md) | S1 | Maya |
| 3 | [Detection efficacy: the catch-rate matrix](03-s3-detection-efficacy.md) | S3 | Lena |
| 4 | [Retire the VPN: zero-trust access](04-s4-ztna.md) | S4 | Devraj |
| 5 | [Keep regulated data from leaving: DLP + CASB + RBI](05-s5-dlp-casb-rbi.md) | S5 | Lena / Tom |
| 6 | [AI-assisted operations — with a verifier, not a vibe](06-s6-ai-assisted-ops.md) | S6 | Lena / Devraj |
| 7 | [Prove the spend and the posture + competitive critique](07-s7-cost-compliance-competitive.md) | S7 | Tom |

Scenario definitions and the evidence map live in
[`../scenarios/00-scenario-catalog.md`](../scenarios/00-scenario-catalog.md).

## The business series (companion)

A five-post, **buyer-facing** companion lives in
[`business/`](business/README.md). It walks the five capabilities shipped this
cycle — activity-tiered dormancy, CASB shadow-IT NoOps, coach-first AI-app DLP,
smart-default compliance templates, and self-hosted Bonsai-8B — as
persona + jobs-to-be-done journeys, with live console screenshots, the real CASB
classifier's output, and an honest competitive assessment for the SME/MSP buyer.

| # | Post | Persona | Capability |
| --- | --- | --- | --- |
| B0 | [Business intro + evidence contract](business/00-business-series-intro.md) | — | — |
| B1 | [The NoOps trial that costs almost nothing](business/08-noops-dormant-trials.md) | Mara (MSP) | Activity-tiered dormancy (#154) |
| B2 | [Shadow-IT discovery without the noise](business/09-shadow-it-noops.md) | Sam (IT lead) | CASB NoOps (#159, #172) |
| B3 | [PII at the AI edge: coach, don't block](business/10-ai-dlp-coaching.md) | Lena (analyst) | AI-app DLP + HITL (#158) |
| B4 | [Compliance baselines in minutes](business/11-compliance-templates.md) | Mara (MSP) | Smart-default templates (#157) |
| B5 | [Prove the spend, prove the posture](business/12-cost-and-competition.md) | Tom (CFO) | Self-hosted AI (#155) + metering + critique |

## Evidence sources (all in-repo)

- **Screenshots:** [`../artifacts/screenshots/`](../artifacts/screenshots/) — 16
  live console captures, audited error-free across all 31 routes / 4 tenants.
- **Payloads:** [`../artifacts/payloads/`](../artifacts/payloads/) — verbatim
  control-plane responses across the seven scenarios, plus the S5 DLP-classify and
  S6 NL-query request payloads. This cycle adds the **real CASB NoOps engine
  output** ([`casb-noops-actions-acme.json`](../artifacts/payloads/casb-noops-actions-acme.json),
  [`casb-classifications-acme.json`](../artifacts/payloads/casb-classifications-acme.json)
  — produced by running the production `Reconcile()`/`RunDigests()` via
  `blog/harness/casb`, not fixtures) and the 14-template
  [`policy-templates-catalog.json`](../artifacts/payloads/policy-templates-catalog.json)
  captured verbatim from the templates API.
- **Efficacy matrix:** [`../artifacts/efficacy-report.json`](../artifacts/efficacy-report.json)
  — 8 functions, real crate APIs, curated corpora, suite verdict PASS.
- **Performance datasheet:** [`../artifacts/edge-performance-datasheet.md`](../artifacts/edge-performance-datasheet.md)
  — per-SKU throughput (dry-run, caveated) + per-packet latency percentiles.
- **Competitor figures:** [`../../bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
  — published datasheet numbers, each with `source_url` + `caveat`.

## Reproducing the artifacts

The harnesses are Go (control-plane data) and Rust (efficacy/perf), consistent
with the backend tech stack. With the stack up (control plane on `:8080`, console
on `:5173`) and `AUTH_JWT_SECRET` exported:

```bash
# 1. Seed four tenants under one MSP (idempotent — rerun-safe).
(cd blog/harness/seed && go run .)

# 2. Drive usage so the metering projections have data.
(cd blog/harness/usage && go run .)

# 3. Emit anomaly alerts (fresh baseline models + spikes for the Alerts surface).
(cd blog/harness/anomalies && go run .)

# 4. Capture the API payloads (GET set + the S5 DLP-classify and S6 NL-query POST pairs).
(cd blog/harness/capture && go run . -base http://localhost:8080 -out ../../artifacts/payloads)

# 5. Real CASB NoOps engine output (seeds inventory, clears prior NoOps rows for
#    the demo tenants, then runs the production Reconcile()/RunDigests() — rerun-safe).
(cd blog/harness/casb && go run .)

# 6. Efficacy + performance (Rust).
(cd bench/efficacy && cargo run --release)   # -> efficacy-report.json
(cd bench && cargo run --release -- ... )    # see bench/README.md (uses --dry-run unprivileged)
```

The seed and capture harnesses are deterministic against the same seeded data: a
rerun reproduces the same payload files (modulo live timestamps and run-rate
drift in the usage meters). Screenshots are taken from the live console after the
seed step.

## The four honesty rules (recap)

1. **Measured ≠ dry-run** — the Gbps headline is dry-run on this rig; latency
   percentiles are the defensible perf signal.
2. **Competitor numbers are published datasheet figures, caveated** — ASIC
   appliances are not apples-to-apples with software-on-VM.
3. **Screenshots are of real, seeded, error-free pages** — three genuinely broken
   routes were fixed ([#116](https://github.com/kennguy3n/visible-fishbone/pull/116)),
   not screenshotted around.
4. **The critique is honest** — every post names where SNG falls short; Post 7
   consolidates the competitive critique.
