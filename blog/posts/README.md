# ShieldNet Gateway — the measured SASE series

An eleven-post engineering series that walks the real product end-to-end, with
live screenshots, verbatim API payloads, and an in-repo efficacy/performance
harness. Every figure traces to an evidence source; every post ends with an
honest "where we fall short."

**This cycle's theme:** *run 5,000 SME tenants — most of them dormant trials —
without an operations team.* A twelve-workstream push merged into `main`
(`65824c75`): universal dormancy tiering, hibernation/scale-to-zero, tier-aware
telemetry, a self-operating control plane (auto-promotion + capacity autopilot +
margin autopilot), a shared AI inference pool, multi-queue edge throughput, and a
breadth catch-up across identity, threat-intel, and CASB/DLP. All evidence was
re-measured on the merged code. Post 0 has the per-workstream "what's actually
wired" table.

## The posts

| # | Post | Theme | Persona |
| --- | --- | --- | --- |
| 0 | [Series intro + the honesty contract](00-series-intro.md) | — | — |
| 1 | [One typed policy graph lights up a branch](01-s2-policy-graph.md) | S2 | Devraj |
| 2 | [Stand up a tenant, then run 5,000 cheaply](02-s1-multitenant-msp-dormancy.md) | S1 + WS-1/2/8 | Maya |
| 3 | [Hibernation: a dormant trial that costs almost nothing](03-hibernation-scale-to-zero.md) | WS-3/4 | Maya / Tom |
| 4 | [Detection efficacy + threat-intel depth](04-s3-detection-efficacy-threat-intel.md) | S3 + WS-10b | Lena |
| 5 | [Retire the VPN: zero-trust + identity breadth](05-s4-ztna-identity.md) | S4 + WS-10a | Devraj |
| 6 | [Keep regulated data in: DLP + CASB + RBI](06-s5-dlp-casb-rbi.md) | S5 + WS-10c | Lena / Tom |
| 7 | [AI-assisted ops + shared inference](07-s6-ai-assisted-ops-shared-inference.md) | S6 + WS-9 | Lena / Devraj |
| 8 | [NoOps self-operation: the control plane that operates itself](08-noops-self-operation.md) | WS-5/6/7 | Maya / Tom |
| 9 | [Prove the spend and the posture + competitive critique](09-s7-cost-compliance-competitive.md) | S7 | Tom |
| 10 | [Six scenarios on one dev VM](10-six-scenarios-on-this-vm.md) | — | Devraj / Lena |

Scenario definitions and the evidence map live in
[`../scenarios/00-scenario-catalog.md`](../scenarios/00-scenario-catalog.md).

## The business series (companion)

A buyer-facing companion lives in [`business/`](business/README.md). It walks the
headline economics — dormant-trial NoOps, shadow-IT discovery, coach-first AI-app
DLP, smart-default compliance, and self-hosted/shared AI — as persona +
jobs-to-be-done journeys.

| # | Post | Persona | Capability |
| --- | --- | --- | --- |
| B0 | [Business intro + evidence contract](business/00-business-series-intro.md) | — | — |
| B1 | [The NoOps trial that costs almost nothing](business/08-noops-dormant-trials.md) | Mara (MSP) | Dormancy tiering + hibernation (WS-1/3) |
| B2 | [Shadow-IT discovery without the noise](business/09-shadow-it-noops.md) | Sam (IT lead) | CASB NoOps (WS-10c) |
| B3 | [PII at the AI edge: coach, don't block](business/10-ai-dlp-coaching.md) | Lena (analyst) | AI-app DLP + HITL |
| B4 | [Compliance baselines in minutes](business/11-compliance-templates.md) | Mara (MSP) | Smart-default templates |
| B5 | [Prove the spend, prove the posture](business/12-cost-and-competition.md) | Tom (CFO) | Shared AI (WS-9) + metering + critique |

## Evidence sources (all in-repo)

- **Screenshots:** [`../artifacts/screenshots/`](../artifacts/screenshots/) —
  live console captures via CDP against the seeded fleet, including the new
  surfaces (fleet metering, CASB NoOps shadow-IT, cross-tenant capability
  roll-out, DLP review queue, guided onboarding, IdP directory, app registry).
- **Payloads:** [`../artifacts/payloads/`](../artifacts/payloads/) — verbatim
  control-plane responses, including the new WS-5 capability-rollout
  (`off→monitor→enforce`) and WS-7 margin/cost surfaces.
- **Efficacy matrix:** [`../artifacts/efficacy-report.json`](../artifacts/efficacy-report.json)
  — 11 functions (incl. kernel firewall, Suricata IPS, two adversarial corpora,
  three wild corpora), real crate APIs, suite verdict PASS, re-run on `main`
  `65824c75`.
- **Edge throughput:** [`../artifacts/multiqueue-micro.json`](../artifacts/multiqueue-micro.json)
  (5.569 → 28.567 Gbps, 5.13×) and
  [`../artifacts/multi-queue-branch-large.json`](../artifacts/multi-queue-branch-large.json)
  (5.063 → 21.564 Gbps, 4.26×) — single-stream floor vs multi-queue ceiling.
- **Scale economics:** [`../artifacts/capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md)
  — 5,000-tenant capacity plan: dormancy dividend 10×, shared AI memory 3,696×,
  sized recommendations for ClickHouse/AI/NATS/Postgres.
- **NoOps metrics:** [`../artifacts/noops-metrics-snapshot.txt`](../artifacts/noops-metrics-snapshot.txt)
  — live capacity-autopilot / hibernation / AI-pool gauges from the seeded stack.
- **Scenario provenance:** [`../artifacts/scenarios.md`](../artifacts/scenarios.md)
  — maps each of the six operator intents to its real code primitive + evidence.
- **Competitor figures:** [`../../bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
  — published datasheet numbers, each with `source_url` + `caveat`.

## Reproducing the artifacts

With the stack up (control plane on `:8080`, console on `:5173`) and the
workstream feature flags + `AUTH_JWT_SECRET` exported:

```bash
# 1. Seed the nine-tenant multi-country fleet under one MSP (idempotent).
(cd blog/harness/seed && go run .)

# 2. Drive usage so the metering projections have data.
(cd blog/harness/usage && go run .)

# 3. Emit anomaly alerts (baseline models + spikes for the Alerts surface).
(cd blog/harness/anomalies && go run .)

# 4. Capture the API payloads (incl. the new WS-5 rollout + WS-7 cost surfaces).
(cd blog/harness/capture && go run . -base http://127.0.0.1:8080 -out ../../artifacts/payloads)

# 5. Real CASB NoOps engine output (runs the production Reconcile()/RunDigests()).
(cd blog/harness/casb && go run .)

# 6. Efficacy + performance (Rust).
ORT_DYLIB_PATH=$HOME/.local/onnxruntime/libonnxruntime.so \
  ./bench/efficacy/target/release/sng-efficacy \
  --firewall --firewall-kernel --swg --ztna --ips --dlp --malware --dns \
  --adversarial --wild --git-sha 65824c75 --out blog/artifacts/efficacy-report.json
./bench/target/release/sng-bench multi-queue --profile bench/profiles/skus/micro.toml \
  --mode full-stack --backend nftables --out blog/artifacts/multiqueue-micro.json

# 7. 5,000-tenant capacity plan (dormancy dividend + shared-AI footprint).
./bench/target/release/sng-bench capacity-plan --tenants 5000 \
  --out-dir blog/artifacts/capacity-plan-5000
```

Screenshots are taken from the live console after the seed step, via CDP.

## The four honesty rules (recap)

1. **Measured ≠ dry-run** — throughput is published as a single-stream floor and
   a multi-queue ceiling, side by side; per-packet latency is reported separately.
2. **Competitor numbers are published datasheet figures, caveated** — ASIC
   appliances are not apples-to-apples with software-on-VM.
3. **Screenshots are of real, seeded, error-free pages.**
4. **The critique is honest** — every post names where SNG falls short; Post 9
   consolidates the competitive critique.
