# ShieldNet Gateway — the measured SASE series

An eleven-post engineering series that walks the real product end-to-end, with
live screenshots, verbatim API payloads, and an in-repo efficacy/performance
harness. Every figure traces to an evidence source; every post ends with an
honest "where we fall short."

**The through-line:** *run 5,000 SME tenants — most of them dormant trials —
without an operations team.* ShieldNet Gateway (SNG) is a multi-tenant SASE
platform where the control plane operates itself: universal dormancy tiering,
hibernation/scale-to-zero, tier-aware telemetry, auto-promotion, capacity and
margin autopilots, a shared AI inference pool, a typed policy graph, a signed
application-identification catalog, managed threat content, on-device DLP with
OCR and document fingerprinting, SWG **inline DLP** and **AI governance** and **RBI**
verdict stages, **clientless ZTNA** browser access, **DEM** (Digital Experience
Monitoring) with bounded synthetic probes, continuous compliance evidence, and a
policy recommendation engine. Every figure below is measured on the current
codebase. Post 0 has the "what's actually wired" table.

## The posts

| # | Post | Focus | Persona |
| --- | --- | --- | --- |
| 0 | [Series intro + the honesty contract](00-series-intro.md) | — | — |
| 1 | [One typed policy graph lights up a branch](01-s2-policy-graph.md) | Unified policy + App-ID + recommendations | Devraj |
| 2 | [Stand up a tenant, then run 5,000 cheaply](02-s1-multitenant-msp-dormancy.md) | Multi-tenant RLS + dormancy + active/active work distribution | Maya |
| 3 | [Hibernation: a dormant trial that costs almost nothing](03-hibernation-scale-to-zero.md) | Scale-to-zero + tier-aware telemetry | Maya / Tom |
| 4 | [Detection efficacy + managed threat content](04-s3-detection-efficacy-threat-intel.md) | Efficacy matrix + signed threat-content bundle | Lena |
| 5 | [Retire the VPN: zero-trust, identity, and experience](05-s4-ztna-identity.md) | ZTNA (agent + clientless browser) + IdP breadth + DEM edge subsystem | Devraj |
| 6 | [Keep regulated data in: DLP + CASB + RBI](06-s5-dlp-casb-rbi.md) | DLP (OCR + fingerprinting + inline SWG) + CASB + AI governance + RBI | Lena / Tom |
| 7 | [AI-assisted ops + shared inference](07-s6-ai-assisted-ops-shared-inference.md) | Verifier-checked AI + shared model + policy synthesis + SWG AI governance | Lena / Devraj |
| 8 | [NoOps self-operation: the control plane that operates itself](08-noops-self-operation.md) | Auto-promotion + capacity/margin autopilots + work distribution | Maya / Tom |
| 9 | [Prove the spend and the posture + competitive critique](09-s7-cost-compliance-competitive.md) | Cost + continuous compliance evidence + critique | Tom |
| 10 | [Six scenarios on one dev VM](10-six-scenarios-on-this-vm.md) | — | Devraj / Lena |

Scenario definitions and the evidence map live in
[`../scenarios/00-scenario-catalog.md`](../scenarios/00-scenario-catalog.md).

## The business series (companion)

A buyer-facing companion lives in [`business/`](business/README.md). It walks the
headline economics — dormant-trial NoOps, shadow-IT discovery, coach-first AI-app
DLP, smart-default compliance, and self-hosted/shared AI — as persona +
jobs-to-be-done journeys.

## The build series (companion)

A technical-product companion lives in [`../build/`](../build/README.md): ten
posts on *how you would build a system like this*, pairing each load-bearing
engineering decision with the business call behind it and how the incumbents
(Zscaler, Palo Alto, Fortinet, Netskope, Cato) made the same call differently.

| # | Post | Persona | Capability |
| --- | --- | --- | --- |
| B0 | [Business intro + evidence contract](business/00-business-series-intro.md) | — | — |
| B1 | [The NoOps trial that costs almost nothing](business/08-noops-dormant-trials.md) | Mara (MSP) | Dormancy tiering + hibernation |
| B2 | [Shadow-IT discovery without the noise](business/09-shadow-it-noops.md) | Sam (IT lead) | CASB NoOps |
| B3 | [PII at the AI edge: coach, don't block](business/10-ai-dlp-coaching.md) | Lena (analyst) | AI-app DLP + HITL |
| B4 | [Compliance baselines in minutes](business/11-compliance-templates.md) | Mara (MSP) | Smart-default templates + continuous evidence |
| B5 | [Prove the spend, prove the posture](business/12-cost-and-competition.md) | Tom (CFO) | Shared AI + metering + critique |

## Evidence sources (all in-repo)

- **Screenshots:** [`../artifacts/screenshots/`](../artifacts/screenshots/) —
  live console captures via CDP against the seeded fleet (fleet metering, CASB
  NoOps shadow-IT, cross-tenant capability roll-out, DLP review queue, guided
  onboarding, IdP directory, app registry, compliance posture).
- **Payloads:** [`../artifacts/payloads/`](../artifacts/payloads/) — verbatim
  control-plane responses, including the application-identification catalog and
  signed bundle, the managed threat-content posture, the continuous-compliance
  posture and evidence packs, the digital-experience scores and degradation
  alert, and the policy-recommendation surface.
- **Efficacy matrix:** [`../artifacts/efficacy-report.json`](../artifacts/efficacy-report.json)
  — 16 functions (incl. kernel firewall, Suricata IPS, an on-device ML-NER
  classifier, two adversarial corpora, three wild corpora, and two
  false-positive load corpora), real crate APIs, suite verdict PASS.
- **Edge throughput:** [`../artifacts/multiqueue-micro.json`](../artifacts/multiqueue-micro.json)
  (5.718 → 27.264 Gbps, 4.77×) and
  [`../artifacts/multi-queue-branch-large.json`](../artifacts/multi-queue-branch-large.json)
  (4.461 → 20.588 Gbps, 4.61×) — single-stream floor vs multi-queue ceiling.
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

With the stack up (control plane on `:8080`, console on `:5173`) and
`AUTH_JWT_SECRET` exported:

```bash
# 1. Seed the nine-tenant multi-country fleet under one MSP (idempotent).
(cd blog/harness/seed && go run .)

# 2. Drive usage so the metering projections have data.
(cd blog/harness/usage && go run .)

# 3. Emit anomaly alerts (baseline models + spikes for the Alerts surface).
(cd blog/harness/anomalies && go run .)

# 4. Capture the core API payloads.
(cd blog/harness/capture && go run . -base http://127.0.0.1:8080 -out ../../artifacts/payloads)

# 5. Real CASB NoOps engine output (runs the production Reconcile()/RunDigests()).
(cd blog/harness/casb && go run .)

# 6. Capture the application-identification, managed-threat-content,
#    continuous-compliance, digital-experience, and policy-recommendation
#    payloads (mints an admin JWT from AUTH_JWT_SECRET, ingests a deterministic
#    experience-probe batch, then captures every response verbatim).
(cd blog/harness/newcaps && go run .)

# 7. Efficacy + performance (Rust).
ORT_DYLIB_PATH=$HOME/.local/onnxruntime/libonnxruntime.so \
  ./bench/efficacy/target/release/sng-efficacy \
  --firewall --firewall-kernel --swg --ztna --ips --dlp --malware --dns \
  --adversarial --wild --out blog/artifacts/efficacy-report.json
./bench/target/release/sng-bench multi-queue --profile bench/profiles/skus/micro.toml \
  --mode full-stack --backend nftables --out blog/artifacts/multiqueue-micro.json

# 8. 5,000-tenant capacity plan (dormancy dividend + shared-AI footprint).
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
