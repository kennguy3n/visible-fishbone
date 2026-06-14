# ShieldNet Gateway, measured: operating 5,000 SME tenants the NoOps way

> **Post 0 of 11 — the series intro and the honesty contract.**
>
> This is an engineering blog series, not a launch announcement. Over eleven
> posts we stand up ShieldNet Gateway (SNG) from a clean database, seed a
> **nine-tenant fleet spanning seven countries and eight industries** under one
> MSP, and walk the *real* product — the Go control plane, the React console,
> the Rust edge crates, the Postgres RLS isolation model, and the metering/cost
> engine.
>
> This cycle has a theme: **run 5,000 SME tenants — most of them dormant trials
> — without hiring an operations team.** A twelve-workstream push merged into
> `main` (`65824c75`) to make that real: universal dormancy tiering,
> hibernation/scale-to-zero, tier-aware telemetry, a self-operating control
> plane (auto-promotion + capacity autopilot + margin autopilot), a shared AI
> inference pool, line-rate-ish multi-queue edge, and a breadth catch-up across
> identity, threat-intel, and CASB/DLP. Every figure below is **re-measured on
> the merged code**, not the previous phase. Every screenshot is a live, seeded,
> error-free page. Every payload is a verbatim capture from a running control
> plane. Every efficacy number comes from a harness that drives the actual
> enforcement code.

## What SNG is

ShieldNet Gateway is a multi-tenant SASE platform with three moving parts:

- **Control plane** — Go service on `:8080`, Postgres 16 with row-level security
  (RLS) for hard tenant isolation, NATS JetStream for config distribution, and
  ClickHouse for telemetry. It compiles one typed *policy graph* per tenant into
  signed bundles the edge enforces.
- **Console** — a React admin/MSP UI on `:5173`. One pane for NGFW, IPS, SWG,
  DNS security, SD-WAN steering, ZTNA, DLP, CASB, browser isolation, AI-assisted
  operations, metering, compliance, and audit.
- **Edge** — Rust crates that enforce the compiled bundle: `sng-fw` (firewall),
  `sng-ips` (Suricata-driven IPS), `sng-swg` (secure web gateway + yara-x malware
  scanning + ClamAV INSTREAM + safe-browsing/category filtering), `sng-dns`
  (threat-intel sinkhole + tunnelling detection), `sng-ztna` (zero-trust
  brokering), `sng-dlp` (on-device ML classifier + coach-first AI-app DLP).
  Beneath the firewall sits an eBPF/XDP fast path — a tail-call-split in-kernel
  pipeline with an LRU verdict cache that serves repeat flows before they reach
  userspace, failing open to nftables for anything it can't decide, and this
  cycle fanned out across NIC RSS queues (Post 2 walks the scaling curve).

## The honesty contract

The single most important thing in this series is what we *don't* claim. Four
rules govern every figure:

1. **Measured ≠ dry-run, and we publish both.** The edge performance harness
   (`bench/`) has an in-process mode that crafts and measures frames with no
   wire I/O — a **ceiling**, not real inspected NIC throughput. We also publish
   a **floor**: a single-stream number (≈5.5 Gbps) and the multi-queue scale-up
   to ≈26 Gbps ([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json),
   Post 2). We refuse to quote the ceiling as a competitive figure; tables show
   floor *and* ceiling side by side, and per-packet latency percentiles are
   called out separately from headline Gbps.

2. **Competitor numbers are published datasheet figures, caveated.** They live
   in [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
   with a `source_url` and a `caveat` on every row. Most competitor boxes are
   ASIC-accelerated fixed appliances; SNG is software-only on a generic x86 VM.
   That is **not** apples-to-apples, and every comparison says so. The
   cloud-native rows (Zscaler) are the only directly comparable ones.

3. **Screenshots are of real, seeded, error-free pages.** Every capture is a
   live console route against the seeded nine-tenant fleet, shot via CDP on this
   VM. We do not screenshot loading spinners or error states.

4. **The critique is honest.** Every post ends with a "where we fall short"
   section, and Post 9 carries a consolidated, evidence-based competitive
   critique against Zscaler, Palo Alto Prisma Access, Cloudflare, Netskope,
   Cato, and Fortinet. This is a critique, not a brochure.

## What shipped this cycle: the 5,000-tenant NoOps push

Last cycle we wired up the deferred enforcement surfaces. This cycle we answered
a harder question — *what does it cost to run 5,000 mostly-dormant SME tenants,
and who operates them?* — with twelve workstreams, all merged into `main` behind
default-OFF gates so an upgrade is behaviourally inert until an operator (or the
autopilot) opts a tenant in.

| WS | Capability | Lands in | PR(s) | Status on `main` |
| --- | --- | --- | --- | --- |
| WS-1 | Universal dormancy tiering (shared sweep planner for *every* periodic job) | Post 2 | [#219](https://github.com/kennguy3n/visible-fishbone/pull/219) | Merged — 10× fewer tenant-visits/cycle ([capacity plan](../artifacts/capacity-plan-5000/report.md)) |
| WS-2 | `last_active_at` writer coverage + correctness | Post 2 | [#215](https://github.com/kennguy3n/visible-fishbone/pull/215) | Merged — the activity signal hibernation trusts |
| WS-3 | Hibernation / scale-to-zero + wake-on-activity | Post 3 | [#222](https://github.com/kennguy3n/visible-fishbone/pull/222) | Merged, default-OFF (`HIBERNATION_ENABLED`, migration 068) |
| WS-4 | Tier-aware telemetry sampling | Post 3 | [#220](https://github.com/kennguy3n/visible-fishbone/pull/220) | Merged, default-OFF (`CLICKHOUSE_TIER_SAMPLING_ENABLED`) |
| WS-5 | NoOps auto-promotion (off→monitor→enforce, guardrailed) | Post 8 | [#218](https://github.com/kennguy3n/visible-fishbone/pull/218), [#228](https://github.com/kennguy3n/visible-fishbone/pull/228), [#232](https://github.com/kennguy3n/visible-fishbone/pull/232) | Merged, default-OFF (`ROLLOUT_AUTOPILOT_ENABLED`, migration 069) |
| WS-6 | Capacity autopilot (live-fleet-driven sizing) | Post 8 | [#214](https://github.com/kennguy3n/visible-fishbone/pull/214) | Merged, default-OFF (`CAPACITY_AUTOPILOT_ENABLED`) |
| WS-7 | Margin/cost autopilot | Post 8 | [#216](https://github.com/kennguy3n/visible-fishbone/pull/216) | Merged, default-OFF (`METERING_AUTOPILOT_ENABLED`) |
| WS-8 | Multi-queue / RSS edge throughput | Post 2 | [#221](https://github.com/kennguy3n/visible-fishbone/pull/221) | Merged — single-stream floor → multi-queue ceiling rig |
| WS-9 | Fleet-scale shared AI inference pool | Post 7 | [#217](https://github.com/kennguy3n/visible-fishbone/pull/217) | Merged, default-OFF (`AI_INFERENCE_POOL_ENABLED`) |
| WS-10a | IGA / IdP connector breadth | Post 5 | [#212](https://github.com/kennguy3n/visible-fishbone/pull/212) | Merged, default-OFF (`IDP_DIRECTORY_SYNC_ENABLED`) |
| WS-10b | Threat-intel feed breadth (JA3, Suricata rule bundle, retro-hunt) | Post 4 | [#213](https://github.com/kennguy3n/visible-fishbone/pull/213), [#224](https://github.com/kennguy3n/visible-fishbone/pull/224)–[#236](https://github.com/kennguy3n/visible-fishbone/pull/236) | Merged, default-OFF (`THREAT_INTEL_RETROHUNT`) |
| WS-10c | CASB SaaS-API + DLP detector catalog breadth | Post 6 | [#223](https://github.com/kennguy3n/visible-fishbone/pull/223), [#227](https://github.com/kennguy3n/visible-fishbone/pull/227), [#230](https://github.com/kennguy3n/visible-fishbone/pull/230), [#231](https://github.com/kennguy3n/visible-fishbone/pull/231) | Merged, default-OFF (`CASB_NOOPS_ENABLED`) |

The combined result builds clean (`go build ./...`, `cargo build --release`),
passes `go vet` and the unit suites across the touched packages, and migrations
sequence with no collisions (068 hibernation, 069 rollout-monitor-evidence).
A buyer-facing companion series (`business/`) walks the headline economics as
persona + jobs-to-be-done journeys.

## The cast (seeded data)

One MSP manages a **nine-tenant fleet spanning seven countries and eight
industries** across three service tiers — so every screenshot shows real
tenant-shaped data, tier differences are visible (a starter tenant genuinely has
fewer features on than an enterprise one), and **data-residency +
jurisdiction-correct compliance baselines** show up across five regimes. The
seed harness pins every tenant to a canonical UUID so payloads and screenshots
stay reproducible across reseeds (`blog/harness/seed`, idempotent).

| Tenant | Country | Industry | Tier | Compliance regime | Margin % |
| --- | --- | --- | --- | --- | ---: |
| Globex Health Systems | US | healthcare / HIPAA | enterprise | us-baseline | +66.8 |
| Britannia Robotics | GB | technology | enterprise | uk-dpa | +62.5 |
| Lumière Légal | FR | legal | professional | eu-gdpr | +55.5 |
| Outback Retail Co | AU | retail | professional | au-privacy | +54.1 |
| Nordic EduCloud | SE | education | starter | eu-gdpr | +49.5 |
| Acme Retail Group | US | retail / PCI | enterprise | us-baseline | +47.2 |
| Umbrella Logistics | SG | logistics | starter | (default) | +42.6 |
| Initech Financial | DE | finance | professional | eu-gdpr | +15.2 |
| Maple Health Network | CA | healthcare | professional | ca-pipeda | **−14.3** |

Acme is the richest tenant and the one most posts walk through; Umbrella is the
deliberately-sparse one we use for honest empty states; **Maple is deliberately
underwater** — a professional-tier tenant consuming enterprise-scale resources,
the honest upsell signal the margin autopilot (Post 8) is built to surface. The
fleet runs at **≈50.7% blended margin** ([`s7-admin-cost-report.json`](../artifacts/payloads/s7-admin-cost-report.json)).

## The personas

| Persona | Role | Cares about |
| --- | --- | --- |
| **Maya** | MSP platform lead | time-to-onboard, isolation, blast radius, cost-at-scale |
| **Devraj** | one-person SME IT | one console, safe defaults |
| **Lena** | MSP SOC analyst | catch-rate, false-positive load, time-to-explanation |
| **Tom** | CFO / buyer | predictable spend, consolidation, compliance evidence |

## The series

0. **This post** — what SNG is, and the honesty contract.
1. **One typed policy graph** (S2) — the differentiated-design centerpiece.
2. **Multi-tenant / MSP + universal dormancy tiering** (S1 + WS-1/2/8) — onboarding, RLS isolation, and the cost lever that makes 5,000 tenants affordable.
3. **Hibernation / scale-to-zero** (WS-3/4) — dormant trials cost almost nothing, and wake in under 5 seconds.
4. **Detection efficacy + threat-intel depth** (S3 + WS-10b) — the catch-rate / false-positive matrix, now with adversarial + wild corpora and a real Suricata rule bundle.
5. **Retire the VPN + identity breadth** (S4 + WS-10a) — zero-trust access and IdP/IGA directory sync.
6. **Keep regulated data in** (S5 + WS-10c) — DLP + CASB + browser isolation, broader detector and SaaS-API catalog.
7. **AI-assisted ops + shared inference** (S6 + WS-9) — the verifier-checked model, now one pooled model serving the whole fleet.
8. **NoOps self-operation** (WS-5/6/7) — auto-promotion, capacity autopilot, and margin autopilot: the platform that operates itself.
9. **Prove the spend and the posture** (S7) — cost, compliance, and the consolidated competitive critique.
10. **Six scenarios on one dev VM** — route / allow / block / prioritise / throttle / threat-protection walked as real typed policies, benchmarks re-measured on this VM.
