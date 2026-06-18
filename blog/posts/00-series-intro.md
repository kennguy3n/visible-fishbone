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
> The product has a theme: **run 5,000 SME tenants — most of them dormant trials
> — without hiring an operations team.** That shapes everything: universal
> dormancy tiering, hibernation/scale-to-zero, tier-aware telemetry, a
> self-operating control plane (auto-promotion + capacity autopilot + margin
> autopilot) backed by an active/active work distributor, a shared AI inference
> pool, a signed application-identification catalog, managed threat content,
> on-device DLP with OCR and document fingerprinting, lightweight
> digital-experience monitoring, continuous compliance evidence, a policy
> recommendation engine, and a multi-queue edge. Every figure below is
> **measured on the current codebase**. Every screenshot is a live, seeded,
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
  userspace, failing open to nftables for anything it can't decide, and fans
  out across NIC RSS queues (Post 2 walks the scaling curve).

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

## What's actually wired: the 5,000-tenant NoOps platform

The load-bearing question SNG is built around is *what does it cost to run 5,000
mostly-dormant SME tenants, and who operates them?* The answer is a set of
capabilities that, by default, are behaviourally inert until an operator (or the
autopilot) opts a tenant in — so a deployment stays predictable until you turn a
lever. Here is what each does and where this series walks it.

| Capability | What it does | Walked in | Default |
| --- | --- | --- | --- |
| Universal dormancy tiering | Shared sweep planner for *every* periodic job — 10× fewer tenant-visits/cycle ([capacity plan](../artifacts/capacity-plan-5000/report.md)) | Post 2 | On |
| Active/active work distributor | Lease-fenced tenant-shard ownership so periodic work runs across replicas, not on one leader | Post 2, 8 | On |
| Hibernation / scale-to-zero | Dormant trials wind down to near-zero and wake on activity | Post 3 | Off (`HIBERNATION_ENABLED`) |
| Tier-aware telemetry sampling | Telemetry volume scales with tenant tier and activity | Post 3 | Off (`CLICKHOUSE_TIER_SAMPLING_ENABLED`) |
| NoOps auto-promotion | Guardrailed `off→monitor→enforce` capability ladder | Post 8 | Off (`ROLLOUT_AUTOPILOT_ENABLED`) |
| Capacity autopilot | Live-fleet-driven sizing recommendations | Post 8 | Off (`CAPACITY_AUTOPILOT_ENABLED`) |
| Margin / cost autopilot | Surfaces underwater tenants as an upsell signal | Post 8 | Off (`METERING_AUTOPILOT_ENABLED`) |
| Multi-queue / RSS edge | Single-stream floor → multi-queue ceiling throughput | Post 2 | On |
| Shared AI inference pool | One pooled model serves the whole fleet | Post 7 | Off (`AI_INFERENCE_POOL_ENABLED`) |
| Application-identification catalog | Signed, versioned App-ID catalog (215 apps / 17 categories) replacing a closed protocol set | Post 1, 4 | On |
| Managed threat content | Curated, signed threat-indicator bundle delivered with no per-tenant config | Post 4 | On (`THREAT_INTEL_ENABLED`) |
| IdP / IGA directory sync | Directory federation + app registry breadth | Post 5 | Off (`IDP_DIRECTORY_SYNC_ENABLED`) |
| Digital-experience monitoring | Lightweight ZDX-style per-target experience scores + degradation alerts | Post 5 | On |
| DLP OCR + document fingerprinting | On-device classifier extended to image-borne data and document identity matching | Post 6 | On |
| CASB NoOps | Shadow-IT discovery + recommended action with no manual tuning | Post 6 | On (`CASB_NOOPS_ENABLED`) |
| Continuous compliance evidence | SOC 2 / ISO 27001 posture + downloadable evidence packs, collected on a schedule | Post 9 | On |
| Policy recommendation engine | Traffic-derived, verifier-checked policy suggestions | Post 1, 7 | On (needs telemetry hot tier) |

The platform builds clean (`go build ./...`, `cargo build --release`), passes
`go vet` and the unit suites across all packages, and migrations sequence with
no collisions. A buyer-facing companion series (`business/`) walks the headline
economics as persona + jobs-to-be-done journeys.

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
| Globex Health Systems | US | healthcare / HIPAA | enterprise | us-baseline | +66.9 |
| Britannia Robotics | GB | technology | enterprise | uk-dpa | +62.5 |
| Lumière Légal | FR | legal | professional | eu-gdpr | +55.5 |
| Outback Retail Co | AU | retail | professional | au-privacy | +54.1 |
| Nordic EduCloud | SE | education | starter | eu-gdpr | +49.5 |
| Acme Retail Group | US | retail / PCI | enterprise | us-baseline | +47.2 |
| Umbrella Logistics | SG | logistics | starter | (default) | +42.6 |
| Initech Financial | DE | finance | professional | eu-gdpr | +15.2 |
| Maple Health Network | CA | healthcare | professional | ca-pipeda | **−13.9** |

Acme is the richest tenant and the one most posts walk through; Umbrella is the
deliberately-sparse one we use for honest empty states; **Maple is deliberately
underwater** — a professional-tier tenant consuming enterprise-scale resources,
the honest upsell signal the margin autopilot (Post 8) is built to surface. The
fleet runs at **≈50.9% blended margin** ([`s7-admin-cost-report.json`](../artifacts/payloads/s7-admin-cost-report.json)).

## The personas

| Persona | Role | Cares about |
| --- | --- | --- |
| **Maya** | MSP platform lead | time-to-onboard, isolation, blast radius, cost-at-scale |
| **Devraj** | one-person SME IT | one console, safe defaults |
| **Lena** | MSP SOC analyst | catch-rate, false-positive load, time-to-explanation |
| **Tom** | CFO / buyer | predictable spend, consolidation, compliance evidence |

## The series

0. **This post** — what SNG is, and the honesty contract.
1. **One typed policy graph** — the differentiated-design centerpiece, now with application-aware predicates and traffic-derived recommendations.
2. **Multi-tenant / MSP + universal dormancy tiering** — onboarding, RLS isolation, the active/active work distributor, and the cost lever that makes 5,000 tenants affordable.
3. **Hibernation / scale-to-zero** — dormant trials cost almost nothing, and wake in under 5 seconds.
4. **Detection efficacy + managed threat content** — the catch-rate / false-positive matrix, with adversarial + wild corpora, a real Suricata rule bundle, and a signed managed threat-content bundle.
5. **Retire the VPN + identity + experience** — zero-trust access, IdP/IGA directory sync, and lightweight digital-experience monitoring.
6. **Keep regulated data in** — DLP (including OCR and document fingerprinting) + CASB + browser isolation.
7. **AI-assisted ops + shared inference** — the verifier-checked model, one pooled model serving the whole fleet, and policy synthesis from traffic.
8. **NoOps self-operation** — auto-promotion, capacity autopilot, margin autopilot, and the work distributor: the platform that operates itself.
9. **Prove the spend and the posture** — cost, continuous compliance evidence, and the consolidated competitive critique.
10. **Six scenarios on one dev VM** — route / allow / block / prioritise / throttle / threat-protection walked as real typed policies, benchmarks measured on this VM.
