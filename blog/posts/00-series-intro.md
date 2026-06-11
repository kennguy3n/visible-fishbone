# ShieldNet Gateway, measured: a SASE platform walked end-to-end

> **Post 0 of 8 — the series intro and the honesty contract.**
>
> This is an engineering blog series, not a launch announcement. Over eight
> posts we stand up ShieldNet Gateway (SNG) from a clean database, seed four
> realistic tenants under one MSP, and walk seven executive scenarios through
> the *real* product — the Go control plane, the React console, the Rust edge
> crates, the Postgres RLS isolation model, and the metering/cost engine.
> Every screenshot is of a live, seeded, error-free page. Every payload is a
> verbatim capture from a running control plane. Every efficacy number comes
> from a harness that drives the actual enforcement code.

## What SNG is

ShieldNet Gateway is a multi-tenant SASE platform with three moving parts:

- **Control plane** — Go service on `:8080`, Postgres 16 with row-level security
  (RLS) for hard tenant isolation, NATS JetStream for config distribution, and
  ClickHouse for telemetry. It compiles one typed *policy graph* per tenant into
  signed bundles the edge enforces.
- **Console** — a React admin/MSP UI on `:5173`. One pane for NGFW, IPS, SWG,
  DNS security, SD-WAN steering, ZTNA, DLP, CASB, browser isolation, AI-assisted
  operations, metering, compliance, and audit.
- **Edge** — Rust crates (MSRV 1.91) that enforce the compiled bundle: `sng-fw`
  (firewall), `sng-ips` (Suricata-driven IPS), `sng-swg` (secure web gateway +
  yara-x malware scanning, plus this cycle's **ClamAV INSTREAM** content scan and
  **safe-browsing/category** filtering — Post 5), `sng-dns` (threat-intel sinkhole
  + tunneling detection), `sng-ztna` (zero-trust brokering), `sng-dlp` (on-device
  ML classifier + coach-first **AI-app DLP** — Post 5). Beneath the firewall sits
  an optional **eBPF/XDP fast path**
  ([PR #129](https://github.com/kennguy3n/visible-fishbone/pull/129)) — a
  tail-call-split in-kernel pipeline with an LRU verdict cache that serves
  repeat flows before they ever reach userspace, failing open to nftables for
  anything it can't decide. Post 1 walks it.

## The honesty contract

The single most important thing in this series is what we *don't* claim. Four
rules govern every figure:

1. **Measured ≠ dry-run.** The edge performance harness (`bench/`) has a
   `--dry-run` mode that crafts and measures frames *in-process with no wire
   I/O*. Its Gbps numbers exercise the craft→measure pipeline, **not** real
   inspected throughput on a NIC. Real wire numbers need `CAP_NET_RAW` and an
   in-path edge, which this non-privileged VM cannot provide. So when you see a
   throughput table, you will also see the dry-run caveat — and the per-packet
   *latency* percentiles (which are genuinely informative even in dry-run) are
   called out separately from the headline Gbps.

2. **Competitor numbers are published datasheet figures, caveated.** They live
   in [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
   with a `source_url` and a `caveat` on every row. Most competitor boxes are
   ASIC-accelerated fixed appliances; SNG is software-only on a generic x86 VM.
   That is **not** apples-to-apples, and every comparison says so. The
   cloud-native rows (Zscaler) are the only directly comparable ones, and we
   lean on those for the honest comparison.

3. **Screenshots are of real, seeded, error-free pages.** Before any capture we
   audited all 31 console routes across all four tenants for load/console
   errors. Three routes (DLP, Browser protection, Terraform) were genuinely
   broken — missing Postgres repositories, never wired into the router — and we
   fixed them properly ([PR #116](https://github.com/kennguy3n/visible-fishbone/pull/116))
   rather than screenshotting around them. The console also got a full
   design-system pass ([PR #117](https://github.com/kennguy3n/visible-fishbone/pull/117))
   so the screenshots reflect the product, not a prototype.

4. **The critique is honest.** Every post ends with a "where we fall short"
   section, and Post 7 carries a consolidated, evidence-based competitive
   critique against Zscaler, Palo Alto Prisma Access, Cloudflare, Netskope,
   Cato, and Fortinet. This is a critique, not a brochure.

## What shipped this cycle (and what's actually wired)

This refresh folds six new capabilities into the series — and applies rule 3 to
them honestly. Most are code-complete and tested on `main` but **not yet wired
into the running control plane** (a single integration PR is staged for that), so
the evidence for them is real engine output and passing tests, not live console
screenshots claiming production enforcement:

| Capability | Lands in | PR | Live in console? |
| --- | --- | --- | --- |
| Activity-tiered dormancy | Post 2, 7 | #154 | No — tested, planner not started in `main` |
| ClamAV INSTREAM content scan | Post 5 | #156 | No — OFF by default, constructor-gated |
| Safe-browsing / category filtering | Post 5 | #156 | No — staged for integration |
| Shadow-IT NoOps (classify/recommend/audit) | Post 5 | #159, #172 | Real engine output captured; runtime wiring in #172 |
| Coach-first AI-app DLP + HITL review queue | Post 5, 6 | #158 | No console API for the queue yet |
| Self-hosted Bonsai-8B Q2_0 bake | Post 6, 7 | #155 | Deploy artifact; needs prism-branch kernels |

A buyer-facing companion series (`business/`) walks the same six as
persona + jobs-to-be-done journeys.

## The cast (seeded data)

One MSP, **Northwind Managed Security**, manages four tenants spanning three
service tiers — so every screenshot shows real tenant-shaped data, and the
tier differences are visible (a starter tenant genuinely has fewer features
turned on than an enterprise one):

| Tenant | Tier | Vertical | Sites | Devices |
| --- | --- | --- | ---: | ---: |
| Acme Retail Group | enterprise | retail / PCI | 6 | 4 |
| Globex Health Systems | enterprise | healthcare / HIPAA | 5 | 4 |
| Initech Financial | professional | finance | 3 | 3 |
| Umbrella Logistics | starter | logistics | 2 | 2 |

Acme is the richest tenant and the one most posts walk through; Umbrella is the
deliberately-sparse one we use to show honest empty states; Initech carries the
one credible cost anomaly in the dataset (more in Post 7).

## The personas

| Persona | Role | Cares about |
| --- | --- | --- |
| **Maya** | MSP platform lead | time-to-onboard, isolation, blast radius |
| **Devraj** | one-person SME IT | one console, safe defaults |
| **Lena** | MSP SOC analyst | catch-rate, false-positive load, time-to-explanation |
| **Tom** | CFO / buyer | predictable spend, consolidation, compliance evidence |

## The series

0. **This post** — what SNG is, and the honesty contract.
1. **One typed policy graph** (S2) — the differentiated-design centerpiece.
2. **Multi-tenant / MSP onboarding** (S1) — the operations story + RLS isolation.
3. **Detection efficacy** (S3) — the catch-rate / false-positive matrix.
4. **Retire the VPN** (S4) — zero-trust access to private apps.
5. **Keep regulated data in** (S5) — DLP + CASB + browser isolation.
6. **AI-assisted, verifier-checked operations** (S6) — the model deep-dive.
7. **Prove the spend and the posture** (S7) — cost, compliance, and the
   consolidated competitive critique.

Every post follows the same shape: business context → the scenario walked in the
UI with real screenshots → the real data behind it → how it works under the hood
→ where we fall short. Let's start with the thing that makes SNG different: a
single typed policy graph.
