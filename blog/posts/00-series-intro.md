# ShieldNet Gateway, measured: a SASE platform walked end-to-end

> **Post 0 of 9 — the series intro and the honesty contract.**
>
> This is an engineering blog series, not a launch announcement. Over nine
> posts we stand up ShieldNet Gateway (SNG) from a clean database, seed a
> **nine-tenant fleet spanning seven countries and eight industries** under one
> MSP, and walk the *real* product — the Go control plane, the React console,
> the Rust edge crates, the Postgres RLS isolation model, and the metering/cost
> engine. Post 8 is this cycle's capstone: the six operator scenarios
> (**route / allow / block / prioritise / throttle / threat-protection**) walked
> as real typed policies, with every figure re-measured on this dev VM.
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

1. **Measured ≠ dry-run, and we publish both.** The edge performance harness
   (`bench/`) has a `--dry-run` mode that crafts and measures frames *in-process
   with no wire I/O* — that number is a **ceiling**, exercising the
   craft→measure pipeline, not real inspected NIC throughput. This cycle a real
   wire rig (`sng-bench-wire`, AF_PACKET in-path) and a multi-queue scaling rig
   landed, so we now also publish a **floor**: a single-stream wire number
   (≈5.5 Gbps) and the multi-queue scale-up to ≈26 Gbps (Posts 1, 7, 8). We
   refuse to quote the dry-run ceiling as a competitive figure; throughput
   tables show ceiling *and* floor side by side, and the per-packet *latency*
   percentiles are called out separately from the headline Gbps.

2. **Competitor numbers are published datasheet figures, caveated.** They live
   in [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json)
   with a `source_url` and a `caveat` on every row. Most competitor boxes are
   ASIC-accelerated fixed appliances; SNG is software-only on a generic x86 VM.
   That is **not** apples-to-apples, and every comparison says so. The
   cloud-native rows (Zscaler) are the only directly comparable ones, and we
   lean on those for the honest comparison.

3. **Screenshots are of real, seeded, error-free pages.** Every capture in this
   series is a live console route against the seeded nine-tenant fleet. Where a
   surface is populated only by the real enforcement path and has no "create"
   API (the DLP review queue), we seed deterministic rows that mirror exactly
   the redacted shape the real producer writes, and we say so
   ([`blog/harness/seed/dlp_review_seed.sql`](../harness/seed/dlp_review_seed.sql),
   noted in [`../artifacts/scenarios.md`](../artifacts/scenarios.md)). We do not
   screenshot loading spinners or error states.

4. **The critique is honest.** Every post ends with a "where we fall short"
   section, and Post 7 carries a consolidated, evidence-based competitive
   critique against Zscaler, Palo Alto Prisma Access, Cloudflare, Netskope,
   Cato, and Fortinet. This is a critique, not a brochure.

## What shipped this cycle (and what's actually wired)

Last refresh, six new capabilities were *code-complete but not yet wired* into
the running control plane. This cycle the wiring landed: PRs **#172, #176–#183**
are merged into `main`. The honest distinction now is **wired vs. default-ON** —
the new enforcement surfaces ship behind default-OFF feature gates so an upgrade
is behaviourally inert until an operator opts in. That is the production-correct
posture (no surprise enforcement on upgrade), and it is what the screenshots and
payloads in this series reflect.

| Capability | Lands in | PR | Status on `main` |
| --- | --- | --- | --- |
| CASB shadow-IT NoOps (classify/recommend/audit) | Post 5 | [#172](https://github.com/kennguy3n/visible-fishbone/pull/172) | Wired — real engine output captured via `blog/harness/casb` |
| DLP review-queue operator API | Post 5, 6 | [#176](https://github.com/kennguy3n/visible-fishbone/pull/176) | Wired — console queue live (Post 8 screenshot) |
| IdP directory sync | Post 4 | [#177](https://github.com/kennguy3n/visible-fishbone/pull/177) | Wired, default-OFF (`IDP_DIRECTORY_SYNC_ENABLED`) |
| ClamAV INSTREAM + safe-browsing (ext-authz listener) | Post 5 | [#178](https://github.com/kennguy3n/visible-fishbone/pull/178) | Wired, default-OFF (constructor-gated, fail-open when off) |
| DLP review-queue console UI | Post 5, 6 | [#179](https://github.com/kennguy3n/visible-fishbone/pull/179) | Wired — live `/dlp/review-queue` page |
| SCIM / IdP de-provisioning hardening | Post 4 | [#180](https://github.com/kennguy3n/visible-fishbone/pull/180) | Wired — deactivation revokes live ZTNA sessions |
| Multi-queue NIC wire-throughput benchmark | Post 8 | [#181](https://github.com/kennguy3n/visible-fishbone/pull/181) | Harness — single-stream floor vs multi-queue ceiling |
| DLP detector breadth (+ES/IT/NL/PL/BE) + AI-app exfil wired | Post 5 | [#182](https://github.com/kennguy3n/visible-fishbone/pull/182) | Wired — also fixed 3 real validator bugs |
| ZTNA continuous re-evaluation (`ReevalLoop`) | Post 4 | [#183](https://github.com/kennguy3n/visible-fishbone/pull/183) | Wired, default-OFF (`ztna.reeval_enabled`) |

A buyer-facing companion series (`business/`) walks the headline capabilities as
persona + jobs-to-be-done journeys.

## The cast (seeded data)

One MSP manages a **nine-tenant fleet spanning seven countries and eight
industries** across three service tiers — so every screenshot shows real
tenant-shaped data, the tier differences are visible (a starter tenant genuinely
has fewer features turned on than an enterprise one), and **data-residency +
jurisdiction-correct compliance baselines** show up across five regimes. The
seed harness pins every tenant to a canonical UUID so payloads and screenshots
stay reproducible across reseeds (`blog/harness/seed`, idempotent).

| Tenant | Country | Industry | Tier | Compliance regime | Sites | Devices |
| --- | --- | --- | --- | --- | ---: | ---: |
| Acme Retail Group | US | retail / PCI | enterprise | us-baseline | 6 | 4 |
| Globex Health Systems | US | healthcare / HIPAA | enterprise | us-baseline | 5 | 4 |
| Britannia Robotics | GB | technology | enterprise | uk-dpa | 5 | 4 |
| Initech Financial | DE | finance | professional | eu-gdpr | 3 | 3 |
| Maple Health Network | CA | healthcare | professional | ca-pipeda | 4 | 3 |
| Outback Retail Co | AU | retail | professional | au-privacy | 5 | 3 |
| Lumière Légal | FR | legal | professional | eu-gdpr | 3 | 2 |
| Nordic EduCloud | SE | education | starter | eu-gdpr | 2 | 2 |
| Umbrella Logistics | SG | logistics | starter | (default) | 2 | 2 |

That's **35 sites and 27 devices across five compliance regimes** (us-baseline,
uk-dpa, eu-gdpr, ca-pipeda, au-privacy). Acme is the richest tenant and the one
most posts walk through; Umbrella is the deliberately-sparse one we use to show
honest empty states; the smart-default policy-template engine renders each
tenant's `(industry, country)` coordinates into a jurisdiction-correct baseline
graph (Post 8).

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
8. **Six scenarios on one dev VM** — route / allow / block / prioritise /
   throttle / threat-protection walked as real typed policies, with the
   efficacy + throughput benchmarks re-measured on this VM and an honest
   competitor read.

Every post follows the same shape: business context → the scenario walked in the
UI with real screenshots → the real data behind it → how it works under the hood
→ where we fall short. Let's start with the thing that makes SNG different: a
single typed policy graph.
