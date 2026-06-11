# Prove the spend, prove the posture — and where we honestly lose

> **Business series, Post 5 of 5.** Persona: **Tom**, fractional CFO across
> Mara's book of SMEs. Job-to-be-done: *"Give me a bill I can forecast, a
> consolidation story I can defend, and an honest answer to 'why not just buy
> Zscaler / Cloudflare / a FortiGate?'"*

## What the buyer is actually buying

Tom doesn't buy packets per second. He buys *predictability* and *defensibility*:
a forecastable bill, a margin he can see per customer, and a straight answer
about where this product wins and where it doesn't. This post closes the business
series with all three.

## The spend, on a real page

The Metering page turns raw usage meters into a buyer-facing view — eight metered
dimensions per tenant, each with current usage, a **projected** period-end total,
and a budget bar. Here's Acme, projecting **$1,047.59/mo** at **47.6% margin**:

![Metering & cost — Acme](../../artifacts/business/biz-09-metering-cost.png)

And the fleet roll-up across all four tenants — cost vs. revenue vs. margin, the
number Tom actually manages to:

![Fleet cost & margin](../../artifacts/business/biz-10-fleet-margin.png)

| Tenant | Tier | Projected cost/mo | Margin |
| --- | --- | ---: | ---: |
| Acme Retail Group | Enterprise | $1,047.59 | 47.6% |
| Globex Health Systems | Enterprise | $658.69 | 67.0% |
| Initech Financial | Professional | $418.97 | 16.0% |
| Umbrella Logistics | Starter | $56.47 | 43.0% |

The **projection** is the feature: the engine extrapolates a partial-period run
rate to a period-end total and flags "on track to breach" *before* the invoice,
not after. Initech's thin 16% margin isn't a mystery — it's a visible run-rate
story Tom can act on before renewal.

## The structural cost advantage: zero idle cost + self-hosted AI

Two of the new capabilities change the cost *curve*, not just the reporting:

1. **Dormant trials cost almost nothing** (Post 1). Because the platform's
   periodic work is activity-tiered, a trial that goes quiet is swept ~1/100th as
   often as a busy tenant. Mara can offer trials to everyone; Tom doesn't see the
   bill scale with sign-ups. Appliance and per-seat-licensed incumbents charge
   from day one whether the tenant is active or not.

2. **The AI engine is self-hosted with zero per-call cost.** SNG bakes in the
   Ternary-Bonsai-8B Q2_0 (2-bit) model
   ([PR #155](https://github.com/kennguy3n/visible-fishbone/pull/155)) as the
   default AI engine — pinned to an exact, checksum-verified artifact and run
   on-box. The AI-assisted classification and policy-suggestion features
   (Posts 2–3) don't bill a cloud LLM per call. For an MSP running AI features
   across 5,000 tenants, "no per-call cloud inference cost" is the difference
   between AI features being a margin sink and a margin-neutral default.

## The honest competitive assessment

All competitor figures are **published datasheet numbers** from
[`competitors.json`](../../bench/business-report/competitors.json), each with a
`source_url` and a caveat. **Every hardware row is an ASIC-accelerated appliance;
SNG is software-only on a generic x86 VM — that is not apples-to-apples.** The
[engineering Post 7](../07-s7-cost-compliance-competitive.md) carries the full
throughput tables; here is the *business* read, capability by capability.

### Where SNG wins for the SME/MSP buyer

- **Trial economics.** Activity-tiered dormancy means trials don't bleed money.
  This is an architectural advantage over per-seat (Zscaler/Netskope) and
  per-appliance (Fortinet) models, where a dormant trial still costs.
- **NoOps shadow-IT.** The discover→classify→recommend→audit loop (Post 2) gives
  an SME with no SOC a *decided* list, not a firehose. Netskope and Zscaler have
  deeper CASB catalogs, but they assume an analyst to drive them.
- **Coach-first AI-app DLP.** Defaulting to coaching over blocking (Post 3) is
  the design that keeps the control switched on in a no-SOC shop. Specialist DLP
  vendors lead on detector breadth but default to a heavier-handed posture.
- **Compliance-in-two-dropdowns.** The 14-template deny-by-default catalog
  (Post 4) gets an SME to a jurisdiction-correct posture in minutes. Incumbents
  assume a security team to author policy.
- **Self-hosted AI, zero per-call cost + auditable verdicts.** No cloud-LLM bill,
  and AI verdicts cite compiled rules rather than vibes.

### Where SNG honestly loses

- **Zscaler / Cloudflare — scale and global PoP network.** SNG is *software you
  run*, not a global network you rent. For raw edge scale, DDoS absorption, and
  PoP footprint, this isn't a contest. SNG's counter is policy-model coherence,
  on-device DLP, and SME-friendly economics — not network scale.
- **Palo Alto Prisma Access — threat-intel depth.** PAN's signature/research
  pipeline is the industry's deepest. SNG's IPS is real Suricata — credible, not
  a match. An enterprise buying on threat-research depth should know that.
- **Netskope — CASB/DLP catalog breadth.** Netskope's SaaS-API coverage and
  detector catalog are far ahead. SNG's CASB classifier is heuristic-first with
  optional on-box AI refinement; it's built for *decided defaults*, not
  exhaustive coverage.
- **Cato Networks — operational maturity.** The closest philosophical sibling
  (converged, cloud-native). Cato is further down the same road with a real PoP
  footprint and years of operational hardening SNG doesn't have yet.
- **Fortinet — appliance price/performance.** You cannot beat custom ASIC on
  $/Gbps for a fixed box. SNG's win is *not being an appliance* — no refresh
  cycle, cloud-elastic, activity-priced — not the per-Gbps sticker.

### The one-line summary for Tom

> SNG is the honest choice for an **MSP serving many small tenants** who needs
> NoOps automation, trial economics that don't punish growth, and a compliant
> default in minutes. It is **not** the choice for a single large enterprise
> buying on global-network scale or the deepest threat-research catalog — and we
> just told you which incumbent to buy instead in each of those cases.

## Where this whole series falls short (consolidated, honest)

- **Integration is partial.** Several capabilities ship as tested, opt-in
  components with runtime wiring still in progress — the dormancy planner has one
  live consumer (Post 1), the HITL review queue has no console API yet (Post 3),
  and the cross-tenant template roll-out UI is thin (Post 4). We labeled each one
  in place rather than implying a finished product.
- **The classifiers are heuristic-first.** CASB classification and AI-app
  destination detection make conservative, confidence-scored guesses for the long
  tail and *say so* in their rationale. Optional self-hosted AI refinement raises
  confidence; it doesn't make the baseline omniscient.
- **Cost figures are projections, not invoices**, and the throughput story is a
  software-on-VM story, not a silicon one. Both are caveated everywhere they
  appear.

## The takeaway for Tom

He gets a forecastable bill with per-tenant margin he can manage, a cost *curve*
that rewards growth instead of punishing it (dormant trials and self-hosted AI),
and — most importantly — a vendor that will tell him exactly when to buy someone
else. That honesty is the most defensible thing in the deck.

---

*This concludes the business series. The* [engineering series](../README.md)
*covers the same product for a technical reader, with the full performance,
efficacy, and architecture detail.*
