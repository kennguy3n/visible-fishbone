# Prove the spend, prove the posture

> **Business series, Post 5 of 5.** Buyer: **Tom**, the CFO signing off on the
> security spend. Job-to-be-done: *"show me the cost is predictable, the
> protection is real, and the comparison to the incumbents is honest."*
> Capability: shared AI + metering/margin + the consolidated critique.
> Evidence: [`s7-admin-cost-report.json`](../../artifacts/payloads/s7-admin-cost-report.json),
> [`capacity-plan-5000/report.md`](../../artifacts/capacity-plan-5000/report.md),
> [`efficacy-report.json`](../../artifacts/efficacy-report.json),
> [`../../../bench/business-report/competitors.json`](../../../bench/business-report/competitors.json);
> screenshots [`new-metering-fleet-top.png`](../../artifacts/screenshots/new-metering-fleet-top.png),
> [`new-metering-fleet-table.png`](../../artifacts/screenshots/new-metering-fleet-table.png).

Tom doesn't care about packet inspection. He cares about three things: is the
spend predictable, is the protection real, and is the vendor honest about how it
compares. This post answers all three with measured numbers.

## The spend is predictable — and it shows the loss-makers

The metering engine computes real per-tenant cost against revenue. On the seeded
fleet ([`s7-admin-cost-report.json`](../../artifacts/payloads/s7-admin-cost-report.json)):
**$8,191/mo revenue, ≈$4,039/mo cost, ≈$4,152 margin (~50.7%).**

![Fleet metering](../../artifacts/screenshots/new-metering-fleet-top.png)

But the number Tom should trust is the *spread*, not the blend:

![Per-tenant margin](../../artifacts/screenshots/new-metering-fleet-table.png)

Per-tenant margin runs from **+66.8% (Globex)** down to **−14.3% (Maple
Health)** — Maple is a professional-tier tenant consuming enterprise-scale
resources, deliberately seeded so the report has a *real loss-maker* to surface
rather than an all-green fiction. That's the honest signal a CFO needs: the
platform tells him which tenants to upsell or right-size, and (engineering Post
8) a margin autopilot can act on them.

## The cost scales the right way

The reason the margin holds at 5,000 tenants is the dormant-trial economics
(Post 1). The [capacity model](../../artifacts/capacity-plan-5000/report.md)
shows the two big levers: background work drops **10×** by tiering dormant
tenants, and the AI runs as **one shared model for the whole fleet — ~3,696× less
memory than a per-tenant model.** Cost follows engagement, not tenant count,
which is what makes a trial-heavy fleet profitable.

## The protection is real (and honestly caveated)

Measured on the live stack ([`efficacy-report.json`](../../artifacts/efficacy-report.json)):
100% catch / 0% false-positives across the gating set (firewall, web gateway,
ZTNA, structured DLP, malware, DNS, IPS), with the unstructured ML classifier at
97.4%. And the honest caveat Tom should hear from any vendor: on *wild,* noisy
traffic the malware classifier drops to **90.1% catch with a 9.6% false-positive
rate** — which is why that capability runs monitor-first, not block-first.

## The competitive read (honest)

Every competitor figure lives in
[`competitors.json`](../../../bench/business-report/competitors.json) with a
`source_url` and a `caveat`. The honest summary:

- **SNG is software on a generic x86 VM**; most competitor boxes are ASIC
  appliances. SNG's throughput (5.6 Gbps single-stream floor → 28.6 Gbps
  multi-queue ceiling) is *not* an apples-to-apples comparison to ASIC line-rate,
  and we say so. The directly comparable vendor is cloud-native Zscaler.
- **On breadth** (CASB app catalog, threat-intel feed count), SNG is *closing*
  the gap with Netskope and Palo Alto, not ahead.
- **On the thing that matters to Tom** — running thousands of mostly-dormant SME
  tenants at near-zero marginal cost and near-zero operations — SNG's
  architecture targets exactly the workload the incumbents' per-tenant cost
  structures handle worst.

## Where it falls short

- **Margins are projected, not invoiced** — they drift sub-percent within a
  billing period and assume the seeded usage model; production billing is the
  real source of truth.
- **The competitive table mixes measured (SNG) and cited (competitor) rows.** We
  never fabricate a head-to-head bench; competitor numbers are caveated
  datasheets.
- **Breadth is the standing gap.** The defensible buy case is *economics +
  self-operation for the SME/MSP*, not feature-count parity with a
  best-of-breed point product.
