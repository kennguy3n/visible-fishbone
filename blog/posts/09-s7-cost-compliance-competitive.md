# Prove the spend and the posture — and an honest competitive read

> **Post 9 of 11 — cost, compliance, competition (Scenario S7).** Persona: Tom,
> CFO/buyer. Evidence: [`s7-admin-cost-report.json`](../artifacts/payloads/s7-admin-cost-report.json),
> [`s7-initech-cost-anomalies.json`](../artifacts/payloads/s7-initech-cost-anomalies.json),
> [`efficacy-report.json`](../artifacts/efficacy-report.json),
> [`multiqueue-micro.json`](../artifacts/multiqueue-micro.json),
> [`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md),
> [`bench/business-report/competitors.json`](../../bench/business-report/competitors.json),
> [`complianceauto-acme-posture.json`](../artifacts/payloads/complianceauto-acme-posture.json),
> [`complianceauto-acme-evidence-pack-soc2.csv`](../artifacts/payloads/complianceauto-acme-evidence-pack-soc2.csv);
> screenshots [`new-metering-fleet-top.png`](../artifacts/screenshots/new-metering-fleet-top.png),
> [`new-metering-fleet-table.png`](../artifacts/screenshots/new-metering-fleet-table.png).

A CFO buying security consolidation wants three things proven: the spend is
predictable, the posture is real, and the competitive claim is honest. This post
does all three against the live stack, and ends with the consolidated critique.

## The spend, fleet-wide

The metering engine computes per-tenant cost from real usage and compares it to
revenue. On the seeded nine-tenant fleet
([`s7-admin-cost-report.json`](../artifacts/payloads/s7-admin-cost-report.json)):

- **Revenue $8,191/mo · projected cost ≈$4,039/mo · margin ≈$4,152 (~50.7%).**
- Per-tenant margin spans **+66.8% (Globex)** down to **−14.3% (Maple Health)** —
  Maple is the deliberate underwater tenant (Post 8), Initech the thin-margin one
  at +15.2%.

![Fleet metering](../artifacts/screenshots/new-metering-fleet-top.png)

These are *projected* (elapsed-fraction-extrapolated) figures, so they drift
sub-percent within a billing period; the saved payload is the point-in-time
source of record and the prose uses approximate figures deliberately. The point
isn't a vanity 50% — it's that the report **surfaces a genuine loss-maker
instead of an all-green table**, which is what makes it useful to a CFO.

## The anomaly detector earns its keep

Cost surprises are the CFO's nightmare. The detector flags Initech's
`url_cat_lookups` projecting **$224.77 against a $72.31 five-month baseline =
ratio 3.11, severity `warning`**
([`s7-initech-cost-anomalies.json`](../artifacts/payloads/s7-initech-cost-anomalies.json))
— a modelled mid-period traffic surge it catches while Initech still clears its
$499 tier. Acme's anomaly set is empty (the control). This is the detector firing
on real seeded history, not a hand-written example.

## The posture, proven

Compliance isn't a checkbox here; it's the jurisdiction-correct baseline the
template engine renders from each tenant's `(industry, country)` — five regimes
across the fleet (us-baseline, uk-dpa, eu-gdpr, ca-pipeda, au-privacy). And the
*posture* is the efficacy matrix (Post 4): 100% catch / 0% FP on the gating set,
with the wild-malware WARN published rather than hidden. The honest one-line
posture statement: **strong on structured detection and policy enforcement,
monitor-first on wild malware.**

### Continuous compliance evidence, not a once-a-year scramble

Where most SME-grade tools stop at "here are some policy templates," SNG
**continuously collects audit evidence** and scores the tenant against named
controls. The captured posture for Acme
([`complianceauto-acme-posture.json`](../artifacts/payloads/complianceauto-acme-posture.json))
tracks **16 controls — 10 SOC 2 and 6 ISO 27001 — fed by 3 automated
collectors**, and it is honest about a half-built dev stack rather than printing
a green wall:

- **SOC 2: 6 of 10 controls passing (60%).** The failing four are named, not
  hidden — data retention, federated authentication (SSO), encryption at rest,
  and encryption in transit.
- **ISO 27001: 4 of 6 controls passing (66%).** Failing: identity management and
  use of cryptography.

The evidence is exportable as an auditor-ready pack
([`complianceauto-acme-evidence-pack-soc2.csv`](../artifacts/payloads/complianceauto-acme-evidence-pack-soc2.csv)),
so the artifact a buyer hands their auditor is generated from live system state,
not assembled by hand the week before the audit. The scores above are exactly
what this dev stack earns; a production deployment with SSO and disk encryption
turned on would clear the controls it currently fails.

## The competitive read (honest)

Every competitor number lives in
[`competitors.json`](../../bench/business-report/competitors.json) with a
`source_url` and a `caveat`. The single most important caveat, repeated from the
capacity plan:

> Fortinet (FortiManager) and Palo Alto (Panorama) numbers are management-plane /
> ASIC-appliance figures, **NOT apples-to-apples** with a multi-tenant SaaS
> control plane. Zscaler (cloud-native) is the most directly comparable. Treat
> the cross-vendor column as directional only.

| Dimension | SNG (measured) | Honest competitive read |
| --- | --- | --- |
| Edge throughput | 5.6 Gbps single-stream floor → 28.6 Gbps multi-queue ceiling (software, x86 VM) | Appliance vendors quote higher *ASIC* line-rate; not comparable. Zscaler is cloud-native like SNG. |
| Detection | 100% curated / 0% FP; 90.1% wild malware (WARN) | Mature vendors have larger signature/intel sets; SNG's honesty (publishing wild FPR) is the differentiator, not raw breadth. |
| Cost at scale | 10× dormancy dividend + hibernation + 3,696× AI-memory reduction | This is SNG's actual edge — *dormant-trial economics* nobody else monetises well. |
| Self-operation | 3 guardrailed autopilots (promote/capacity/margin) | Competitors have rich ops tooling; SNG's bet is automating the *decisions*, not just the dashboards. |
| Breadth | broadened IdP/IGA, threat-intel (JA3/Suricata/retro-hunt), CASB SaaS-API + DLP catalog | Still behind Netskope (CASB) / Palo Alto (intel) on sheer catalog size; closing, not closed. |

The competitive thesis is narrow and defensible: SNG is **not** trying to
out-ASIC Fortinet or out-catalog Netskope. It's trying to be the platform that
runs **5,000 SME tenants — most of them dormant trials — at near-zero marginal
cost and near-zero operations**, which is exactly the workload the incumbents'
per-tenant cost structures handle worst.

## Where it falls short

- **Margins are projected, not invoiced.** They drift within a period and assume
  the seeded usage model; a real billing reconciliation is the production source
  of truth, not this projection.
- **The competitive table mixes measured and cited rows.** SNG's numbers are
  measured on this VM; competitor numbers are published datasheets with caveats.
  We never present a fabricated head-to-head bench.
- **Breadth is the standing gap.** On raw CASB app coverage and threat-intel feed
  count, SNG is closing the distance, not ahead. The win is economics and
  self-operation, and we don't pretend otherwise.
- **Compliance scoring reflects the deployment, not a certification.** A passing
  control means the platform collected evidence that the control holds on this
  stack; it is not a substitute for an audited SOC 2 Type II or ISO 27001
  certificate, and we don't claim it is.
