# Prove the spend and the posture — and the competitive critique (S7)

> **Post 7 of 8.** Persona: **Tom**, CFO / buyer. Outcome: predictable spend,
> consolidation savings, compliance evidence — plus the consolidated,
> evidence-based critique against the top SASE vendors.

## What the buyer actually needs

Tom isn't buying packets per second. He's buying *predictability*: a bill he can
forecast, a consolidation story he can defend, and compliance evidence he can
hand an auditor. SNG's metering engine is built for that.

## Walking it in the console

The metering surface is the new **WS8 cost metering UI**
([PR #130](https://github.com/kennguy3n/visible-fishbone/pull/130)) — a
purpose-built spend dashboard that turns the raw usage meters into a buyer-facing
view. It shows eight meters per tenant, each with current usage, a **projected**
end-of-period total, and a budget utilisation bar, plus a platform-wide **fleet
cost & margin** table that refreshes when a tenant's budgets change. Here is the
per-tenant view for Acme (enterprise) — meter limits and projections differ by
tier:

![Metering — Acme (enterprise), per-meter usage + projected spend](../artifacts/screenshots/new-metering-fleet-top.png)

And here is the **MSP fleet roll-up** across all nine tenants, sorted
worst-margin-first so a loss-making tenant is the first thing the operator sees:

![Metering — 9-tenant fleet cost & margin](../artifacts/screenshots/new-metering-fleet-table.png)

## The real numbers

Eight meters, captured live from `GET /usage`
([`s7-acme-usage.json`](../artifacts/payloads/s7-acme-usage.json)) after a clean
full re-seed. The **projected** column is the engine extrapolating the
partial-period run rate to a steady-state period-end total:

| meter | used | projected (period-end) |
| --- | ---: | ---: |
| llm_tokens_used | 4,661,799 | 11,999,317 |
| llm_calls | 5,050 | 12,999 |
| url_cat_lookups | 78,540 | 119,879 |
| malware_scans | 3,272 | 4,995 |
| clickhouse_rows_written | 116,544,966 | 299,982,896 |
| s3_bytes_archived | 582.7 GB | ~1.50 TB |
| bandwidth_proxied_bytes | 1.94 TB | ~5.00 TB |
| policy_evaluations | 39,269,797 | 59,939,144 |

### Projection is the feature

`ProjectToPeriodEnd` is the inverse of the elapsed fraction: 37% through the
month, a value of 100 projects to ~270. That's what powers "on-track to breach"
visibility *before* the breach — the UI flags `projected_soft_exceeded` /
`projected_hard_exceeded` so Tom sees the overage coming, not after the invoice.

### The one credible anomaly

We seeded realistic data — current period *plus five trailing complete months* of
history per tenant — which means most things look normal, and they do. The
cost-anomaly model surfaces exactly **one** credible anomaly across all tenants,
Initech's URL-category lookups, captured at
[`s7-initech-cost-anomalies.json`](../artifacts/payloads/s7-initech-cost-anomalies.json):

```json
{ "meter": "url_cat_lookups", "baseline_monthly_usd": 72.31,
  "projected_monthly_usd": 224.77, "ratio": 3.1083,
  "baseline_months": 5, "severity": "warning" }
```

A 3.11× run-rate over a 5-month baseline (`ratio` 3.1083) — flagged `warning`, not screamed as
critical. Acme's anomalies file, by contrast, is empty (the control). That
restraint is the point: an anomaly detector that flags everything is noise. This
is the detector firing on real seeded history — it only works *because* the seed
carries trailing-month baselines, which is why the harness writes them.

### The margin story (for the MSP)

This is the section the previous draft most understated: metering is no longer a
**four-tenant** report. The admin cost-report now rolls up the full **nine-tenant
fleet** — **$8,191/mo revenue against ≈$4,056/mo projected cost, ≈50% blended
margin** (`s7-admin-cost-report.json`). Per-tenant gross margins (`margin_pct`),
sorted worst-first the way the console shows them:

| tenant | tier | projected cost | margin |
| --- | --- | ---: | ---: |
| Maple Health | professional | ≈$573 | **≈−14.8%** |
| Initech Financial | professional | ≈$425 | ≈14.8% |
| Umbrella Logistics | starter | ≈$57 | ≈42.4% |
| Acme Retail | enterprise | ≈$1,060 | ≈47.0% |
| Outback Retail | professional | ≈$253 | ≈49.3% |
| Nordic EduCloud | starter | ≈$46 | ≈53.9% |
| Lumière Légal | professional | ≈$223 | ≈55.3% |
| Britannia Robotics | enterprise | ≈$752 | ≈62.4% |
| Globex Health | enterprise | ≈$667 | ≈66.6% |

Two things this surfaces that a four-tenant all-green table couldn't:

- **Maple Health is underwater (≈−14.8%).** A professional-$499 tenant consuming
  enterprise-scale bandwidth + ClickHouse, projected ≈$573/mo against $499
  revenue. That negative margin is the honest **upsell signal** the report is
  built to surface — an MSP sees the loss-making tenant *first*, before renewal,
  not after the year-end true-up.
- **Initech's thin ≈14.8% margin is the url_cat surge** — the anomaly above and
  the margin compression are the same story. Initech still clears its $499 tier,
  but only just.

The four-tenant base cohort (Globex + Acme + Umbrella + Initech) still totals
≈$2,210/mo, reconciling with the earlier #196 figure; the other ≈$1,846/mo is the
five tenants added to round the fleet out to nine. (Margins are *projected*
figures and drift sub-percent within a billing period as the elapsed fraction
grows; the saved payload is the point-in-time source of record.)

## Compliance + audit evidence

The compliance surface carries seeded posture reports
([`s7-acme-compliance-reports.json`](../artifacts/payloads/s7-acme-compliance-reports.json)),
and the audit log (Post 2) is the immutable trail. The global-audit fix from
[PR #116](https://github.com/kennguy3n/visible-fishbone/pull/116) means even
tenant-less platform actions are now recorded — audit completeness was a real gap
we closed.

This cycle adds two pieces of buyer-relevant evidence. **Smart-default policy
templates** ([#157](https://github.com/kennguy3n/visible-fishbone/pull/157)) give
an auditor a defensible *starting posture*: a 14-template catalog (5 of them
compliance regimes — EU GDPR, UK DPA, US baseline, Canada PIPEDA, Australia
Privacy Act) that renders a deny-by-default policy graph per industry/regime, so
"we configured nothing" is never the answer. And the **shadow-IT NoOps engine**
([#159](https://github.com/kennguy3n/visible-fishbone/pull/159) /
[#172](https://github.com/kennguy3n/visible-fishbone/pull/172)) writes every
classify/recommend/enforce decision to the same audit trail and rolls it into a
per-tenant digest — the discovery-to-disposition record an auditor actually wants,
rather than a raw list of unsanctioned apps. Both are walked in the business
series (Posts B4 and B2).

## The cost-efficiency argument (honestly bounded)

From the [edge performance datasheet](../artifacts/edge-performance-datasheet.md),
SNG cloud opex at a representative **$0.0416/vCPU-hour** over 730 h/mo:

| SKU | vCPU | est. $/mo | wire firewall peak | $/Gbps (wire) |
| --- | ---: | ---: | ---: | ---: |
| micro | 2 | $61 | 19.35 Gbps | $3 |
| small | 4 | $121 | 18.98 Gbps | $6 |
| medium | 8 | $243 | 18.90 Gbps | $13 |
| large | 16 | $486 | 18.39 Gbps | $26 |

We now publish a `$/Gbps` figure because the denominator is a **real-wire**
measurement (AF_PACKET, `sng-edge` in-path, on the self-hosted `sng-bench-wire`
runner — Post 1), not the dry-run ceiling. Read it as a *floor*: the wire rig is
a single-stream egress path, so the true price/performance on a multi-queue NIC
is better than these numbers, not worse. Appliance capex/support TCO is
vendor-quote territory and we don't invent it. The defensible cost claim is the
*opex side*: software-only, no appliance refresh cycle, scales with cloud vCPU.

This cycle added two more opex levers that map directly onto meters in the table
above:

- **Self-hosted AI removes the per-token bill.** The `llm_tokens_used` /
  `llm_calls` meters are a real line item against a hosted-LLM API. Baking the
  2-bit **Q2_0 Ternary-Bonsai-8B** ([#155](https://github.com/kennguy3n/visible-fishbone/pull/155))
  moves inference onto tenant hardware, so those meters become a fixed-compute
  cost rather than a metered API spend — the whole point of fitting an 8B model
  into a 2-bit quant is to make that affordable. (The honest caveat from Post 6
  stands: the Q2_0 build needs prism-branch kernels, not stock Ollama.)
- **Dormancy shrinks the cost of idle trials.** Activity-tiered sweeps
  ([#154](https://github.com/kennguy3n/visible-fishbone/pull/154)) process a
  dormant tenant every 100th cycle instead of every cycle, so the long tail of
  quiet trials an MSP carries costs ~1/100th of an active tenant's periodic work
  — without turning the tenant off. (Proven by tests; not yet driving a live
  production sweep — see Post 2.)

---

# The consolidated competitive critique

Comparing SNG to the incumbents requires separating two claims: the *throughput*
comparison (which is informative-but-not-fair) and the *architecture* comparison
(which is the real story).

## The throughput table, with the caveat in bold

All competitor numbers are **published datasheet figures** from
[`competitors.json`](../../bench/business-report/competitors.json), each with a
`source_url`. **Every hardware row is an ASIC-accelerated fixed appliance; SNG is
software-only on a generic x86 VM.** SNG's own numbers are now shown both ways —
the dry-run *ceiling* and the real-wire *floor* (single-stream veth, Post 1). The
table is informative context, **not** a head-to-head result:

| Box (class) | firewall | IPS/threat | source |
| --- | ---: | ---: | --- |
| SNG micro (2-core, dry-run ceiling) | ~79 Gbps | ~74 Gbps | sng-bench |
| SNG micro (2-core, wire floor) | 5.5 Gbps | 5.5 Gbps | sng-bench |
| Fortinet FortiGate 40F (2-core) | 5.0 Gbps | 0.8 Gbps | FortiGate 40F datasheet |
| Palo Alto PA-440 (2-core) | 3.1 Gbps | 0.7 Gbps | PA-400 series datasheet |
| Fortinet FortiGate 60F (4-core) | 10.0 Gbps | 1.4 Gbps | FortiGate 60F datasheet |
| Palo Alto PA-450 (4-core) | 5.2 Gbps | 1.6 Gbps | PA-400 series datasheet |
| Check Point 3600 | 3.4 Gbps | 0.65 Gbps | Check Point 3600 datasheet |

The honest reading: appliance IPS/threat throughput collapses to a fraction of
its firewall throughput once inspection is on — that's the ASIC hitting software
inspection paths. SNG's inspection cost is comparatively flat (Post 1's latency
table, and the wire firewall/IPS columns above sit on top of each other), which
is the genuinely interesting architectural signal — now backed by a real wire
benchmark rather than dry-run alone.

### Why is the wire firewall floor (5.5) *equal* to the IPS floor (5.5)?

This is the obvious question — if IPS adds inspection work, why doesn't the wire
number drop like the appliance rows do? Because **at the single-stream wire
floor, the bottleneck is the wire, not the inspection.** The `sng-bench-wire` rig
drives one AF_PACKET stream over a veth pair, and a single stream is capped by a
per-frame syscall / packets-per-second ceiling long before either the firewall or
the IPS path saturates a core. Both rows hit the *same* ceiling, so they read the
same — it's a property of the single-stream harness, not evidence that IPS is
free.

Two measurements prove the wire (not inspection) is the limit:

- **Frame-size sweep (Post 1):** the same path scales with frame size — 64 B
  → 0.25 Gbps, 1500 B → 5.38 Gbps, 9000 B → 18.96 Gbps. Throughput tracks frames
  *per second*, the signature of a PPS/syscall bound, not an inspection bound.
- **Multi-queue scaling rig** ([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json)):
  lifting the single-stream cap by fanning out across queues takes the *same*
  enforcement path from **5.45 Gbps (1 queue) → 25.98 Gbps (16 queues), a 4.77×
  scale-up** (1q→2q at 96% efficiency, 2q→4q at 91%, then flattening as the VM's
  cores saturate). The wire floor moves 4.77× just by adding queues — so 5.5 was
  never an inspection limit.

The true inspection cost only shows up where the wire *isn't* the bottleneck — in
the dry-run ceiling (firewall ~79 → IPS ~74 Gbps, a single-pass ~3–4% hit) and in
the multi-queue ceiling. Because SNG is **single-pass** (one decode, all
verdicts), inspection costs a few percent rather than collapsing throughput the
way a bolt-on inspection stage does on a fixed appliance.

## The one apples-to-apples comparison

The only directly-comparable competitor row is cloud-native: **Zscaler's admin
API**, p99 **100–300 ms** for tenant CRUD (caveated "directly comparable" in our
dataset). SNG's Go control plane is the right thing to bench against that, and
that comparison *is* fair because both are software services, not silicon.

## Per-vendor honest critique

- **Zscaler** — the cloud-native incumbent; massive PoP footprint and identity
  integration depth SNG doesn't match. SNG's counter is architectural unification
  (one policy graph) and on-device DLP. *We lose on scale and ecosystem; we win
  on policy-model coherence and auditability.*
- **Palo Alto Prisma Access** — deepest threat-prevention research and signature
  pipeline in the industry. SNG's IPS is real Suricata, which is credible but not
  a match for PAN's threat research org. *We lose on threat-intel depth.*
- **Cloudflare** — unmatched edge network and DDoS scale. SNG isn't a global
  network; it's software you run. *Different category for raw network scale.*
- **Netskope** — the DLP/CASB depth leader. SNG's on-device ML DLP is a real
  latency/privacy differentiator, but Netskope's detector and SaaS-API breadth is
  far ahead. *We win on on-device inference; we lose on detector catalog.*
- **Cato Networks** — the closest philosophical sibling (single-pass,
  cloud-native, converged). The honest comparison is converged-architecture vs.
  converged-architecture; Cato has the operational maturity and PoP footprint SNG
  lacks. *Closest competitor; they're further along the same road.*
- **Fortinet** — price/performance king via custom ASIC. SNG can't beat silicon
  on $/Gbps for a fixed appliance. *We lose on appliance price/performance; we
  win on not being an appliance (no refresh cycle, cloud-elastic).*

## Where SNG genuinely differentiates

1. **One typed policy graph** drives every enforcement domain — no five-console
   drift (Post 1).
2. **Auditable AI**: verdicts cite compiled rules, carry `ai_generated: false`
   when deterministic, and degrade safely (Post 6).
3. **On-device ML DLP** keeps content on the endpoint (Post 5).
4. **In-repo, reproducible efficacy harness** that drives the real code and ships
   its corpora (Post 3).
5. **NoOps shadow-IT for the under-staffed team** — discovery becomes a
   recommend-first, fully-audited disposition trail rather than a dashboard
   nobody triages (Post 5; #159/#172).
6. **Self-hosted AI with no per-token bill** — a 2-bit 8B model baked to run on
   tenant hardware, so the AI features aren't a metered cloud dependency (#155).

## Where SNG genuinely falls short

1. **Wire throughput is a single-stream floor** — measured over a veth pair, not
   a multi-queue physical NIC, so it understates real line-rate. The multi-queue
   rig (5.45 → 25.98 Gbps, 4.77×) shows the headroom above the floor, but it is
   still a software-on-x86 number, not an ASIC line-rate.
2. **Identity/IAM depth** is scaffolding, not a finished IGA suite (Posts 2, 4).
3. **No global PoP network** — it's software you operate, not a network you rent.
4. **Threat-intel and DLP-detector breadth** trail the specialist incumbents.
5. **Curated efficacy corpora**, not wild-traffic catch-rates.
6. **This cycle's new capabilities are wired but default-OFF.** ClamAV,
   safe-browsing, the NoOps engine, AI-app DLP and the review queue are now wired
   into the running control plane behind per-tenant default-OFF gates (the staged
   off→monitor→enforce rollout framework, #202) — a step past the previous draft's
   "staged, not wired." The honest framing is now *wired vs. default-ON*: an
   out-of-the-box install isn't enforcing them until an operator opts in, which
   is the production-correct posture, not the same as "on for every tenant
   today."

Next, the closing post: methodology, reproducibility, and how to run all of this
yourself.
