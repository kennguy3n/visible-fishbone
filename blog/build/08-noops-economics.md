# Engineer the economics: NoOps for 5,000 mostly-dormant tenants

> **Build series, Post 8 of 10 — unit cost.** Reader: both, because this is where
> architecture becomes a P&L. The decision: *how do you make the marginal dormant
> tenant cost almost nothing, and how do you operate 5,000 of them without an
> operations team?*

This is the post the whole platform was built to earn. The bet (Post 1) is a
trial-heavy SME fleet where most tenants are dormant. That bet only pays off if
two things are true: the dormant tenant is nearly free, and nobody has to babysit
the fleet. Both are engineering problems with a P&L answer.

## The build: four mechanisms that bend the cost curve

**1. Universal dormancy tiering.** Every periodic per-tenant job
(`internal/service/capacity`, `internal/capacityplan`) goes through one shared
sweep planner that visits active tenants every cycle, idle tenants ~10× less
often, and dormant tenants ~100× less. The modelled result at 5,000 tenants:
**10× fewer tenant-visits per cycle**
([`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md), mix
400 active / 600 idle / 4,000 dormant). Background work scales with *activity*,
not tenant count.

**2. Hibernation / scale-to-zero.** A genuinely dormant trial winds down to
near-zero resident cost and wakes on activity. The dormant tenant stops being a
line item until it is real.

**3. A shared AI inference pool.** One pooled model serves the whole fleet
instead of one model per tenant: **~3,696× less memory** (4.6 GB shared vs ~17,000
GB per-tenant resident) in the capacity model (Post 9 covers the safety side).

**4. Active/active work distribution.** Periodic work is sharded across replicas
with lease-fenced ownership (`internal/service/workshard`): **1,024 shards**, a
lease TTL of 20 s with a 7 s safety margin so a previous owner stops processing
(local validity lapses at cycle-start + 13 s) before a successor can acquire the
expired lease at + 20 s. That fencing window is what lets work run on *every*
replica instead of piling onto one leader — the single-leader bottleneck was the
original 5,000-tenant ceiling.

## Operating it without people: guardrailed autopilots

A tiny team cannot tune 5,000 tenants, so the control plane operates itself
through three autopilots (`internal/service/rollout`, `capacity`, `metering`),
each **off by default and guardrailed**:

- **Auto-promotion** walks a capability up an `off → monitor → enforce` ladder,
  only promoting after a monitoring period proves it would not cause false
  blocks.
- **Capacity autopilot** turns live fleet load into sizing recommendations
  (raise ClickHouse batch to 13,250, AI pool concurrency to 7, Postgres pool/replica
  to 5).
- **Margin autopilot** surfaces underwater tenants — like the deliberately
  loss-making Maple Health (−13.9%) — as an upsell signal rather than a silent
  loss.

The live gauges are real: `sng_capacity_fleet_tenants 10` (the nine customer
tenants plus the platform tenant) in
[`noops-metrics-snapshot.txt`](../artifacts/noops-metrics-snapshot.txt).

## The business call: the cost model *is* the product

The scenario: **Mara, an MSP owner,** and **Tom, her CFO,** look at the same
fleet. Mara cares that she can run an unlimited trial funnel; Tom cares that the
bill is predictable and that the loss-makers are visible. The four mechanisms give
Mara near-free trials; the autopilots give Tom a fleet that sizes and polices
itself, with the one underwater tenant flagged for an upsell conversation rather
than absorbed as a mystery cost. NoOps is not a feature bolted on top — it is the
business model expressed as code.

## How the incumbents approached it

- **Fortinet / Palo Alto** price and operate per appliance / per enterprise; the
  unit economics assume a paying box or a paying enterprise, not a dormant trial
  that should cost nothing. There is no "dormant tenant is free" primitive because
  there is no dormant tenant in that model.
- **Zscaler** is multi-tenant cloud and amortises beautifully across *busy*
  enterprise tenants; its economics are tuned for high utilisation, not a
  long dormant tail.
- **Netskope / Cato** run private global backbones — a large fixed cost that
  busy enterprise fleets amortise well, but that a mostly-idle SME fleet cannot.

Every incumbent's economics are excellent for a *busy* fleet. SNG's distinctive
call is engineering specifically for the *idle* fleet — dormancy tiering,
hibernation, a shared model, active/active distribution — because the dormant
trial is the tenant the incumbents structurally cannot serve cheaply.

## Build it yourself

1. **Put every periodic job behind one activity-aware sweep planner.** Do not let
   each feature schedule its own per-tenant work; tier them all together.
2. **Make dormant mean near-zero.** Hibernate idle tenants to a parked state and
   wake on activity; the dormant tenant must leave the cost sheet.
3. **Share the expensive resources** — one AI model for the fleet, not one per
   tenant — and size them from live load, not guesswork.
4. **Distribute work with lease fencing,** so it runs across replicas without two
   owners ever processing the same shard.
5. **Automate operations with guardrails, off by default.** An autopilot that
   promotes only after a clean monitoring window is safe; one that acts
   immediately is a liability.

## Where this approach falls short

- **The 5,000-tenant numbers are a model.** They are sized from real per-feature
  measurements, but hibernation and the autopilots have not fired on a long-lived
  production fleet — on the all-active seeded fleet they are wired and exporting
  metrics, not yet exercised at scale. The honest next step is a staging fleet
  that publishes real wake-latency and promotion/throttle events.
- **Lease fencing assumes bounded clock skew.** The 7 s safety margin only holds
  if replica clocks agree to within it; a cross-datacenter deployment may need a
  larger margin.
- **Autopilots off by default is a real adoption cost.** The safe default means a
  buyer has to opt in to the very automation that makes the economics sing, so the
  out-of-the-box experience understates the platform.
