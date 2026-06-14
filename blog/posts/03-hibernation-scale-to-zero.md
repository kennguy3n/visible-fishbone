# Hibernation: a dormant trial that costs almost nothing, and wakes in seconds

> **Post 3 of 11 — scale-to-zero (WS-3 + WS-4).** Persona: Maya, MSP platform
> lead; Tom, CFO. Evidence: [`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md),
> [`noops-metrics-snapshot.txt`](../artifacts/noops-metrics-snapshot.txt); migration
> `068_tenant_hibernation`, PR [#222](https://github.com/kennguy3n/visible-fishbone/pull/222)
> (hibernation), PR [#220](https://github.com/kennguy3n/visible-fishbone/pull/220)
> (tier-aware sampling).

Post 2 made dormant tenants *cheaper* by visiting them less. This post makes them
nearly *free* by turning them off — and, just as important, turning them back on
the instant someone shows up. This is the capability that lets a sales team hand
out 4,000 free trials without the platform's cost following them.

## The lifecycle

A tenant moves through activity tiers driven by WS-2's `last_active_at` signal:
**active → idle → dormant → hibernated**. Hibernation (WS-3, migration
`068_tenant_hibernation`) is the terminal cost state, and it does three things to
a tenant that's gone quiet:

1. **Pauses telemetry ingest.** A hibernated tenant writes near-zero rows. The
   tier-aware sampler (WS-4) already throttles by tier — active tenants get full
   fidelity, idle reduced, dormant *security-events-only* — and hibernation takes
   it to the floor.
2. **Applies aggressive ClickHouse TTL.** Hot telemetry for a hibernated tenant
   ages out fast; the storage footprint collapses toward its long-term archive,
   not its live working set.
3. **Condenses NATS subscriptions.** The config-distribution fan-out for a
   tenant nobody is configuring is collapsed, shrinking subject cardinality —
   which, at 5,000 tenants, is a real number: the [capacity
   plan](../artifacts/capacity-plan-5000/report.md) models **35,000 distinct
   subjects across 16 partitions**, and hibernated tenants drop out of that
   working set.

The hibernation controller is a leader-only singleton job, so exactly one
control-plane replica drives the state machine regardless of how many are
running. Its gauges are live on the seeded stack
([`noops-metrics-snapshot.txt`](../artifacts/noops-metrics-snapshot.txt)):

```
sng_hibernation_hibernated_tenants 0
sng_hibernation_hibernate_total 0
sng_hibernation_wake_total 0
sng_hibernation_wake_latency_seconds_count 0
```

Those are zero **on purpose** — the seeded nine-tenant fleet is deliberately all
*active* (every tenant carries current data so the rest of the series has
something to show). The gauges being registered and exported is the honest
evidence that the controller is wired and running; the dividend is what the
capacity model quantifies at fleet scale.

## Wake-on-activity: the part that makes it safe

Scale-to-zero is only acceptable if waking up is invisible to the user. The wake
path triggers on the first real signal — a login, an agent check-in, an enrolled
device phoning home — and the contract is a **sub-5-second wake SLA**:
re-subscribe NATS, restore the tenant's compiled bundle to the edge, resume
ingest, and clear the hibernation state. `sng_hibernation_wake_latency_seconds`
is the histogram that proves it in production; on a fleet where nothing has
hibernated yet, it has no observations, and we won't fake one.

The design choice that makes this work: **hibernation never touches the source of
truth.** The tenant's policy graph, identities, and config live in Postgres the
whole time. Hibernation pauses the *derived, running* state (telemetry ingest,
hot storage, live subscriptions), all of which is reconstructable from the
durable record. Waking is therefore a *restore*, not a *recreate*, which is why
it can hit a seconds-scale SLA instead of a cold-start re-provision.

## Why this is the SME/MSP wedge

Every cloud-native SASE vendor can run a busy tenant. The thing nobody monetises
well is the *dormant* one. An MSP's funnel is mostly trials that never convert;
a cloud vendor's per-tenant baseline cost (a running pipeline, a hot index, a
subscription) is charged whether or not the tenant does anything. SNG inverts
that: an idle trial's cost decays with its activity (Post 2), and a truly dormant
one hibernates to near-zero until it wakes. That is the structural reason SNG can
say "leave the trial running, it costs us nothing" — and mean it.

## Where it falls short

- **No production hibernation data yet in this evidence set.** The mechanism is
  merged, wired, and exporting metrics, but the seeded fleet is all-active by
  design, so the hibernated-tenant count and wake-latency histogram are empty
  here. The fleet-scale dividend is *modelled* (capacity plan), not *observed* on
  this VM. A future post on a long-lived staging fleet should publish the real
  wake-latency distribution.
- **Wake adds first-request latency for the unlucky packet.** The first signal
  after hibernation pays the restore cost. The <5s SLA covers the tenant becoming
  fully live; an individual user's very first request may see a brief delay while
  the bundle restores. For a trial that's been dormant for weeks, that's an
  acceptable trade — but it is a trade.
- **Aggressive TTL means a hibernated tenant's hot telemetry is gone.** Waking
  restores live ingest, not the aged-out hot rows; long-term forensic data lives
  in the archive tier, not the hot path. An operator who needs deep history on a
  just-woken tenant queries the archive, which is slower.
