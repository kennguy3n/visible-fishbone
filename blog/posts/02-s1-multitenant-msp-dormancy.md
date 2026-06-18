# Stand up a tenant before the call ends — then run 5,000 of them cheaply

> **Post 2 of 11 — operations at scale (Scenario S1).** Persona: Maya,
> MSP platform lead. Evidence: [`s1-tenants.json`](../artifacts/payloads/s1-tenants.json),
> [`s1-msps.json`](../artifacts/payloads/s1-msps.json),
> [`s1-acme-audit-log.json`](../artifacts/payloads/s1-acme-audit-log.json),
> [`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md),
> [`multiqueue-micro.json`](../artifacts/multiqueue-micro.json),
> [`multi-queue-branch-large.json`](../artifacts/multi-queue-branch-large.json);
> screenshots [`refresh-dashboard-fleet.png`](../artifacts/screenshots/refresh-dashboard-fleet.png),
> [`s1-tenants.png`](../artifacts/screenshots/s1-tenants.png),
> [`s1-audit-log.png`](../artifacts/screenshots/s1-audit-log.png),
> [`new-cross-tenant-rollout.png`](../artifacts/screenshots/new-cross-tenant-rollout.png).

An MSP's economics are simple: revenue scales with tenants, but if *cost* scales
with tenants too, the model breaks the moment a sales team starts handing out
free trials. SNG's bet is that the marginal cost of a dormant tenant should round
to zero. This post is the operations story — onboarding, isolation, audit — and
the cost lever that makes 5,000 tenants (most of them idle trials) affordable.

## Onboarding and isolation

One MSP manages the nine-tenant fleet ([`s1-msps.json`](../artifacts/payloads/s1-msps.json)),
and each tenant is hard-isolated by Postgres row-level security: every query
carries a tenant scope, and the RLS policy makes cross-tenant reads structurally
impossible, not merely filtered in application code. The tenants list
([`s1-tenants.json`](../artifacts/payloads/s1-tenants.json)) is the same data the
fleet dashboard renders.

![The fleet dashboard — the seeded fleet (nine customer tenants plus the platform tenant) under one MSP](../artifacts/screenshots/refresh-dashboard-fleet.png)

Standing up a tenant is one API call (or one wizard, Post 5's guided onboarding)
that seeds a jurisdiction-correct baseline graph. Every change is an audit event
([`s1-acme-audit-log.json`](../artifacts/payloads/s1-acme-audit-log.json)) with
actor, before/after, and the compiled result — so blast radius is auditable and
scoped to one tenant.

![Acme's audit trail](../artifacts/screenshots/s1-audit-log.png)

For the MSP that wants the same baseline on many tenants at once, the
cross-tenant roll-out surface previews a per-tenant diff before applying:

![Cross-tenant roll-out](../artifacts/screenshots/new-cross-tenant-rollout.png)

## The cost lever: universal dormancy tiering

Here is the problem with 5,000 tenants. The control plane runs *periodic
per-tenant jobs* — IdP directory sync, CASB shadow-IT reconcile, compliance
evidence scheduling, threat-intel recompile, metering roll-ups. Naïvely, each job
visits every tenant every cycle: 5,000 tenants × N jobs of pointless work for the
4,000 that are dormant trials nobody has logged into in weeks.

SNG makes the `SweepPlanner` the **shared middleware every periodic job tiers
through**. It reads a hardened `last_active_at` activity signal and assigns each
tenant a cadence:

- **active** tenants visited every cycle (1×),
- **idle** tenants every 10th cycle (10× fewer visits),
- **dormant** tenants every 100th cycle (100× fewer visits).

The [capacity plan at 5,000 tenants](../artifacts/capacity-plan-5000/report.md)
models the realistic mix — **400 active / 600 idle / 4,000 dormant** — and the
dividend is measured, not hand-waved:

> per job: **5,000 tenants/cycle (untiered) → 500.0 tenants/cycle (tiered) =
> 10.0× fewer.** Tiered breakdown/cycle: 400 active + 60 idle + 40 dormant. Tail
> dividend: idle **10×**, dormant **100×** fewer visits/cycle. Aggregate across
> the tiered jobs: **15,000 → 1,500 tenants/cycle.**

That is a 10× reduction in the dominant per-tenant background cost, achieved by
*not doing work for tenants who aren't using the product* — and it applies to
every job that opts into the planner, not one special-cased consumer. Post 3
takes this further: dormant tenants don't just get visited less, they
*hibernate*.

## Spreading the work that does run: the active/active distributor

Tiering decides *how often* a tenant is visited; something still has to decide
*which replica* does the visiting. A naïve design elects one leader and runs
every tenant's periodic work on it serially — which is exactly the bottleneck
that caps a fleet at the size one box can sweep. SNG instead spreads tenants
across replicas with a lease-fenced **active/active work distributor**
(`internal/service/workshard`): the tenant keyspace is hashed into **1,024
shards**, and each replica leases a disjoint subset. Leases use a 20-second TTL
with a 7-second safety margin, so a replica stops processing a shard
(at cycle-start + 13 s) well before any successor can acquire the expired lease
(at + 20 s) — no two replicas ever own the same shard at once, and adding a
replica simply re-balances shards rather than reshuffling a single leader's
queue. Onboarding the 5,000th tenant adds shards to the pool; it doesn't pile
onto one machine.

## The edge keeps up too

Background cost is one half; data-path throughput is the other. The firewall fast
path was historically quoted as a conservative **single-stream floor** (~5.5
Gbps) because that's the honest number for one stream through one core. A
multi-queue rig fans the XDP fast path across NIC RSS queues and reports
the floor *and* the ceiling on the same run:

| Profile | Single-stream floor | Multi-queue ceiling | Lift |
| --- | --- | --- | --- |
| micro ([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json)) | 5.718 Gbps (1q) | 27.264 Gbps (16q) | 4.77× |
| branch-large ([`multi-queue-branch-large.json`](../artifacts/multi-queue-branch-large.json)) | 4.461 Gbps (1q) | 20.588 Gbps (32q) | 4.61× |

**Read this honestly** (the artifact says so itself): this is the in-process
forwarding fast path fanned across 8 worker threads on a generic x86 VM — a
*software* multi-queue model, not a multi-queue physical NIC and not an ASIC. The
single-stream row is the same conservative floor we always quote; the wide rows
show how the per-queue path scales when the box is allowed to use all its cores.
Treat the ceiling as *closer* to a vendor's multi-queue line-rate figure, still
not apples-to-apples. The honest takeaway: the single-stream floor was never a
CPU-inspection bound, it was a per-frame syscall ceiling, and exposing the cores
lifts it 4–5×.

## Where it falls short

- **The activity mix is a model input, not a live fleet measurement.** The 10×
  dividend assumes the 400/600/4,000 split; a fleet that is mostly active sees a
  smaller dividend (correctly — there's less idle work to skip). The point is the
  *mechanism* scales the cost with engagement, not tenant count.
- **Tiering trades freshness for cost.** A dormant tenant's IdP sync or
  shadow-IT inventory can be up to 100 cycles stale. That's the right trade for a
  trial nobody is using, and the wake path (Post 3) forces a fresh sweep the
  moment someone logs in — but it is a trade, and we say so.
- **Multi-queue is measured in software.** The real-NIC, multi-RSS-queue,
  CAP_NET_RAW wire number on representative hardware is the figure a buyer should
  demand in a bake-off; we publish the methodology and the software curve, not a
  hardware line-rate claim.
