# How to build a SASE platform like this — and how the decisions were made

> **Build series, Post 0 of 10 — the intro.** Reader: an engineer *and* a
> product leader who want to rebuild a system like ShieldNet Gateway (SNG) from
> first principles. Companion to the [engineering series](../posts/README.md)
> (what it does) and the [business series](../posts/business/README.md) (why a
> buyer cares). This series answers *how you would build it, and why each
> load-bearing decision went the way it did.*

Most architecture write-ups show you the finished building and call it a
blueprint. They skip the part that actually matters: the *decisions* — the forks
where a different choice would have produced a different (often worse) product,
and the business reasoning that picked one fork over the other. This series is
those forks.

## The thesis you are building toward

SNG is a multi-tenant SASE platform with one organising bet: **run 5,000 SME
tenants — most of them dormant trials — without an operations team, at near-zero
marginal cost per dormant tenant.** Everything downstream is in service of that
bet. If you were building a SASE platform for ten Fortune-100 enterprises, almost
every decision in this series would flip. That is the point: *the decision is
downstream of who you serve.*

So we open the series (Post 1) with the market bet, because it constrains every
technical choice that follows:

- A typed, compiled policy graph (Post 3) instead of a pile of rule tables —
  because one tiny team has to safely manage thousands of tenants' policies.
- Postgres row-level security as the isolation boundary (Post 4) instead of
  per-tenant databases — because 5,000 cheap tenants cannot each carry the cost
  of a dedicated datastore.
- A software edge composed from Rust crates with a kernel fast path (Posts 2, 5)
  instead of custom silicon — because the economics only work on commodity x86. The
  edge now also carries add-on SWG verdict stages for **inline DLP**, **AI governance**,
  and **RBI**, plus **clientless ZTNA** and a default-off **DEM** subsystem, each as a
  separate crate so the core stays composable.
- A signed, versioned App-ID catalog (Post 6) instead of a hard-coded protocol
  set — because you cannot ship a new product build every time an app appears.
- Detection efficacy as a measured discipline with published false-positive
  budgets (Post 7) — because a tiny team cannot survive a noisy product.
- NoOps economics — dormancy tiering, hibernation, a shared AI pool, active/active
  work distribution (Post 8) — because the marginal dormant tenant has to cost
  almost nothing.
- AI that verifies its own suggestions before a human sees them (Post 9) —
  because automation without a safety net does not scale to a small team.
- An evidence harness that makes every claim reproducible (Post 10) — because the
  honesty contract is only credible if you can re-run it.

## How to read each post

Each post is built in four moves, and you can read any one move on its own:

1. **The build.** The technical design, anchored to real paths in this repo. If a
   post says "compile the graph in `internal/service/policy`", that package
   exists; go read it.
2. **The business call.** The same decision told as a product scenario — the
   tradeoff, the buyer it serves, the cost or revenue it moves. This is the part a
   product leader can take into a roadmap discussion.
3. **How the incumbents approached it.** Zscaler, Palo Alto Prisma Access,
   Fortinet, Netskope, and Cato all solved these problems; they made different
   calls because they serve different buyers. We contrast the *approach*, using
   their published constraints (caveated — see the
   [README honesty contract](README.md#the-honesty-contract)).
4. **Where this approach falls short.** Every decision has a cost. We name it.

## The evidence is the same evidence

This is not a greenfield thought experiment. Every number in this series is the
same measured number the engineering series publishes, from the same harness on
the same VM: the efficacy matrix
([`efficacy-report.json`](../artifacts/efficacy-report.json), 16 functions, suite
verdict PASS), the throughput floor-and-ceiling
([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json), 5.718 → 27.264
Gbps), the 5,000-tenant capacity model
([`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md)), and
the verbatim API payloads in [`../artifacts/payloads/`](../artifacts/payloads/).
When this series says a decision "works," it points at the artifact that proves
it.

## Where this series falls short

- **It is one design, not the design.** SNG made a coherent set of choices for a
  specific buyer. A different buyer (a single large enterprise, a consumer ISP, a
  government tenant) would justify different choices. We argue *why* SNG chose as
  it did, not that it is universally correct.
- **It is built on one VM.** The architecture is real and the per-feature numbers
  are measured, but the 5,000-tenant economics are a sized model, not a
  production fleet. Post 8 and Post 10 are explicit about which numbers are
  measured and which are modelled.
- **The incumbent contrasts are from the outside.** We reason about Zscaler,
  Palo Alto, Fortinet, Netskope, and Cato from their public material, not their
  source. The contrasts are about *published approach and constraint*, not a
  claim to know their internals.
