# Pick the bet: SASE for the dormant-trial SME fleet

> **Build series, Post 1 of 10 — the market bet.** Reader: product-led, but the
> bet here constrains every engineering decision in Posts 2–10. The decision:
> *who do you build for, and what does that do to your unit economics?*

Before a single line of Go or Rust, a SASE platform makes one decision that
quietly determines everything else: **who is the tenant?** Get this wrong and no
amount of good engineering saves you, because the cost structure is decided here.

## The build: design for the fleet shape, not the marquee customer

SNG's tenant is a **small or mid-sized business, usually arriving as a trial,
usually managed by an MSP alongside dozens or hundreds of siblings.** The fleet
the seed harness builds (`blog/harness/seed`) is deliberately shaped like that
reality: nine customer tenants across seven countries, eight industries, three
service tiers, and five compliance regimes, under one MSP — plus one deliberate
loss-maker (Maple Health, **−13.9%** margin) so the money story is not an
all-green fiction.

That fleet shape forces a specific cost model. At 5,000 tenants the activity mix
is roughly **400 active / 600 idle / 4,000 dormant**
([`capacity-plan-5000/report.md`](../artifacts/capacity-plan-5000/report.md)). The
load-bearing engineering consequence: *the marginal tenant is dormant*, so the
marginal tenant must cost almost nothing. If onboarding a trial that nobody ends
up using costs you a dedicated database, a per-tenant model in memory, and a full
sweep of background jobs every cycle, you lose money on 80% of your fleet. So the
bet — "trial-heavy SME fleet" — directly produces the architecture:

- **Hard isolation that is cheap per tenant** → Postgres row-level security, not
  a database per tenant (Post 4).
- **Background work that scales with activity, not tenant count** → universal
  dormancy tiering and hibernation (Post 8): **10× fewer** tenant-visits per
  cycle, dormant trials winding down to near-zero.
- **One shared AI model, not one per tenant** → **~3,696× less** memory than
  per-tenant residency (Post 9).
- **Self-operation** → a tiny team cannot babysit 5,000 tenants, so the control
  plane runs itself through guardrailed autopilots (Post 8).

## The business call: the dormant tenant is the product decision

Here is the scenario that makes this concrete. **Mara runs an MSP.** She onboards
fifty SME trials a month; historically maybe eight convert. With a per-tenant cost
model, those forty-two non-converting trials are pure loss — so she rations
trials, slows her funnel, and competes badly. SNG's bet is that *the trial should
cost almost nothing until it is real*, which lets Mara run an unlimited trial
funnel. The dormancy dividend (10×) and hibernation are not engineering
vanity — they are the feature that makes Mara's business model work.

The flip side is honest: this bet means SNG is **not** optimised for the single
giant tenant who wants line-rate ASIC throughput and a dedicated tenant cluster.
We chose the long tail. That is a product decision, and it is the right one
*for this buyer*.

## How the incumbents approached it

The incumbents made the opposite-end bet, visible in their published constraints
([`competitors.json`](../../bench/business-report/competitors.json)):

- **Fortinet** sells hardware tiers — FortiGate 40F/60F/100F at 5/10/20 Gbps
  firewall throughput — with management through FortiManager (policy-push p99
  200–500 ms at 1,000 managed devices). The unit is *an appliance per site*. Great
  economics if every customer buys a box; structurally heavy for a dormant trial
  that should cost nothing.
- **Palo Alto Prisma Access** centres the enterprise: rich policy, Panorama
  management (policy-compile p99 300–800 ms). The buyer is an enterprise security
  team, and the product is priced and operated for one.
- **Zscaler** is the closest architectural cousin — cloud-native, multi-tenant,
  no customer appliance (admin API p99 100–300 ms). But Zscaler's bet is the
  *enterprise* cloud: a global PoP footprint and enterprise sales motion, not a
  near-zero-cost dormant SME trial run by an MSP.
- **Netskope and Cato** are cloud-native SASE built for mid-market-and-up with
  their own global private backbones (Cato especially). Powerful, but the backbone
  is a fixed cost that a dormant-trial fleet cannot amortise the way an
  always-busy enterprise fleet can.

None of them is *wrong* — they serve a busier, richer buyer. SNG's wedge is the
buyer they structurally cannot serve cheaply: the MSP with thousands of mostly-idle
SME tenants.

## Build it yourself

1. **Write down your fleet shape first.** Active/idle/dormant ratios, tenants per
   operator, conversion rate. This is the spec for your cost model.
2. **Find the marginal tenant.** If it is dormant, every per-tenant fixed cost is
   your enemy; design them out before you write features.
3. **Pick the isolation boundary that is cheap per tenant** (Post 4) and the work
   model that scales with activity (Post 8). These two decisions, made here, are
   what let the bet pay off.

## Where this approach falls short

- **The dormant-trial bet leaves the high end on the table.** A single large
  enterprise wanting dedicated infrastructure and line-rate silicon is not SNG's
  buyer, and pretending otherwise would be dishonest.
- **No global PoP footprint.** Zscaler/Netskope/Cato win on worldwide
  low-latency presence. SNG is software you run where you need it, which is
  flexible but not a turnkey global backbone.
- **The 5,000-tenant economics are a model.** They are sized from real
  per-feature numbers (Post 10), but they are not yet a production fleet's
  observed bill. The honest next step is a long-lived staging fleet.
