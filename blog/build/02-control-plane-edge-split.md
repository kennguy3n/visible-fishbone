# Split the plane: a Go control plane and a Rust edge

> **Build series, Post 2 of 10 — language and topology.** Reader: engineer-led,
> with a product framing of the cost tradeoff. The decision: *where does policy
> get decided, where does traffic get enforced, and what language does each
> deserve?*

A SASE platform has two very different jobs, and the first real architecture
decision is to stop pretending they are one. **Deciding** policy — compiling a
tenant's intent into rules, distributing it, metering it, proving compliance — is
a correctness-and-iteration problem. **Enforcing** policy — inspecting packets,
scanning content, brokering sessions at multi-gigabit rates — is a
latency-and-throughput problem. Build them with one toolchain and you compromise
both.

## The build: two planes, two languages

SNG splits cleanly:

- **The control plane is Go** (`cmd/sng-control`, `internal/`). It owns the API
  (`api/openapi.yaml`), the typed policy graph and its compiler
  (`internal/service/policy`), tenant lifecycle, metering, compliance, and the
  ~40 services under `internal/service/`. Go's strengths — fast compiles, a huge
  standard library, painless concurrency, excellent Postgres/NATS clients — are
  exactly what an iteration-heavy control plane needs. It talks to Postgres 16
  (state + isolation, Post 4), NATS JetStream (config distribution), and
  ClickHouse (telemetry).
- **The edge is Rust** (`crates/`: `sng-fw`, `sng-ips`, `sng-swg`, `sng-dns`,
  `sng-ztna`, `sng-dlp`, and the shared `sng-policy-eval`). The data plane needs
  predictable latency, no GC pauses in the packet path, and memory safety while
  doing genuinely dangerous things (parsing hostile input at speed). Rust gives
  all three. The edge consumes the *compiled, signed* bundle the control plane
  emits — it never re-derives policy.

The two planes meet at exactly one contract: **a signed policy bundle.** The
control plane compiles intent → bundle → signs it; the edge verifies the
signature and enforces. Neither side reaches into the other's internals. That
single narrow interface is what lets each plane evolve on its own clock.

## Why the edge is fast without silicon

The throughput story is measured, not asserted. On a generic x86 VM the
multi-queue edge scales from a **single-stream floor of 5.569 Gbps to a
multi-queue ceiling of 28.567 Gbps** across 8 cores — a **5.13× lift**
([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json)) — and a
branch-large profile from 5.063 to 21.564 Gbps (4.26×,
[`multi-queue-branch-large.json`](../artifacts/multi-queue-branch-large.json)).
The lift comes from fanning out across NIC RSS queues and a kernel fast path
(Post 5), not from an ASIC. We publish floor *and* ceiling because quoting only
the ceiling would violate the honesty contract.

## The business call: commodity hardware is the moat

The scenario: **Tom, a CFO,** is comparing a software SASE against a hardware
incumbent. The hardware vendor's throughput is higher per box — but it is a box,
with a refresh cycle, a depreciation schedule, and a per-site capital line. SNG's
pitch to Tom is that *the edge runs on the commodity compute you already buy*, and
scales by adding queues and cores rather than swapping silicon. The Go/Rust split
is what makes that credible: Rust gets you appliance-class enforcement on generic
CPUs, and Go gets you a control plane you can ship features into weekly. The
product consequence is a cost curve that bends with Moore's law and cloud
instance pricing, not with a hardware refresh cycle.

## How the incumbents approached it

- **Fortinet** is the purest hardware bet: custom SPU/NP ASICs deliver
  appliance throughput (40F/60F/100F at 5/10/20 Gbps firewall,
  [`competitors.json`](../../bench/business-report/competitors.json)), but those
  numbers are *not* apples-to-apples with software-on-VM and the unit is a box per
  site. Brilliant at the high end; structurally heavy for a dormant fleet.
- **Palo Alto** likewise leans on appliances (PA-440/450) plus a cloud Prisma
  Access; Panorama is the management plane. Strong enterprise story, hardware cost
  base.
- **Zscaler** is the closest to SNG's *topology* — no customer appliance, a
  cloud-native multi-tenant enforcement layer — but it runs on Zscaler's own
  global infrastructure, not commodity compute you operate. The control-plane
  contract (admin API p99 100–300 ms) is the comparable surface.
- **Netskope and Cato** also run cloud-native data planes on their own backbones;
  the language/runtime is theirs, the topology is "our cloud, not your box."

SNG's distinctive call is *software edge on hardware you already own* — closer to
Zscaler's no-appliance topology but deployable on commodity compute, with Rust
buying appliance-class enforcement without the appliance.

## Build it yourself

1. **Separate decide from enforce.** Make policy compilation a control-plane job
   and enforcement a data-plane job, with one signed artifact between them.
2. **Match the language to the job.** Iteration-heavy control plane → a fast,
   batteries-included language (Go). Latency-critical, hostile-input data plane →
   a memory-safe systems language with no GC in the hot path (Rust).
3. **Keep the interface narrow.** One signed bundle. The edge must never need to
   understand *why* a rule exists, only how to enforce it.

## Where this approach falls short

- **Software is not silicon.** The throughput ceiling is a multi-core software
  curve, not an ASIC line-rate. A buyer who needs guaranteed line-rate at 100G
  should demand a real-NIC bake-off; we publish the floor precisely so that
  conversation is honest.
- **Two languages, two toolchains.** The Go/Rust split costs you build
  complexity, cross-language testing, and a wider hiring surface. It is the right
  cost here, but it is a real one.
- **The narrow interface is a discipline, not a guarantee.** Every time a feature
  tempts you to leak control-plane logic into the edge, the split erodes. It has
  to be defended in review.
