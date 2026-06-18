# Compose the edge from crates, with a kernel fast path

> **Build series, Post 5 of 10 — the enforcement architecture.** Reader:
> engineer-led, with a product framing of the throughput-vs-cost tradeoff. The
> decision: *how do you build a software data plane that is fast enough to matter
> without custom hardware?*

The edge has to do contradictory things: parse hostile input, scan content,
broker zero-trust sessions, and make verdicts at multi-gigabit rates — all
without a GC pause in the packet path and without a memory-safety bug becoming a
remote exploit. The decision is *how to structure that work* so it is fast,
safe, and composable.

## The build: one crate per enforcement job, plus an in-kernel fast path

SNG's data plane is a set of focused Rust crates (`crates/`), each owning one
enforcement job, all consuming the same compiled policy bundle (Post 3):

- `sng-fw` — stateful firewall.
- `sng-ips` — Suricata-driven intrusion prevention.
- `sng-swg` — secure web gateway: yara-x malware scanning, ClamAV INSTREAM,
  safe-browsing / category filtering.
- `sng-dns` — threat-intel sinkhole + DNS-tunnelling detection.
- `sng-ztna` — zero-trust session brokering.
- `sng-dlp` — on-device ML classifier + coach-first AI-app DLP (Posts 7, 9).
- `sng-appid` — the signed application-identification catalog (Post 6).
- `sng-policy-eval` — the shared evaluator every crate calls, so a verdict means
  the same thing everywhere.

Beneath the firewall sits an **eBPF/XDP fast path** (`crates/sng-ebpf`): a
tail-call-split in-kernel pipeline with an LRU verdict cache that serves repeat
flows before they ever reach userspace, **fails open to nftables** for anything
it cannot decide, and fans out across NIC RSS queues. That last property is where
the throughput comes from.

## Why composition beats a monolith

Because the crates share one evaluator and one bundle format, you can add an
enforcement surface without touching the others, and a verdict from any crate
escalates consistently (the DLP OCR hook, for instance, can only ever *raise* a
verdict, never weaken one — `Option::max` semantics). The throughput is measured:
**5.718 Gbps single-stream floor → 27.264 Gbps multi-queue ceiling across 8
cores (4.77×)** ([`multiqueue-micro.json`](../artifacts/multiqueue-micro.json)),
and 4.461 → 20.588 Gbps on the branch-large profile (4.61×). The lift is RSS
queue fan-out plus the kernel cache, not silicon.

## The business call: scale by adding cores, not boxes

The scenario: **Tom, a CFO,** has two quotes. One is a hardware appliance with a
higher single-box number and a three-year refresh cycle. The other is SNG, whose
edge scales by adding queues and cores on compute Tom already rents. The crate +
XDP architecture is what lets SNG say "your throughput grows with the instance
you pick, and the fast path means repeat flows cost almost nothing" — a cost
curve that tracks cloud pricing, not a hardware BOM. For an MSP running a
dormant-heavy fleet, that elasticity is the product: idle tenants consume almost
no edge, busy ones get more cores.

## How the incumbents approached it

- **Fortinet** is the silicon answer: SPU/NP ASICs deliver appliance throughput
  (5/10/20 Gbps firewall on 40F/60F/100F,
  [`competitors.json`](../../bench/business-report/competitors.json)) but those
  are ASIC numbers, not software-on-VM, and the unit is a box. Unbeatable
  per-watt at the high end; wrong unit for a dormant fleet.
- **Palo Alto** mixes appliances (PA-440/450) with cloud enforcement; threat
  prevention throughput is the inspected number to compare, and it too is
  hardware-anchored.
- **Zscaler** runs a cloud-native software data plane — architecturally the
  closest — but on Zscaler's own infrastructure; you do not add your own cores,
  you buy capacity from their cloud.
- **Cato** runs its enforcement on a private global backbone; **Netskope**
  similarly on its NewEdge network. Both are "our cloud does the inspection,"
  which is powerful but a fixed-cost backbone you cannot shrink for idle tenants.

SNG's distinctive call is a *composable software edge you run on commodity
compute*, with a kernel fast path doing the cheap work — closest to Zscaler's
software topology but deployable on hardware you control and scale yourself.

## Build it yourself

1. **One crate per enforcement job, one shared evaluator.** Keep verdicts
   consistent by routing them all through the same evaluation code.
2. **Put a fast path in the kernel.** An XDP/eBPF LRU verdict cache for repeat
   flows turns the common case nearly free; fail open to a userspace path for
   anything the cache cannot decide.
3. **Make escalation monotonic.** A second detector should only ever raise a
   verdict, never weaken one — so adding inspection can never accidentally permit
   something the base pass blocked.
4. **Fan out across RSS queues** and publish the floor *and* the ceiling, so the
   throughput story is honest.

## Where this approach falls short

- **Software is not line-rate silicon.** The ceiling is a multi-core curve; a
  buyer needing guaranteed 100G line-rate should demand a real-NIC bake-off. We
  publish the single-stream floor precisely so nobody mistakes the ceiling for a
  guarantee.
- **The kernel fast path is operationally heavy.** eBPF/XDP needs a compatible
  kernel, careful verifier-friendly code, and real care around failing open. It
  buys throughput at the cost of deployment complexity.
- **Composability is a discipline.** The shared-evaluator contract only holds if
  every new crate respects it. A crate that evaluates policy its own way reintroduces
  the inconsistency the architecture exists to prevent.
