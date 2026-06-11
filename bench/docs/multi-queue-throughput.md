# Multi-queue wire-throughput methodology

This document explains the `sng-bench multi-queue` mode: what it measures,
how to run it, and — most importantly — how to read a single-stream
*floor* against a multi-queue *ceiling* without overclaiming.

## Why this mode exists

SNG's published wire-throughput figure is honestly a **single-stream
floor**: one flow, one core, measured over a veth pair. That number is
deliberately conservative and the blog says so. It is *not* what a real
edge box does at the line rate, and it is *not* comparable to the
multi-queue figures hardware vendors (e.g. a Fortinet ASIC) publish, which
fan traffic across many NIC receive (RSS) queues, one per core.

A multi-queue physical NIC hashes incoming flows across N receive rings,
each pinned to its own core, and the per-queue XDP fast path runs
independently on each. The aggregate the box sustains is therefore far
above the single-stream floor — that aggregate is the **line-rate
ceiling** this mode measures.

## What it models, precisely

Each "queue" is a worker thread that owns a **distinct**
`ForwardingHarness` — its own `FirewallEngine`, conntrack, L7 inspectors,
AEAD key, and synthetic flow pool. N queues therefore share **no mutable
state**, exactly as N RSS rings pinned to N cores do not. A `Barrier`
releases every queue into its measured loop simultaneously, so the streams
genuinely contend for the host's cores and memory bandwidth for the whole
run. Per-queue state construction (engine install, inspector setup, flow
pool build) happens *before* the barrier and is never inside the timed
loop.

The forwarding decision and inspection stages are the **same** ones the
`forwarding` mode drives (`datapath.rs`) — the real `sng_fw` /
`sng_ebpf` / `ring` / `aho-corasick` code the edge ships, not a stand-in.
The only thing this mode adds is the fan-out across threads.

### The scaling curve

The sweep measures a curve of fan-out widths: `1, 2, 4, …` up to (and one
power-of-two step past) the larger of the host's available parallelism and
the SKU's `nic_queues`. For each width it records:

| Column | Meaning |
| --- | --- |
| **Aggregate Mpps / Gbps** | Sum of every concurrent stream's throughput — what the box sustains at that fan-out. |
| **Per-queue Mpps** | `aggregate / queues`. Falls once the fan-out exceeds the physical cores. |
| **Scaling eff.** | `aggregate / (queues × single_stream)`. `100%` is ideal linear scaling; below that is the real, contended ceiling. |
| **p50 / p99 (max)** | Mean per-stream median, and worst-case p99, service time. |

The `queues == 1` row is always measured first and is the efficiency
baseline — it **is** the single-stream floor.

## How to run it

```bash
cd bench
cargo build --release

# Default curve, raw-L3 fast path (the line-rate forwarding ceiling),
# parameters taken from the SKU profile:
target/release/sng-bench multi-queue \
  --profile profiles/skus/micro.toml \
  --out results/multiqueue-micro.json --git-sha "$(git rev-parse --short HEAD)"

# A full-inspection curve on a larger SKU (NGFW + L7 IPS/DLP, no TLS decrypt):
target/release/sng-bench multi-queue \
  --profile profiles/skus/medium.toml \
  --mode full-stack --packets-per-queue 60000 \
  --out results/multiqueue-medium-full-stack.json
```

It needs **no root, no NIC, and no running gateway** — it is an in-process
model, so it runs anywhere `cargo` does (including an unprivileged CI
runner). It prints the markdown summary to stderr and writes the
machine-readable JSON to `--out` (or stdout when `--out` is omitted).

### Flags

- `--mode` — inspection depth: `raw-l3` (default; the lean L3/L4
  forwarding decision — the line-rate ceiling), `ngfw-verdict`,
  `full-stack`, `full-stack-tls`.
- `--backend` — `xdp` (default, the fast path) or `nftables` (the
  userspace slow path).
- `--queues 1,2,4,8` — explicit fan-out widths. A `1` floor is always
  measured even if omitted. Empty derives the default curve.
- `--packets-per-queue` / `--rule-count` — override the per-stream sample
  size and synthetic rule count (default to the profile's `[datapath]`).

## How to read the numbers honestly

1. **The floor is the floor.** The `queues == 1` row is the same
   conservative single-stream number the blog quotes. The multi-queue
   rows do not replace it — they bracket the realistic operating range
   between the floor and the ceiling.
2. **Efficiency below 100% past your core count is expected and honest.**
   On an 8-vCPU host, the 16-queue row is oversubscribed: the OS
   time-slices 16 streams over 8 cores, so per-queue throughput and
   scaling efficiency drop. That is the *true* ceiling, not a defect —
   reporting only the linear extrapolation would be the dishonest move.
3. **Run-to-run scatter is real.** On a shared VM the scheduler perturbs
   any single run by double digits. For a published figure, sample
   several runs and take the median (the same discipline the
   `forwarding-compare` regression gate uses).
4. **It is still software on a VM.** This is a *software* multi-queue
   model — not a multi-queue physical NIC, and not an ASIC. Treat the
   ceiling as an apples-*closer* figure to a vendor's multi-queue
   line-rate number, **still not apples-to-apples**. The report markdown
   carries this caveat inline so it travels with the numbers.

## Captured results

The committed artifacts under [`../results/`](../results) were measured on
an 8-vCPU x86 VM (`available_parallelism = 8`):

- [`multiqueue-micro.json`](../results/multiqueue-micro.json) — `micro`
  SKU, `raw-l3` / `xdp`. Single-stream floor ≈ **36 Gbps**, 16-queue
  ceiling ≈ **279 Gbps** (a ~7.7× lift). The lean forwarding decision is
  pps-bound, so it scales near-linearly until the cores saturate.
- [`multiqueue-medium-full-stack.json`](../results/multiqueue-medium-full-stack.json)
  — `medium` SKU, `full-stack` / `xdp`. Single-stream floor ≈ **2.4
  Gbps** (below the 6 Gbps acceptance target), multi-queue ceiling ≈
  **11 Gbps** (above it). This is the headline case: the single-stream
  floor *undersells* a box that comfortably clears its target once it uses
  all its queues.

Absolute numbers depend on the host; re-run on your own hardware. The
*shape* — a steep early climb that flattens past the physical core count —
is the portable result.
