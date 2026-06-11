# `sng-bench` — ShieldNet Gateway edge benchmark suite

A reproducible benchmark harness that publishes throughput, latency, and
concurrent-flow numbers for the SNG edge data path, per edge SKU.

## Why this is a standalone crate

`bench/` is its own Cargo workspace (note the bare `[workspace]` table in
[`Cargo.toml`](./Cargo.toml)) and is **deliberately not** a member of the
root workspace. Benchmarks are heavy and only need to run on a schedule,
so excluding them keeps `cargo build --workspace`, `cargo test
--workspace`, and the per-PR CI gates fast — they never compile this
crate. The trade-off is that you build and lint it explicitly from inside
`bench/`:

```bash
cd bench
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

## What it measures

Four measurement modes, each a subcommand of the `sng-bench` binary:

| Mode | Question it answers | Headline metric |
| --- | --- | --- |
| `throughput` | How much inspected traffic can the edge sustain (single stream)? | max Gbps / pps |
| `latency` | What per-packet latency does the edge add? | p50 / p95 / p99 (ns) |
| `concurrent-flows` | How many active flows before degradation? | max flows |
| `multi-queue` | What is the aggregate ceiling across N parallel queues/streams? | aggregate Gbps + scaling efficiency |

The `multi-queue` mode exists because `throughput` measures a deliberately
conservative **single-stream floor** (one flow, one core). A real edge box
— like the ASIC appliances competitors benchmark — fans traffic across
many NIC receive (RSS) queues, one per core. `multi-queue` drives the
forwarding fast path across N concurrent streams and reports the aggregate
**line-rate ceiling** and per-stream scaling, so the floor and the ceiling
can be read side by side. See
[`docs/multi-queue-throughput.md`](./docs/multi-queue-throughput.md) for
the full methodology and how to read it honestly (it is a *software*
multi-queue model on a VM, not an ASIC).

A further subcommand, `compare`, diffs two JSON reports and exits non-zero
on regression (see [Regression detection](#regression-detection)). Another,
`business-report`, sweeps every profile across all three modes, packet
sizes, and inspection depths and renders one consolidated RFP-response
datasheet (see [Business report](#business-report)).

### Dimensions

Each run is parameterised over the dimensions that move edge performance,
recorded in the report so results are comparable only across matching
configurations:

- **Packet size** — `--packet-size` 64, 512, 1500, or 9000 (jumbo). Small
  frames stress the per-packet (pps-bound) path; jumbo frames stress the
  bandwidth-bound path.
- **Policy complexity** — `--policy-rules` 10, 100, or 1000. The number of
  rules loaded on the edge under test.
- **Inspection depth** — `--inspection` `no-inspect`, `url-cat`, or
  `full-tls`. The edge is configured out-of-band to match; the harness
  records the label.
- **IP version / L4** — `--ip-version` v4|v6, `--l4` udp|tcp-syn.

## Hardware profiles

[`profiles/`](./profiles) holds one TOML per edge SKU. Each profile pins
the reference hardware and the published acceptance target; the harness
loads `target_gbps` and flags a `MISS` in the report when a throughput run
falls short.

| Profile | vCPU | RAM | NIC | Target |
| --- | ---: | ---: | ---: | ---: |
| [`branch-small`](./profiles/branch-small.toml) | 2 | 4 GB | 1 Gbps | 800 Mbps |
| [`branch-medium`](./profiles/branch-medium.toml) | 4 | 8 GB | 10 Gbps | 5 Gbps |
| [`branch-large`](./profiles/branch-large.toml) | 8 | 16 GB | 25 Gbps | 10 Gbps |
| [`cloud-pop-small`](./profiles/cloud-pop-small.toml) | 4 | 8 GB | 10 Gbps | 2 Gbps |

`cloud-pop-small` models a shared multi-tenant cloud PoP (2 Gbps
aggregate across ~100 tenants) rather than a single-tenant branch box.

## Methodology

- **Traffic generation** ([`traffic_gen.rs`](./src/traffic_gen.rs)) — the
  `TrafficGenerator` trait crafts well-formed Ethernet/IP/L4 frames with
  correct checksums (RFC 1071 internet checksum + L4 pseudo-header) and
  randomised 5-tuples drawn from configured IPv4/IPv6 subnets and port
  ranges. `RawSocketGenerator` transmits them over `AF_PACKET`;
  `DryRunGenerator` crafts without wire I/O for unprivileged self-test.
  5-tuple sampling is seeded (`--seed`) so a run is byte-for-byte
  reproducible.
- **Pacing** — a token-bucket `Pacer` releases packets at `--target-pps`
  (0 = as fast as possible), with the burst capped so a scheduling stall
  cannot produce an artificial spike.
- **Measurement** ([`measurement.rs`](./src/measurement.rs)) — throughput
  uses lock-free atomic packet/byte counters sampled per one-second
  window. Latency uses an HdrHistogram-style log-linear histogram
  (configurable significant digits, pre-allocated, O(1) `record`) so the
  measurement itself does not allocate or perturb the timing. Resource
  usage is sampled from `/proc/stat` (CPU%) and `/proc/self/status`
  (`VmRSS`).
- **Allocation discipline** — frame buffers are sized once and reused; the
  hot path performs no per-packet heap allocation.

### Running the live path

The live modes put real frames on the wire and therefore need
`CAP_NET_RAW` and an edge in-path:

```bash
sudo target/release/sng-bench throughput \
  --profile profiles/branch-medium.toml \
  --interface eth1 \
  --packet-size 1500 --policy-rules 100 --inspection url-cat \
  --target-pps 4000000 --duration 60 \
  --out-dir results --git-sha "$(git rev-parse HEAD)"
```

Drop privileges and the in-path requirement with `--dry-run`, which
exercises the full craft → measure → report pipeline in-process:

```bash
target/release/sng-bench throughput \
  --profile profiles/branch-small.toml --dry-run --duration 5
```

The single `unsafe` block in the suite lives in `traffic_gen.rs::raw`
(initialising the `sockaddr_ll` for the `AF_PACKET` bind); it is scoped
tightly and documented inline. Everything else is `#![deny(unsafe_code)]`.

## Reports

Each run writes `results/<profile>-<mode>-<unixtime>.json`
([`report.rs`](./src/report.rs)) and prints a markdown summary to stdout.
The JSON carries a `schema_version`, the run dimensions, the measured
metrics, peak CPU/RSS, the target, and the git SHA, so a report is
self-describing for later comparison.

## Regression detection

`compare` loads a baseline and a current report and applies fractional
thresholds (default 10% throughput drop / 10% latency increase):

```bash
sng-bench compare \
  --baseline results/baseline-branch-medium.json \
  --current  results/branch-medium-throughput-<unixtime>.json \
  --throughput-drop 0.10 --latency-increase 0.10
```

Exit codes: `0` within thresholds, `2` regression detected (distinct from
a harness failure), other non-zero = error.

## Forwarding regression gate (statistically sound)

The per-PR CI gate
([`throughput-regression.yml`](../.github/workflows/throughput-regression.yml),
mirrored by `make bench-regression`) runs the **Micro** forwarding sweep
and compares it against the committed baseline
[`results/forwarding-micro.json`](./results/forwarding-micro.json) using
`forwarding-compare`.

The comparison is **hardware-invariant** — it never diffs absolute
throughput (which drifts run-to-run on shared CI runners) but only
dimensionless ratios: per-`(mode, backend)` normalised per-packet cost and
the raw-L3 `xdp / nftables` speedup.

A single run of those ratios on a shared Azure runner still wobbles by
double digits on scheduler noise alone, so a one-shot gate fires on noise
and trains everyone to ignore it. The gate is therefore **statistical**:

1. **Sample N times.** `make bench-regression` re-runs the sweep
   `BENCH_SAMPLES` times (default **7**), serialised and — where `taskset`
   exists — pinned to a single core so the scheduler does not migrate the
   measurement mid-run and inflate the variance.
2. **Aggregate with the median.** Each ratio is reduced across the samples
   with the **median**, which ignores the lone wild outlier a shared runner
   periodically emits (a mean would not).
3. **Gate against a noise band.** A metric is flagged only when the median
   move (a) clears the fractional `--threshold` (default **15%**) in the
   regressing direction **and** (b) is larger than `--sigma × σ` (default
   **2σ**, ~95% of Gaussian noise), where `σ` is the corrected sample
   standard deviation of the samples themselves. A real per-stage or
   fast-path regression clears both bars; a dip that lives inside the
   run-to-run scatter does not.

```bash
# What `make bench-regression` runs (abbreviated): N samples, then compare.
for i in $(seq 1 7); do
  sng-bench forwarding --profile profiles/skus/micro.toml \
    --out target/forwarding-micro-samples/sample-$i.json
done
sng-bench forwarding-compare \
  --baseline results/forwarding-micro.json \
  --current target/forwarding-micro-samples/sample-1.json \
  ... \
  --current target/forwarding-micro-samples/sample-7.json \
  --threshold 0.15 --sigma 2.0
```

`forwarding-compare` accepts `--current` once per sample; passing a single
`--current` collapses `σ` to zero and reproduces the legacy one-shot
threshold check, so the interface stays backward compatible. The command
prints every gated metric (`baseline → median (±%)`, `σ`, and the noise
band) so an engineer can see *why* it did or did not fire, then exits `2`
iff a real regression cleared both bars.

### Refreshing the baseline

The baseline is a measured artifact, so an intentional, understood change
to the data path (or a deliberate methodology change) means it must be
regenerated — **on `main`, after the change has merged**, so the committed
baseline always reflects shipped `main` rather than an in-flight branch:

```bash
# On main, after merge:
cargo run --manifest-path bench/Cargo.toml --release -- forwarding \
  --profile bench/profiles/skus/micro.toml \
  --out bench/results/forwarding-micro.json \
  --git-sha "$(git rev-parse --short HEAD)"
git commit bench/results/forwarding-micro.json \
  -m "bench: refresh forwarding-micro baseline (intentional <reason>)"
```

Because the gate keys on hardware-invariant ratios, you do **not** need to
regenerate the baseline just because CI moved to a different runner — only
when the underlying ratios genuinely, intentionally changed.

## Business report

`business-report` runs the full sweep (every profile × `{throughput,
latency, concurrent-flows}` × packet sizes × inspection depths) and
renders one consolidated markdown datasheet plus its backing JSON, with
an executive summary, per-SKU detail (throughput matrix, latency
percentiles, resource use), a competitor comparison, and a cost analysis:

```bash
target/release/sng-bench business-report \
  --profiles-dir profiles --dry-run \
  --out-dir results --git-sha "$(git rev-parse HEAD)"
```

The competitor section compares SNG's measured per-depth throughput
against published Fortinet / Palo Alto / Check Point numbers for the same
core class ([`competitor.rs`](./src/competitor.rs)). Those are
purpose-built hardware/ASIC figures and SNG is software-only on a generic
x86 VM, so **every row carries that caveat** — the comparison is
informative, not apples-to-apples.

## CI

[`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml)
runs the sweep weekly (Mondays 07:00 UTC) and on demand. It builds the
harness, sweeps every profile across all three modes, compares each fresh
throughput report against the committed
`results/baseline-<profile>.json`, fails the run and files a tracking
issue on a >10% regression, uploads all reports as artifacts, and (on the
scheduled run) commits the refreshed reports back to `bench/results/`. On
a stock GitHub-hosted runner the sweep runs `--dry-run`; point it at a
dedicated in-path runner to publish real line-rate numbers.
