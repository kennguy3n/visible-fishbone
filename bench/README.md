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

Three measurement modes, each a subcommand of the `sng-bench` binary:

| Mode | Question it answers | Headline metric |
| --- | --- | --- |
| `throughput` | How much inspected traffic can the edge sustain? | max Gbps / pps |
| `latency` | What per-packet latency does the edge add? | p50 / p95 / p99 (ns) |
| `concurrent-flows` | How many active flows before degradation? | max flows |

A fourth subcommand, `compare`, diffs two JSON reports and exits non-zero
on regression (see [Regression detection](#regression-detection)).

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
