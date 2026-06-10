# Throughput by SKU

<!--
  GENERATED FILE — do not edit the tables by hand.
  Regenerate from the repo root with:
    cargo run --manifest-path bench/Cargo.toml --release -- forwarding-doc \
      --profiles-dir bench/profiles/skus --out docs/throughput-skus.md \
      --git-sha "$(git rev-parse --short HEAD)"
-->

This document publishes the per-SKU forwarding throughput of the ShieldNet
Gateway edge data path. It is produced by the `sng-bench` harness driving
the **real** enforcement code paths — the same `FirewallEngine`,
`XdpRuleSet` (WS1 eBPF/XDP fast path), L7 `AppIdentifier`/`SniExtractor`,
Aho-Corasick IPS/DLP multi-pattern matcher, and `ring` AES-256-GCM TLS
record opener the gateway ships — over a deterministic synthetic flow pool.
No number below is hand-entered or extrapolated.

## Forwarding modes

Each SKU is swept across four cumulative inspection depths:

| Mode | Stages run |
| --- | --- |
| `raw-l3` | L3/L4 forwarding decision only (XDP rule match or engine verdict). |
| `ngfw-verdict` | Stateful NGFW verdict (5-tuple policy + connection tracking). |
| `full-stack` | NGFW + L7 app-id + URL categorization + IPS/DLP content scan + malware reputation. |
| `full-stack-tls` | Full stack with TLS decrypt: SNI extraction, decrypt decision, AES-256-GCM record opening, then cleartext content scan. |

For each mode we measure both forwarding substrates — the **nftables**
userspace slow path (`FirewallEngine`) and the **XDP** fast path
(`XdpRuleSet`) from WS1 — so the published headline figures reflect the
shipping fast path while the toggle quantifies its advantage. The
`full-stack-tls` mode is additionally broken down across the six-tier
traffic-class taxonomy (`trusted_direct`, `trusted_media_bypass`,
`inspect_lite`, `inspect_full`, `tunnel_private`, `block`) weighted by each
profile's configured mix.

## Methodology

* **Profiles.** SKUs are pinned in `bench/profiles/skus/{micro,small,medium,large}.toml`
  (2 / 4 / 8 / 16 vCPU, matching the `commodity.rs` baseline). Each profile
  fixes the vCPU/RAM/NIC assumptions, the synthetic policy `rule_count`, the
  representative `packet_bytes`, the `sample_packets` per measurement, and
  the traffic mix, so a run is fully reproducible from the file alone.
* **Throughput.** Wall-clock time to push `sample_packets` through the
  pipeline; `pps = packets / elapsed`. `Gbps` converts at the profile's
  representative frame size (`pps × packet_bytes × 8`). The harness drives a
  single core, so these are **per-core** fast-path rates; the WS1 XDP path
  scales per RSS queue, so the box aggregate is approximately the figure
  times the SKU's `nic_queues` fan-out.
* **Latency.** Per-packet service time sampled in fixed brackets so timer
  overhead amortises away, fed to an HDR-style histogram; `p50`/`p99` are
  read from it.
* **CPU headroom.** `1 − target_share_pps / measured_pps`, floored at zero,
  where `target_share_pps` is the SKU's published `target_gbps` divided
  across its `nic_queues` fan-out (one queue per vCPU when unset) at the
  representative frame size. It is each core's spare decision capacity over
  its share of the committed box target — comparing a per-core measurement
  to a whole-box target would read ~0% on every multi-core SKU.

## How to reproduce

```sh
# (sng-bench is a standalone workspace, hence --manifest-path; run from
#  the repo root so the relative paths below resolve.)

# One SKU → JSON artifact (used as the CI baseline):
cargo run --manifest-path bench/Cargo.toml --release -- forwarding \
  --profile bench/profiles/skus/micro.toml --out bench/results/forwarding-micro.json

# All SKUs → regenerate this document:
cargo run --manifest-path bench/Cargo.toml --release -- forwarding-doc \
  --profiles-dir bench/profiles/skus --out docs/throughput-skus.md \
  --git-sha "$(git rev-parse --short HEAD)"
```

Absolute figures scale with the host; the run is deterministic in shape
(flow pool, rule walk, and per-class weighting are seeded), so ratios
between modes/backends are stable across machines. That invariance is what
the regression gate keys on.

## Published throughput

Measured at revision `8e66a68`.

### SKU: `micro`

Synthetic policy: 128 rules · representative frame 1500 B · 100000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 3.03 | 36.366 | 463 ns | 674 ns | 99% |
| ngfw-verdict | 0.44 | 5.222 | 2.293 µs | 3.989 µs | 92% |
| full-stack | 0.41 | 4.887 | 2.453 µs | 4.303 µs | 92% |
| full-stack-tls | 0.30 | 3.553 | 2.455 µs | 9.639 µs | 89% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.49 | 5.895 |
| XDP (fast path) | 3.03 | 36.366 |

XDP fast-path speedup: **6.17×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.42 | 5.036 | 2.357 µs | 3.799 µs |
| trusted_media_bypass | 0.42 | 5.017 | 2.385 µs | 3.779 µs |
| inspect_lite | 0.34 | 4.096 | 2.885 µs | 4.555 µs |
| inspect_full | 0.12 | 1.407 | 8.543 µs | 12.679 µs |
| tunnel_private | 0.37 | 4.416 | 2.791 µs | 4.555 µs |
| block | 1.65 | 19.857 | 586 ns | 828 ns |

### SKU: `small`

Synthetic policy: 256 rules · representative frame 1500 B · 200000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 1.56 | 18.669 | 743 ns | 1.473 µs | 97% |
| ngfw-verdict | 0.34 | 4.059 | 3.089 µs | 5.359 µs | 85% |
| full-stack | 0.31 | 3.729 | 3.259 µs | 6.479 µs | 83% |
| full-stack-tls | 0.22 | 2.699 | 3.455 µs | 10.327 µs | 77% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.40 | 4.743 |
| XDP (fast path) | 1.56 | 18.669 |

XDP fast-path speedup: **3.94×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.32 | 3.854 | 3.031 µs | 5.823 µs |
| trusted_media_bypass | 0.31 | 3.779 | 3.215 µs | 5.963 µs |
| inspect_lite | 0.27 | 3.280 | 3.587 µs | 6.459 µs |
| inspect_full | 0.11 | 1.327 | 9.079 µs | 13.015 µs |
| tunnel_private | 0.29 | 3.443 | 3.303 µs | 6.187 µs |
| block | 0.80 | 9.563 | 1.153 µs | 1.511 µs |

### SKU: `medium`

Synthetic policy: 512 rules · representative frame 1500 B · 400000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 0.82 | 9.883 | 1.272 µs | 2.643 µs | 92% |
| ngfw-verdict | 0.21 | 2.484 | 4.847 µs | 8.719 µs | 70% |
| full-stack | 0.13 | 1.536 | 7.475 µs | 19.199 µs | 51% |
| full-stack-tls | 0.15 | 1.806 | 6.667 µs | 21.551 µs | 58% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.28 | 3.386 |
| XDP (fast path) | 0.82 | 9.883 |

XDP fast-path speedup: **2.92×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.21 | 2.473 | 6.203 µs | 24.703 µs |
| trusted_media_bypass | 0.11 | 1.330 | 7.747 µs | 21.711 µs |
| inspect_lite | 0.10 | 1.250 | 5.551 µs | 10.703 µs |
| inspect_full | 0.09 | 1.073 | 11.159 µs | 16.511 µs |
| tunnel_private | 0.19 | 2.253 | 5.359 µs | 10.383 µs |
| block | 0.39 | 4.694 | 2.517 µs | 3.495 µs |

### SKU: `large`

Synthetic policy: 1024 rules · representative frame 1500 B · 600000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 0.38 | 4.559 | 2.645 µs | 5.343 µs | 84% |
| ngfw-verdict | 0.12 | 1.400 | 8.447 µs | 16.991 µs | 46% |
| full-stack | 0.12 | 1.385 | 8.895 µs | 17.423 µs | 46% |
| full-stack-tls | 0.10 | 1.149 | 8.911 µs | 22.447 µs | 35% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.16 | 1.916 |
| XDP (fast path) | 0.38 | 4.559 |

XDP fast-path speedup: **2.38×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.12 | 1.385 | 8.247 µs | 17.935 µs |
| trusted_media_bypass | 0.11 | 1.378 | 8.311 µs | 17.967 µs |
| inspect_lite | 0.11 | 1.298 | 8.863 µs | 18.719 µs |
| inspect_full | 0.07 | 0.821 | 14.231 µs | 24.751 µs |
| tunnel_private | 0.11 | 1.322 | 8.703 µs | 18.351 µs |
| block | 0.20 | 2.420 | 4.907 µs | 6.071 µs |

## Regression detection

CI gates on the **Micro** profile (`.github/workflows/throughput-regression.yml`).
On every push/PR it rebuilds the sweep and compares it against the committed
baseline `bench/results/forwarding-micro.json` with:

```sh
cargo run --manifest-path bench/Cargo.toml --release -- forwarding \
  --profile bench/profiles/skus/micro.toml --out /tmp/forwarding-micro.json
cargo run --manifest-path bench/Cargo.toml --release -- forwarding-compare \
  --baseline bench/results/forwarding-micro.json \
  --current  /tmp/forwarding-micro.json \
  --threshold 0.15
```

The comparison is **hardware-invariant** — it never diffs two absolute
throughput numbers (which drift with the runner). Instead it diffs
dimensionless ratios:

1. **Per-mode normalised cost.** For every `(mode, backend)` it computes
   `ns_per_packet(mode) / ns_per_packet(raw-l3, xdp)` and flags a regression
   when that ratio rises by more than the threshold — i.e. a stage (NGFW,
   IPS, TLS, …) became disproportionately more expensive relative to the
   line-rate fast path.
2. **Fast-path advantage.** It tracks the raw-L3 `xdp / nftables` speedup and
   flags a regression when it drops by more than the threshold — catching a
   fast-path that lost ground against the engine, the one regression a
   relative-cost check anchored on the fast path cannot see on its own.

A flagged regression exits non-zero (code 2) and fails the build. Refresh
the baseline deliberately — by re-running the `forwarding` command above and
committing the updated JSON — when a change is an intentional, understood
shift.
