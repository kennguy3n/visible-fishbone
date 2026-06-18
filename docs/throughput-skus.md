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

Measured at revision `d94732e3`.

### SKU: `micro`

Synthetic policy: 128 rules · representative frame 1500 B · 100000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 3.00 | 36.036 | 443 ns | 635 ns | 99% |
| ngfw-verdict | 0.47 | 5.635 | 2.157 µs | 4.279 µs | 93% |
| full-stack | 0.44 | 5.239 | 2.373 µs | 4.471 µs | 92% |
| full-stack-tls | 0.32 | 3.841 | 2.357 µs | 9.511 µs | 90% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.52 | 6.246 |
| XDP (fast path) | 3.00 | 36.036 |

XDP fast-path speedup: **5.77×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.42 | 4.995 | 2.273 µs | 3.927 µs |
| trusted_media_bypass | 0.45 | 5.460 | 2.221 µs | 3.637 µs |
| inspect_lite | 0.37 | 4.469 | 2.781 µs | 4.255 µs |
| inspect_full | 0.12 | 1.460 | 8.223 µs | 14.071 µs |
| tunnel_private | 0.37 | 4.425 | 2.661 µs | 4.227 µs |
| block | 1.70 | 20.406 | 562 ns | 851 ns |

### SKU: `small`

Synthetic policy: 256 rules · representative frame 1500 B · 200000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 1.46 | 17.498 | 736 ns | 1.328 µs | 96% |
| ngfw-verdict | 0.34 | 4.070 | 3.025 µs | 5.331 µs | 85% |
| full-stack | 0.32 | 3.842 | 3.213 µs | 5.819 µs | 84% |
| full-stack-tls | 0.23 | 2.778 | 3.495 µs | 12.279 µs | 77% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.41 | 4.880 |
| XDP (fast path) | 1.46 | 17.498 |

XDP fast-path speedup: **3.59×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.32 | 3.804 | 3.029 µs | 5.919 µs |
| trusted_media_bypass | 0.31 | 3.758 | 3.081 µs | 6.875 µs |
| inspect_lite | 0.28 | 3.305 | 3.551 µs | 6.483 µs |
| inspect_full | 0.11 | 1.311 | 8.983 µs | 13.703 µs |
| tunnel_private | 0.29 | 3.528 | 3.265 µs | 6.223 µs |
| block | 0.81 | 9.660 | 1.196 µs | 1.973 µs |

### SKU: `medium`

Synthetic policy: 512 rules · representative frame 1500 B · 400000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 0.75 | 8.972 | 1.345 µs | 2.715 µs | 92% |
| ngfw-verdict | 0.22 | 2.590 | 4.755 µs | 8.727 µs | 71% |
| full-stack | 0.20 | 2.368 | 5.067 µs | 10.231 µs | 68% |
| full-stack-tls | 0.15 | 1.741 | 6.139 µs | 15.687 µs | 57% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.28 | 3.341 |
| XDP (fast path) | 0.75 | 8.972 |

XDP fast-path speedup: **2.69×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.20 | 2.377 | 4.927 µs | 10.791 µs |
| trusted_media_bypass | 0.20 | 2.404 | 4.819 µs | 9.791 µs |
| inspect_lite | 0.18 | 2.189 | 5.483 µs | 11.047 µs |
| inspect_full | 0.09 | 1.062 | 10.839 µs | 18.975 µs |
| tunnel_private | 0.19 | 2.297 | 5.299 µs | 11.335 µs |
| block | 0.40 | 4.805 | 2.325 µs | 3.577 µs |

### SKU: `large`

Synthetic policy: 1024 rules · representative frame 1500 B · 600000 packets/measurement.

**Forwarding modes (XDP fast path):**

| Mode | Mpps | Gbps | p50 | p99 | CPU headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-l3 | 0.40 | 4.766 | 2.471 µs | 5.479 µs | 84% |
| ngfw-verdict | 0.12 | 1.407 | 8.471 µs | 17.087 µs | 47% |
| full-stack | 0.11 | 1.371 | 9.007 µs | 18.399 µs | 45% |
| full-stack-tls | 0.09 | 1.113 | 9.239 µs | 23.951 µs | 33% |

**Raw-L3 datapath toggle (nftables vs XDP):**

| Substrate | Mpps | Gbps |
| --- | ---: | ---: |
| nftables (slow path) | 0.17 | 2.036 |
| XDP (fast path) | 0.40 | 4.766 |

XDP fast-path speedup: **2.34×**.

**Per-traffic-class (full-stack + TLS, XDP fast path):**

| Traffic class | Mpps | Gbps | p50 | p99 |
| --- | ---: | ---: | ---: | ---: |
| trusted_direct | 0.11 | 1.372 | 8.439 µs | 19.279 µs |
| trusted_media_bypass | 0.11 | 1.337 | 8.423 µs | 20.175 µs |
| inspect_lite | 0.11 | 1.262 | 9.015 µs | 20.655 µs |
| inspect_full | 0.07 | 0.793 | 14.807 µs | 27.023 µs |
| tunnel_private | 0.11 | 1.289 | 8.887 µs | 20.591 µs |
| block | 0.20 | 2.423 | 4.955 µs | 8.367 µs |

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
