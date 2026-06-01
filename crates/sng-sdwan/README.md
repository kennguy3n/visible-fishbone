# sng-sdwan

SD-WAN steering brain for the ShieldNet Gateway edge VM.
`sng-sdwan` is the **path-selection brain** the data path consults
for every steerable flow. Given a `SteeringRequest` (tenant,
traffic class, flow id), the brain joins three signals:

1. **Path catalog** (`PathProvider`) — the static set of
   underlay paths available to this tenant (MPLS, internet-A,
   internet-B, LTE, etc.) with their per-traffic-class
   eligibility.
2. **Liveness probes** (`ProbeProvider`) — the most-recent
   `PathProbe` for each candidate path, carrying observed
   latency / loss / jitter and an epoch-millisecond timestamp.
3. **Policy** (`SdwanPolicy`) — the score weight vector,
   per-metric SLO floors, and operator-configured probe
   freshness budget.

The brain computes a weighted composite score for each
candidate (lower = better), picks the lowest-scoring fresh
path, and returns a `SteeringDecision` carrying the selected
path id, the score, and a structured `SteeringReason`.

## Module layout

* `path` — `Path`, `PathId`, `TrafficClass`, and the
  `PathProvider` trait + `StaticPathProvider` test impl.
* `probe` — `PathProbe` and the `ProbeProvider` trait +
  `StaticProbeProvider` test impl.
* `policy` — `SdwanPolicy`, `ScoreWeights`, and the
  hot-swap `SdwanPolicyHolder`.
* `score` — pure composite-score computation; the
  arithmetic is overflow-saturated to `worst()` (rather than
  panicking) so even pathological probe values stay
  well-defined.
* `decision` — `SteeringDecision` + `SteeringReason`
  (`BestInBudget`, `FallbackBelowFloor`, `StickyPinned`,
  `NoCandidate`, …).
* `request` — `SteeringRequest` envelope.
* `service` — `SdwanService` orchestrator with the
  sticky-pin cache (bounded; oldest-expiration eviction at
  capacity) and the `evaluate` / `finalise` two-phase API
  the data path uses.
* `stats` — Prometheus-friendly counter surface; relaxed-
  ordering snapshot per the documented per-counter atomicity
  contract (matches `sng-ztna::stats` and `sng-swg::stats`).

## Two distinct `TrafficClass` enums

The `sng_sdwan::path::TrafficClass` enum (4 variants —
`RealTime`, `Interactive`, `BestEffort`, `Bulk`) is intentionally
separate from `sng_core::traffic_class::TrafficClass` (6
variants — `TrustedDirect`, `TrustedMediaBypass`, `InspectLite`,
`InspectFull`, `TunnelPrivate`, `Block`). They serve different
layers: `sng_core::TrafficClass` is the wire-level envelope
classification used by every subsystem; `sng_sdwan::TrafficClass`
is the path-selection steering tier the SD-WAN brain consumes
when picking an underlay. The compiler maps between them at
bundle-build time.

## Local verification

```sh
cargo +1.85 test  -p sng-sdwan
cargo +1.85 clippy -p sng-sdwan --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
