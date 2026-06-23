# sng-dem

Digital Experience Monitoring (DEM) subsystem for the ShieldNet Gateway
edge appliance.

`sng-dem` runs bounded synthetic probes against critical SaaS targets
and emits structured probe results. It is the edge half of the DEM
feature: the control plane owns target configuration, scoring, and
alerting, while this crate performs the actual measurement and returns
normalized results.

## Probe kinds

* `dns` — A/AAAA resolution against the target host.
* `tcp` — TCP connect to the target host and port.
* `http` — HTTP GET request (legacy, mostly superseded by `https`).
* `https` — HTTPS GET request with TLS handshake timing.

## Module layout

* `target` — `Target` definition, `ProbeKind` enum, target validation,
  and `EngineConfig` cost-model limits (max concurrency, timeout, jitter,
  max targets).
* `result` — `ProbeResult`, `ProbeErrorKind`, and structured JSON
  output matching the Go control-plane DTOs.
* `probe` — `ProbeEngine` and per-kind probe implementation. Probes are
  run with a bounded concurrency pool, per-probe timeout, configurable
  jitter, and deterministic cancellation.
* `lib` — Crate public API and re-exports.

## Engine behavior

`ProbeEngine::new` validates the `EngineConfig` and returns an engine
that can execute one-off or batched probes. `ProbeEngine::run_sweep`
accepts a target list, runs all probes concurrently up to
`max_concurrency`, and returns a `Vec<ProbeResult>`.

The engine is intentionally I/O-bound and uses `tokio::task::JoinSet`
so the runtime controls the task fan-out. A target that exceeds its
per-probe deadline is recorded as `ProbeErrorKind::Timeout` and does not
stall the rest of the sweep.

## Integration

The edge `sng-edge` crate wraps `sng-dem` in a `DemSubsystem` adapter
(`crates/sng-edge/src/subsystems/dem.rs`). The subsystem is **default
off**; when disabled it constructs no engine and its `start` task simply
waits for shutdown. When enabled it schedules sweeps on a configurable
interval and logs each probe result via `tracing`.

## Local verification

```sh
cargo +1.91 test  -p sng-dem
cargo +1.91 clippy -p sng-dem --all-targets -- -D warnings
cargo +1.91 fmt    --all -- --check
```
