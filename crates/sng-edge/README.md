# sng-edge

ShieldNet Gateway edge VM appliance binary. `sng-edge` boots on the
customer's branch / site network and composes every enforcement
library crate behind the shared
[`sng_core::supervisor::Supervisor`](../sng-core/src/supervisor.rs)
harness:

| Subsystem | Library crate | Responsibility |
|---|---|---|
| `comms` | [`sng-comms`](../sng-comms) | Control-plane client (mTLS, h2, MessagePack); reconnect-with-backoff; bounded spool |
| `policy_eval` | [`sng-policy-eval`](../sng-policy-eval) | Verified bundle for the `Edge` target; hot-swap; sub-microsecond per-flow verdict |
| `telemetry` | [`sng-telemetry`](../sng-telemetry) | Five-stage pipeline (collect / dedup / redact / enrich / egress) |
| `dns` | [`sng-dns`](../sng-dns) | Recursive resolver + reputation / category / sinkhole filter chain |
| `fw` | [`sng-fw`](../sng-fw) | L3-L7 firewall, NAT, deterministic nftables script via `ShellNftables` |
| `ips` | [`sng-ips`](../sng-ips) | Suricata supervisor via `ShellSuricata` |
| `swg` | [`sng-swg`](../sng-swg) | Envoy supervisor + ext-authz handler via `ShellEnvoy` |
| `ztna` | [`sng-ztna`](../sng-ztna) | Per-app access broker |
| `sdwan` | [`sng-sdwan`](../sng-sdwan) | Underlay path selection per probe + policy |
| `updater` | [`sng-updater`](../sng-updater) | Signed manifest install + dual-bank rollback |

## Library / binary split

The crate exposes a `lib` target alongside the `bin`. The library
half publishes [`run_edge`] (full supervisor lifecycle on a
loaded config) and [`build_edge`] (subsystem composition only).
The binary half (`src/main.rs`) is a thin wrapper around
[`run_from_args`].

This split exists so the in-tree integration tests
(`tests/edge_e2e.rs`, `tests/edge_supervisor.rs`) can drive the
supervisor stack in-process without spawning a child process,
without OS signals, and without binding real network sockets.
External subprocesses (Suricata / Envoy / nftables) are swapped
for in-memory test doubles via the same trait surface
`build_edge` exposes to the binary.

## CLI

```
sng-edge --config <PATH> [--health-bind <HOST:PORT>] \
         [--updater-backend in-memory|disk] \
         [--pal-backend in-memory|native] \
         [--log-filter <ENV_FILTER>] [--log-json]
```

* `--config` is required. Reference schema:
  [`crate::config::EdgeConfig`](src/config.rs).
* `--health-bind` exposes the supervisor's health aggregator on
  the named address; default OFF (typical deployment fronts the
  binary with a reverse proxy that owns its own port binding).
* `--updater-backend disk` is reserved for a future disk-backed
  bank writer + EFI bootloader crate; the binary today fails
  fast at boot with `EdgeBuildError::UnsupportedUpdaterBackend`
  rather than silently running with the test backend.
* `--pal-backend native` is reserved for the per-OS PAL impls
  used by `sng-agent`; the edge VM does not need them in its
  packet path but the flag is shape-parity'd with the agent
  CLI so config-management templates can target both binaries.

Each flag is also bindable via `SNG_EDGE_*` environment
variables.

## Supervisor drain contract

`run_edge` configures the supervisor with `health_drain_first =
true` so the health aggregator is drained before any subsystem
Arc clones it holds are released. This is load-bearing: the
telemetry-pipeline `recv()` only completes after every
producer-side mpsc clone is dropped, and the aggregator holds
one such clone for the duration of its loop. Releasing it
first lets the per-subsystem drain steps actually observe
channel closure inside the drain budget.

See `tests/edge_e2e.rs::supervisor_drain_under_load` for the
regression test.

## Local verification

```sh
cargo +1.85 test  -p sng-edge
cargo +1.85 clippy -p sng-edge --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
