# sng-agent

ShieldNet Gateway endpoint client binary. `sng-agent` runs on the
user's Windows / macOS / Linux device and composes a strict subset
of the enforcement library crates behind the shared
[`sng_core::supervisor::Supervisor`](../sng-core/src/supervisor.rs)
harness:

| Subsystem | Library crate | Responsibility |
|---|---|---|
| `comms` | [`sng-comms`](../sng-comms) | Control-plane client (smaller pool than edge) |
| `policy_eval` | [`sng-policy-eval`](../sng-policy-eval) | Verified bundle for the `Endpoint` target |
| `telemetry` | [`sng-telemetry`](../sng-telemetry) | Single sink, no on-disk spool |
| `ztna` | [`sng-ztna`](../sng-ztna) | Per-flow access broker |
| `pal_capture` | [`sng-pal`](../sng-pal) | Traffic-capture → policy-eval → action loop |
| `pal_posture` | [`sng-pal`](../sng-pal) | Posture collector cadence → telemetry |
| `pal_tunnel` | [`sng-pal`](../sng-pal) | Tunnel up/down driven by policy verdicts |

## Library / binary split

Like `sng-edge`, the crate exposes a `lib` target alongside the
`bin`. The library half publishes `run_agent` (full supervisor
lifecycle on a loaded config) and `build_agent` (subsystem
composition only). The binary half (`src/main.rs`) is a thin
wrapper around `run_from_args`.

The in-tree integration tests (`tests/agent_e2e.rs`,
`tests/agent_supervisor.rs`) drive the supervisor stack
in-process with `InMemoryPal` standing in for the per-OS
backends.

## CLI

```
sng-agent --config <PATH> \
          [--pal-backend in-memory|native] \
          [--capture-backend in-memory|native] \
          [--posture-backend in-memory|native] \
          [--tunnel-backend in-memory|native] \
          [--log-filter <ENV_FILTER>] [--log-json]
```

* `--config` is required. Reference schema:
  [`crate::config::AgentConfig`](src/config.rs).
* `--pal-backend native` is reserved for the per-OS PAL impls
  (WFP / Network Extension / nftables-TPROXY for capture; TPM /
  Secure Enclave / kernel keyring for the key store; BoringTun /
  kernel WireGuard / `NEPacketTunnelProvider` for the tunnel)
  which ship as a separate set of per-OS crates. The binary
  today fails fast at boot with
  `AgentBuildError::UnsupportedPalBackend` rather than silently
  running with the test backend.
* `--capture-backend` / `--posture-backend` /
  `--tunnel-backend` are per-sub-adapter overrides on top of
  `--pal-backend` so an operator can pin one adapter at a time
  during a staged native-backend rollout (e.g. ship capture
  first, then posture, then tunnel).

Each flag is also bindable via `SNG_AGENT_*` environment
variables.

## Resource budget

`sng-agent` targets the SDA / VMA / SKA family budgets:

* Sub-15 MB resident memory.
* Sub-0.1 % idle CPU.
* Adaptive scheduling: posture scans / heartbeats back off on
  battery and during user activity.

These are budgets, not aspirations — `sng-agent` is rejected
from release if it cannot meet them on the reference hardware
tier. The `pal_posture` cadence and `comms` reconnect-with-
backoff are both tuned to that ceiling.

## Local verification

```sh
cargo +1.91 test  -p sng-agent
cargo +1.91 clippy -p sng-agent --all-targets -- -D warnings
cargo +1.91 fmt    --all -- --check
```
