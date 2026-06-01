# sng-ips

IDS / IPS subsystem for the ShieldNet Gateway edge VM. Wraps
Suricata in inline (`AF_PACKET`, `IPS` mode) operation. The crate
is trait-based at every external boundary (`SuricataProcess`,
`IpsEventSink`) so the unit + integration test suites run
without root, without an actual Suricata binary, and without
touching the kernel.

## Module layout

* `process` — `SuricataProcess` trait with a production
  shell-out impl (`ShellSuricata`) and a `MockSuricata`
  for tests. The trait is intentionally narrow (`start`,
  `stop`, `signal`, `stats`, `is_alive`) so the supervisor in
  `manager` can swap implementations without touching the
  surrounding control logic. The mock writes synthetic EVE
  JSON for the alert-normalisation tests.
* `config` — deterministic `suricata.yaml` renderer for the
  IPS slice of a policy bundle. Mirrors `sng_fw::compile`:
  hand-rendered text, byte-identical output for byte-identical
  input, no third-party parser in the path.
* `rules` — typed `Rule` model and the parser/loader that
  authenticates a signed rule pack from the control plane.
* `eve` — `EveRecord` enum (`EveAlert`, `EveFlow`, `EveDns`,
  `EveHttp`, `EveTls`, `EveFileinfo`, `EveAnomaly`) and the
  normaliser that lifts Suricata's EVE JSON into the SNG
  telemetry envelope.
* `health` — health state machine (`Healthy` / `Degraded`
  / `Failed` / `Unknown`) and operator-chosen `FailMode`
  (`Open` / `Closed`) governing what happens to traffic when
  the IPS is down.
* `manager` — `IpsManager` supervisor that wires all of the
  above together: `install(config)` validates + writes +
  reloads or starts; `probe()` runs one health tick; the
  manager keeps the SHA-256 of the last installed config so a
  re-install with the same bytes is a no-op.
* `telemetry` — `IpsEventSource` + `IpsEventSink` adapters
  for the [`sng-telemetry`](../sng-telemetry) pipeline.

## Wire-format compatibility

The serialised rule / config shapes round-trip through the Go-
side compiler output (`internal/service/policy/`) so a rule
edited in the operator portal compiles into the exact YAML /
signature pack the edge consumes.

## Local verification

```sh
cargo +1.85 test  -p sng-ips
cargo +1.85 clippy -p sng-ips --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
