# SNG Test-Suite Report

Full run of every existing test suite across the Go control plane and the Rust
data plane, plus the standalone `bench/` harness dry-runs and the Criterion
policy-eval microbenchmarks. All commands below were executed on the runner and
their real output is recorded here — nothing is assumed.

## Runner / toolchain

| | |
| --- | --- |
| OS | Ubuntu 22.04 (x86_64), 8 vCPU, 31 GiB RAM |
| Go | go1.25.0 (matches CI `GO_VERSION: 1.25`) |
| Rust | rustc 1.85.0 (matches CI `RUST_TOOLCHAIN: 1.85`) |
| Docker | 27.4.1 (testcontainers available) |
| golangci-lint | v2.5.0 (matches CI) |
| base commit | `9e123f6` (`Merge pull request #80 … fix-dup-040-migration`) |

## Summary

Every layer is green. No test failures were found in the suite. The only code
change in this PR is a lint/clarity cleanup in the bench harness (see
[Fixes](#fixes-applied)); it did not change any behaviour or test outcome.

| Layer | Command | Run | Passed | Failed | Skipped |
| --- | --- | ---: | ---: | ---: | ---: |
| Go unit | `go test -race -count=1 ./...` | 1735 | 1735 | 0 | 0 |
| Go integration (testcontainers) | `go test -race -count=1 -tags=integration ./...` | 1779 | 1779 | 0 | 0 |
| Rust workspace (unit + integration + doctests) | `cargo test --workspace` | 1806 | 1806 | 0 | 0 |
| Bench crate (standalone) | `cd bench && cargo test` | 43 | 43 | 0 | 0 |

Notes on the counts:
- The Go *integration* run is a superset of the unit run: the `integration`
  build tag adds 44 testcontainer-gated tests (1779 − 1735) on top of the 1735
  unit tests. Those 44 live in 8 files: `internal/service/metering`,
  `internal/service/pop`, `internal/migrate` (runner + online),
  `internal/repository/postgres` (postgres / harness / pgbouncer /
  compliance_evidence).
- The Rust 1806 figure is the sum of all `test result: ok.` lines from
  `cargo test --workspace` (unit tests in each crate, the `tests/` integration
  binaries, and doctests). The integration-heavy E2E binaries are broken out
  in [Edge / Agent E2E](#edge--agent-e2e) below.
- The `bench/` crate is its own `[workspace]` and is not a member of the root
  Cargo workspace, so it is counted separately (39 lib tests + 4 bin tests).

## Lint / format gates

All clean — these are the same gates CI enforces, run locally:

| Gate | Command | Result |
| --- | --- | --- |
| Go vet | `go vet ./...` | clean |
| golangci-lint (default tags) | `golangci-lint run ./...` | `0 issues` |
| golangci-lint (integration tag) | `golangci-lint run --build-tags=integration ./...` | `0 issues` |
| Rust clippy | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Rust fmt | `cargo fmt --all -- --check` | clean |
| Bench clippy | `cd bench && cargo clippy --all-targets -- -D warnings` | clean |
| Bench fmt | `cd bench && cargo fmt --all -- --check` | clean |

## Edge / Agent E2E

Run individually as the most integration-heavy Rust tests; both green. The
`BuiltEdge { .. }` destructures in `crates/sng-edge/tests/edge_e2e.rs` (lines
695, 860, 972) already list all 11 subsystem fields including `ha` and
`updater`, so they match `BuiltEdge` in `crates/sng-edge/src/supervisor.rs` —
no missing field, no leaked Arc, clean drain/shutdown.

| Command | Result |
| --- | --- |
| `cargo test -p sng-edge --test edge_e2e` | ok — 3 passed, 0 failed (`full_stack_boots_pulls_bundle_then_drains_cleanly`, `supervisor_drain_under_continuous_load_within_budget`, `comms_reconnects_after_control_plane_transient_outage`) |
| `cargo test -p sng-agent --test agent_e2e` | ok — 2 passed, 0 failed (`full_stack_boots_pulls_bundle_then_drains_cleanly`, `agent_supervisor_drain_under_continuous_load_within_budget`) |

## Bench harness dry-runs

`cd bench && cargo build --release` succeeded, then each mode was run with
`--profile profiles/branch-small.toml --dry-run --duration 15`. All three exited
0 and wrote a valid `schema_version: 1` JSON report (validated with a JSON
parser).

> **What `--dry-run` measures.** In dry-run there is no real edge in-path; the
> harness exercises its own craft + transmit path against an in-process
> generator. The throughput/latency numbers below therefore characterise the
> *load-generator's* synthetic packet path on this 8-vCPU runner, **not** the
> SNG data plane's enforced throughput. They are recorded to prove the harness
> produces well-formed reports, not as a measurement of the product against the
> design targets in docs/throughput-skus.md. Real numbers require the live
> in-path setup the harness README describes.

Profile dimensions: packet size 1500 B, 100 policy rules, no-inspect.

| Mode | Key metrics (dry-run, branch-small) |
| --- | --- |
| throughput | max 77.165 Gbps · max 6,430,424 pps · mean 76.041 Gbps · target 0.800 Gbps (PASS) |
| latency | p50 170 ns · p95 241 ns · p99 270 ns · max 3.282 ms · clamped 0 |
| concurrent-flows | max active flows 98,222,080 |

Resources reported at peak (harness process): ~13% mean CPU busy, peak RSS
1.3–3.3 MiB across the three runs.

## Criterion policy-eval microbenchmarks

`cargo bench -p sng-policy-eval` — actual numbers for the 4 shapes in
`crates/sng-policy-eval/benches/eval.rs`. Criterion reports `[lower estimate
upper]`; the middle value is the point estimate.

| Shape | Time (point estimate) | Range |
| --- | ---: | --- |
| `evaluate/default_action` | 12.770 ns | [12.666 ns, 12.869 ns] |
| `evaluate/literal_subject` | 21.403 ns | [21.241 ns, 21.571 ns] |
| `evaluate/steer_with_steering_lookup` | 81.341 ns | [80.780 ns, 81.937 ns] |
| `evaluate/100_rules_last_matches` | 664.61 ns | [660.11 ns, 668.93 ns] |

## Fixes applied

### `bench/src/main.rs` — `CounterZero` → `COUNTER_ZERO`

A module-level `const` was named `CounterZero` (PascalCase) and carried an
`#[allow(non_upper_case_globals)]` to silence the lint:

```rust
// before
#[allow(non_upper_case_globals)]
const CounterZero: measurement::CounterSnapshot = …;
…
rate_between(CounterZero, snap, start.elapsed())

// after
const COUNTER_ZERO: measurement::CounterSnapshot = …;
…
rate_between(COUNTER_ZERO, snap, start.elapsed())
```

Renaming to the conventional `SCREAMING_SNAKE_CASE` removes the need for the
lint-suppression attribute entirely — the long-term fix rather than carrying an
`#[allow]` forever. Verified clean afterwards with `cargo clippy --all-targets
-- -D warnings`, `cargo fmt --all -- --check`, and `cargo test` in `bench/`.

## Preexisting / environmental notes

- None. No test was modified to pass, and no failure had to be worked around.
- The bench dry-run figures are synthetic by design (see the note above) — they
  are not a substitute for a live in-path benchmark on dedicated hardware.
