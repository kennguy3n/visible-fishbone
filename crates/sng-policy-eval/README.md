# sng-policy-eval

ShieldNet Gateway (SNG) local policy evaluation engine. `sng-policy-eval`
consumes verified policy bundles (delivered by `sng-comms`, signed by
the control plane, verified against a per-tenant trust store) and
evaluates per-flow verdicts on the data path.

## Pipeline

```text
sng-comms          → verified PolicyBundle.body bytes ↓
sng-policy-eval    → LoadedBundle (in-memory)         ↓
enforcement caller → Flow → Verdict                    ↓
```

The top-level entry point is [`PolicyEngine`](src/engine.rs). Build it
from a verified bundle body, then call [`PolicyEngine::evaluate`] per
flow.

## Wire format

Bundles are MessagePack envelopes wrapping JSON-encoded rule and
steering blocks — exactly the shape `internal/service/policy/` emits
on the Go control plane:

| field | type           | meaning                              |
|-------|----------------|--------------------------------------|
| `v`   | u8             | schema version (currently 1)         |
| `t`   | string         | bundle target (edge / endpoint / …)  |
| `g`   | string         | graph id (UUID)                      |
| `gv`  | i64            | graph version                        |
| `c`   | string         | compiler version                     |
| `d`   | string         | default action verb                  |
| `r`   | bin            | JSON-encoded `Vec<Rule>`             |
| `st`  | bin (optional) | JSON-encoded `SteeringRuleSet`       |
| `ts`  | timestamp      | compiled-at                          |

## Architecture

* **Hot-swap** — bundle rotation goes through [`arc_swap::ArcSwap`].
  The hot path ([`PolicyEngine::evaluate`]) clones a cheap `Arc` and
  does zero locking; rotation is atomic against concurrent readers
  and concurrent writers.
* **Replay protection** — by default, a bundle whose `graph_version`
  is strictly less than the currently-loaded version is rejected
  ([`PolicyEvalError::Stale`]). Pass `force = true` on the swap path
  for explicit operator rollback.
* **Target binding** — the engine is bound to a [`BundleTarget`] at
  construction; misrouted bundles fail with `TargetMismatch`.
* **Fail-closed** — unknown subject refs, unrecognised matcher kinds,
  and missing principals all skip the rule. The bundle's
  `default_action` (or `Deny` if absent) fires when nothing matches.
* **Wire compatibility** — every public type round-trips through the
  Go-side wire shape. Forward-compat `Unknown` variants on subject /
  predicate matchers let receivers keep loading bundles whose schema
  is one version ahead of what they understand.

## Verbs

Seven verbs, matching `ARCHITECTURE.md §3.2`:

| verb            | verdict shape              |
|-----------------|----------------------------|
| `allow`         | `Verdict::Allow`           |
| `deny`          | `Verdict::Deny`            |
| `inspect`       | `Verdict::Inspect{level}`  |
| `steer`         | `Verdict::Steer{class}`    |
| `decrypt`       | `Verdict::Decrypt`         |
| `log`           | `Verdict::Log`             |
| `suggest_only`  | `Verdict::SuggestOnly{..}` |

## Performance

`cargo bench -p sng-policy-eval` (criterion). Representative numbers
on a recent x86_64 box:

| bench                                 | time    |
|---------------------------------------|---------|
| `evaluate/default_action`             | ~15 ns  |
| `evaluate/literal_subject`            | ~21 ns  |
| `evaluate/steer_with_steering_lookup` | ~87 ns  |
| `evaluate/100_rules_last_matches`     | ~660 ns |

All under the sub-microsecond per-flow target. The 100-rule case
linearly scans rules (no skip list / decision-tree yet) and still
clears the budget; if rule counts climb into the low thousands the
next optimisation is a per-domain index on rule entry.

## Testing

```sh
cargo test -p sng-policy-eval
```

64 unit tests + 5 integration tests:

* End-to-end signed-bundle pipeline (`tests/integration.rs`) — mints
  an Ed25519 keypair, signs a real bundle, verifies through
  `sng_core::policy::PolicyVerifier`, loads through `PolicyEngine`,
  drives flows.
* Hot-swap, downgrade protection, target-mismatch rejection,
  tampered-body rejection.
* Concurrent swap + evaluate stress test.
