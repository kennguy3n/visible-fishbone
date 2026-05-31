# sng-swg

Secure Web Gateway (SWG) subsystem for the ShieldNet Gateway edge
VM. Wraps an in-tree Envoy forward-proxy as the data plane and
provides a Rust supervisor that owns config render, hot-swap,
process lifecycle, and per-request verdict evaluation via the
HTTP ext-authz contract.

The supervisor is trait-based at every external boundary
(`UrlCategorizer`, `MalwareVerdictProvider`, `EnvoyProcess`,
`TelemetryEmitter`) so the unit test suite runs without an Envoy
binary, without network, and without touching the kernel. The
in-tree `MockEnvoyProcess` captures every signal the production
`ShellEnvoy` impl would deliver via `/bin/kill`, and the
fixtures-driven verdict tests exercise the same decision pipeline
ext-authz uses at runtime.

## Module layout

* [`bypass`] — operator + industry-default SNI bypass list with
  longest-suffix-first match semantics. Re-uses
  `sng_fw::sni_suffix_match` so the SWG and the firewall agree on
  which TLS handshakes are exempt from inspection.
* [`categorizer`] — async `UrlCategorizer` trait and the in-tree
  `LocalCategoryDb` impl that backs a signed category bundle.
* [`malware`] — async `MalwareVerdictProvider` trait with the
  in-tree `StaticMalwareList` impl plus a TTL cache so the
  forward proxy can short-circuit repeat lookups.
* [`rate_limit`] — token-bucket per `(tenant_id, principal_id)`
  with a `Clock` trait so the tests drive refill deterministically
  via `TestClock`.
* [`verdict`] — pure verdict state machine producing
  `Action::{Allow, Bypass, Deny, RateLimit}`. The decision logic
  is testable without any HTTP layer.
* [`auth`] — HTTP ext-authz handler: JSON envelope decode, verdict
  dispatch, response render, telemetry emit. Envoy POSTs each
  candidate request to `/ext_authz`; the handler computes the
  verdict and replies with a JSON body Envoy maps onto allow / deny
  / 429.
* [`config`] — deterministic Envoy YAML renderer with SHA-256
  digest dedup. Mirrors `sng_fw::compile::render_script` (the
  nftables renderer): hand-rendered text, byte-identical output
  for byte-identical input, no third-party parser in the path.
* [`process`] — `EnvoyProcess` trait + `ShellEnvoy` and
  `MockEnvoyProcess` impls. Production shells out to `envoy
  --config-path …` for spawn / validate and to `/bin/kill -<sig>`
  for signal delivery (matches `sng_ips::process::ShellSuricata`).
* [`health`] — health state machine (`Healthy` / `Degraded` /
  `Failed` / `Unknown`) and operator-chosen `FailMode` (open /
  closed) governing what happens to traffic when the SWG is down.
* [`manager`] — supervisor that wires all of the above together:
  `install(config)` validates + writes + reloads or starts;
  `probe(admin_reachable)` runs one health tick; the manager
  keeps the digest of the last installed config so a re-install
  with the same bytes is a no-op.
* [`telemetry`] — `TelemetryEmitter` trait + the `sng-telemetry`
  bridge. Maps SWG-specific `Action` values onto the shared
  `Verdict` envelope and carries per-decision context
  (rate-limit metadata, bypass reason, category) without folding
  the distinction onto the wire shape.

## Wire-format compatibility

### Request

The Envoy ext-authz request body has just two top-level fields —
the full HTTP header map as an array of `[name, value]` pairs
(which is how serde serialises `Vec<(String, String)>`) and an
optional pre-computed body hash. SNG-specific fields are
**carried in headers**, not as top-level JSON keys — `into_context`
in `auth.rs` extracts them from the header vector at decode time.

```json
{
  "headers": [
    [":method", "GET"],
    [":scheme", "https"],
    [":path", "/page"],
    ["host", "example.com"],
    ["x-sng-tenant", "acme"],
    ["x-sng-principal", "user@acme"],
    ["x-sng-sni", "example.com"],
    ["user-agent", "Mozilla/5.0"]
  ],
  "body_sha256": "e3b0c442…"
}
```

The HTTP-pseudo headers `:method`, `:scheme`, `:path`, and the
`host` header are required. `x-sng-tenant` and `x-sng-principal`
are required so the handler can drive per-tenant rate-limiting
and per-principal audit. `x-sng-sni` is optional (set by the
forward-proxy on intercepted CONNECTs); `x-sng-file-sha256` and
the JSON `body_sha256` field both feed the malware-verdict path
(the JSON field is the wire-format slot — the header is the
Envoy filter-chain handoff slot).

### Response

The response envelope mirrors what Envoy turns into an
authorisation decision plus the matching deny / 429 response:

```json
{
  "action": "allow | deny | bypass | rate_limit",
  "status": 200,
  "reason": "human-readable description",
  "retry_after_secs": 60,
  "category": "social_media"
}
```

`status`, `retry_after_secs`, and `category` are nullable.
`retry_after_secs` is populated only on the `rate_limit` action
(it becomes the `Retry-After` header Envoy hands back); `category`
is populated only when the categoriser produced a value (any
action).

Both shapes are exercised by [`auth::tests`] round-trip tests so a
silent rename to either is caught at build time.

## Local verification

```
cargo test  -p sng-swg
cargo clippy -p sng-swg --all-targets -- -D warnings
cargo fmt    --check
```

