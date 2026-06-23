# sng-ztna

Zero-Trust Network Access (ZTNA) subsystem for the ShieldNet
Gateway. ZTNA is the per-application access broker. Where
[`sng-fw`](../sng-fw) decides whether a 5-tuple may pass and
[`sng-swg`](../sng-swg) decides what a web request may retrieve,
ZTNA decides whether **a specific identity on a specific device
may reach a specific application**.

## Module layout

* `app` — `App`, `AppCatalogProvider` trait, and the
  `StaticAppCatalog` test impl. What apps does this tenant
  publish? What URL / host patterns identify them? What
  minimum posture do they require? What groups are entitled?
* `identity` — `UserIdentity` and the `IdentityProvider`
  trait. Given a verified user id (`sub` from the IdP or the
  SPIFFE ID from the mTLS chain), what groups does the user
  belong to and is MFA still fresh?
* `device` — `DeviceTrustProvider` trait. Given a device id
  (the certificate fingerprint that passed mTLS), is the
  device enrolled, what is its live posture snapshot, when was
  it last attested?
* `policy` — `ZtnaPolicy` and the rule shapes that join the
  three providers above into an access decision.
* `request` — `AccessRequest` envelope.
* `error` — `ZtnaError` mapped to
  `sng_core::error::ErrorCode`.
* `service` — `ZtnaService::evaluate` is the brain's entry
  point. The path is: resolve app → resolve device trust +
  posture → resolve identity + group memberships → evaluate
  policy → return `AccessDecision` (`Allow`, `Deny`,
  `DenyPosture`, `DenyMfaStale`, …) with a structured
  reason for the audit log.
* `clientless` — browser-based access to internal web apps without
  an endpoint agent. OIDC authentication, sharded session store,
  host-to-app matching, reverse-proxy target routing, and cookie
  management. The clientless evaluator reuses the same
  `ZtnaService` for policy decisions.
* `stats` — counter surface; relaxed-ordering snapshot per
  the same per-counter contract as `sng-sdwan` and `sng-swg`.

## Telemetry

Every evaluation emits one structured event into the
[`sng-telemetry`](../sng-telemetry) pipeline carrying the
tenant, user, device, app, decision, and the policy id that
fired. The decision record is the source of truth for the
operator audit log.

## Local verification

```sh
cargo +1.91 test  -p sng-ztna
cargo +1.91 clippy -p sng-ztna --all-targets -- -D warnings
cargo +1.91 fmt    --all -- --check
```
