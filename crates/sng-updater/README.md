# sng-updater

Self-update engine for the ShieldNet Gateway edge VM and endpoint
client. The updater is the brain that decides **when**, **what**,
and **how** to install a new release of `sng-edge` or `sng-agent`
onto the running appliance. It does not itself ship bytes across
the wire (that is [`sng-comms`](../sng-comms)) and it does not
itself reboot the host (that is the bootloader binding); it
orchestrates the verified hand-off between those layers.

## Invariants

1. **Signed manifest gate** — only an Ed25519-signed manifest
   from a key the operator has explicitly provisioned can drive
   an install.
2. **Downgrade-rejected** — only a manifest whose version is
   strictly newer than the currently-committed image can be
   downloaded. The engine rejects downgrades up front, before
   the image bytes hit disk.
3. **Hash-authenticated body** — only the bytes whose SHA-256
   matches the signed manifest's `sha256` claim can be written
   to the inactive bank. The signed manifest authenticates the
   entire image transitively through the hash claim, exactly
   the way [`sng-policy-eval`](../sng-policy-eval)
   authenticates the rule table through the bundle body
   signature.
4. **Rollback-safe health window** — only an image that comes
   back healthy within the configurable window after the bank
   swap remains committed. If the health check fails (or
   times out), the bootloader is asked to re-pin the previous
   bank and the install is recorded as rolled-back.

## Module layout

* [`manifest`] — typed manifest model + Ed25519 signature
  verification via [`sng_core::policy::PolicyVerifier`]-style
  trust store.
* [`source`] — `ManifestSource` trait + `StaticManifestSource`
  test impl (production source is a `sng-comms` pull).
* [`download`] — streaming [`ImageDownloader`] with
  on-the-fly SHA-256 hashing ([`StreamingHasher`]) so a
  truncated or tampered transfer is rejected before the bank
  finalises.
* [`bank`] — `BankWriter` trait with a documented
  **idempotency contract** on `mark_committed` / `set_active`
  (the post-commit retry loop in the manager depends on it).
  Ships with `InMemoryBankWriter` for tests; the on-disk
  production impl ships separately.
* [`bootloader`] — `Bootloader` trait + `InMemoryBootloader`
  for tests; production impl bridges to the host bootloader
  (GRUB / U-Boot / EFI).
* [`healthcheck`] — `HealthCheck` trait, `HealthReport`,
  `StaticHealthCheck` for tests. The manager spins one of
  these inside the rollback window after each commit.
* [`policy`] — operator-controlled `UpdaterPolicy`
  (manifest-size cap, health-window cadence, channel pin) with
  hot-swap via `UpdaterPolicyHolder`.
* [`verifier`] — Ed25519 signature verification primitives,
  exported so external callers can re-verify a manifest out of
  band.
* [`state`] — explicit [`UpdateState`] state machine the
  service walks, rejecting illegal transitions.
* [`service`] — `UpdaterService` orchestrator with the
  install / rollback brain. Exposes `clear_layout_divergence`
  so an operator can re-arm the engine after manual metadata
  reconciliation.
* [`stats`] — counter surface matching the same per-counter
  contract used elsewhere in the workspace.

## Failure-mode discipline

Every error variant on `UpdaterError` maps to a distinct
`sng_core::ErrorCode` so the operator portal can distinguish
on dashboards between e.g. *"the manifest size exceeded the
operator-configured policy ceiling, no bytes were fetched"* and
*"the image we did fetch read larger than the manifest
declared"*. The variants are deliberately verbose for that
reason.

## Local verification

```sh
cargo +1.85 test  -p sng-updater
cargo +1.85 clippy -p sng-updater --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
