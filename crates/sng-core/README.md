# sng-core

Foundation crate for the ShieldNet Gateway endpoint / edge workspace.

`sng-core` publishes the primitives every other crate in the workspace
depends on:

- **Identifier newtypes** (`TenantId`, `DeviceId`, `SiteId`, `PolicyBundleId`, …)
  wrapping `uuid::Uuid` so the multi-tenant boundary is enforced at the type level.
- **Traffic class enum** with byte-identical serialisation to
  `internal/repository/app_registry.go::TrafficClass` on the Go side.
- **Policy bundle target enum** (`edge` / `endpoint` / `cloud` / `mobile`)
  matching `internal/repository/types.go::PolicyBundleTarget`.
- **MessagePack event envelope and typed payloads** wire-compatible with
  `internal/nats/schema/`.
- **Ed25519 signed policy bundle verification** against a configurable
  trust store of control-plane signing keys.
- **Stable error taxonomy** (`SngError` + `ErrorCode`) that maps to the
  Go control plane's error codes for cross-stack correlation.
- **Configuration loader** (env + optional TOML file) validated at startup.
- **Lifecycle traits** (`ShutdownSignal`, `Health`, `HealthCheck`) so every
  long-running module participates in the same drain protocol.

The crate is `#![forbid(unsafe_code)]` and uses the workspace-pedantic
clippy profile.
