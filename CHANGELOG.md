# Changelog

All notable changes to the ShieldNet Gateway (SNG) control plane are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed (Breaking)

- **Production builds forbid `AUTH_JWT_SECRET` and exclude the HMAC JWT path
  entirely** ([#87]). The `uat`/`prod` config check inverted from *required* to
  *forbidden*: a control plane started in a production environment with
  `AUTH_JWT_SECRET` set now **fails closed at boot** with
  `AUTH_JWT_SECRET must NOT be set in production environments: the HMAC JWT signing/verification path is excluded from production builds; terminate identity at the gateway via OIDC instead`.
  The HMAC verifier is compiled out of production binaries via
  `//go:build production`, so in production every `Bearer` token —
  operator-console JWTs **and** HMAC-signed mobile session tokens — is refused
  with `jwt_hmac_disabled`; the only in-process auth path is the
  `X-SNG-API-Key` header. An **OIDC gateway is therefore a hard prerequisite
  for all authenticated traffic** (operator and mobile), and mobile
  device-revocation enforcement moves to the gateway/enrollment layer in
  production.

  **Upgrade steps for an existing production deployment:**
  1. Confirm identity terminates at the OIDC gateway and in-process auth uses
     `X-SNG-API-Key`.
  2. Unset `AUTH_JWT_SECRET` in the `uat`/`prod` environment.
  3. Roll out the new build.

  See [`SECURITY.md`](./SECURITY.md) and [`docs/deploy.md`](./docs/deploy.md) for
  the full prerequisite documentation.

### Added

- Leader-election fencing tokens (`FencingToken{LockID, Epoch}`,
  `RunIfLeaderFenced`), `/readyz` leader-state reporting, and the
  `sng_leader_transitions_total` Prometheus counter ([#87]).
- `sng-migrate squash` command that renders a consolidated migration baseline
  for new deployments ([#87]).
- Defense-in-depth tenant isolation: data-layer GUC read-back + expected-tenant
  assertion in `setTenantGUC`, the `AssertTenantContext` middleware, per-tenant
  NATS subject ACL templates under `deploy/nats/`, and a cross-tenant isolation
  integration test ([#87]).
- WS5 endpoint DLP: native per-OS `ChannelInterceptor` backends in `sng-pal`
  (`crates/sng-pal/src/dlp/`) for the file-write, clipboard, print and
  USB-transfer channels — Linux (inotify, udev/netlink, X11 XFIXES / Wayland),
  macOS (FSEvents, IOKit, `NSPasteboard`) and Windows (`ReadDirectoryChangesW`,
  WMI, clipboard format-listener chain, print-spool-directory watch) — each
  transparently falling back to a bounded portable poll watcher when its kernel
  hook is unavailable. The Windows print channel watches the spool directory
  (`…\spool\PRINTERS`) and reads the actual spooled-job content, mirroring the
  Linux/macOS spool watchers, rather than the content-less spooler change
  notification. The `sng-dlp` engine is wired into the `sng-agent` supervisor
  loop, gated per channel by `[dlp]` config flags. Operator `[dlp]` tuning
  (`max_file_bytes`, `poll_interval`) is honoured by every channel regardless
  of which backend a host ends up using, and is validated at load time
  (`> 0` when `dlp.enabled`) so a zero ceiling cannot silently disable content
  inspection ([#133]).

### Changed

- WS5 endpoint DLP (Linux): the `inotify` file-write watcher and the native
  X11 clipboard monitor now wake their async consumer via a
  `tokio::sync::Notify` edge bridge (pulsed by the worker thread on each
  queued batch, on worker exit, and on shutdown) instead of draining the
  shared buffer on a fixed 50 ms poll. This matches the existing
  `LinuxUsbTransferMonitor` udev wake, removes ~20 idle timer wakeups
  per second per channel, and cuts event-detection latency from up-to-50 ms
  to effectively zero; a `SHUTDOWN_POLL` fallback tick remains as a defensive
  bound only (`Notify` preserves a racing pulse as a permit) ([#135]).

[#87]: https://github.com/kennguy3n/visible-fishbone/pull/87
[#133]: https://github.com/kennguy3n/visible-fishbone/pull/133
[#135]: https://github.com/kennguy3n/visible-fishbone/pull/135
[Unreleased]: https://github.com/kennguy3n/visible-fishbone/compare/main...HEAD
