# Security Policy

ShieldNet Gateway (SNG) is a security product. We take vulnerability
reports seriously and prioritise them ahead of other work.

## Supported surface

We accept and triage vulnerability reports against `main` — the
shipping state of the product. Build the affected binary from the
latest `main` (or report the git SHA you built from) so we triage
against the same code you ran.

The product surface this policy covers, for code that lives in
*this* repository:

- The Rust enforcement plane under `crates/`, including the edge
  VM image binary (`sng-edge`), the endpoint client binary
  (`sng-agent`), and every shared library crate (`sng-core`,
  `sng-pal`, `sng-comms`, `sng-policy-eval`, `sng-telemetry`,
  `sng-fw`, `sng-ips`, `sng-dns`, `sng-swg`, `sng-dlp`, `sng-ztna`,
  `sng-sdwan`, `sng-dem`, `sng-updater`).
- The Go control plane: `cmd/sng-control` (long-running API +
  worker), `cmd/sng-migrate` (one-shot migration runner), every
  package under `internal/`, the SQL migrations under
  `migrations/`, and the REST API surface described by
  `api/openapi.yaml`.
- The wire protocol described in
  [`ARCHITECTURE.md`](./ARCHITECTURE.md) §10 (the SN360 native
  protocol over TLS 1.3, HTTP/2, and MessagePack).
- The signed policy bundle / signed update manifest format
  (Ed25519 over a canonical MessagePack payload).

The broader SN360 multi-product security-event platform
(Wazuh-based correlation, IOC distribution, SBOM / inventory,
MSP portal across all SN360 products) lives in the sibling
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
repo and is covered by that repo's `SECURITY.md`. Reports that
straddle both surfaces should be sent to the address below; we
will route internally.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion thread
for security vulnerabilities.**

Send the report to **[security@uney.com](mailto:security@uney.com)**.
Encrypt sensitive details with our PGP key (fingerprint published
at [https://uney.com/.well-known/security.txt](https://uney.com/.well-known/security.txt))
if the issue involves credentials, exploit code, or PII.

A useful report includes:

- A short description of the vulnerability and its impact.
- The affected SNG component (`sng-control`, `sng-migrate`,
  `sng-edge`, `sng-agent`, or a named library crate) and the
  version (`sng-control --version`, `sng-edge --version`,
  `sng-agent --version`, or the git SHA you built from).
- The deployment shape: SaaS control plane vs. self-hosted, edge
  VM hypervisor (VMware / KVM / Hyper-V / cloud), endpoint OS
  (Windows / macOS / Linux).
- Reproduction steps, ideally with a minimal config and a
  redacted log excerpt.
- Any proof-of-concept code, signed payload, packet capture, or
  sample inputs.
- Whether the issue has been disclosed elsewhere.

## Our response

We aim to:

- Acknowledge the report within **2 business days**.
- Provide an initial assessment (confirmed / not confirmed /
  needs more information) within **7 business days**.
- Publish a fix in a tagged release within **90 days** for
  high-severity issues, sooner for actively exploited ones.

We will coordinate disclosure with you. Public advisories (CVE,
GitHub Security Advisory, release notes) credit the reporter
unless you ask to remain anonymous.

## Out of scope

The following are not vulnerabilities for the purposes of this
policy:

- Operator misconfiguration that disables a security feature (for
  example running `sng-edge` with `dns.filter_chain: []`,
  disabling TLS inspection for every flow, or running
  `sng-control` against a Postgres role that bypasses RLS). The
  defaults documented in [`docs/deploy.md`](./docs/deploy.md)
  and the reference config shipped with each binary are the
  supported configuration.
- Theoretical issues that require an already-compromised
  control-plane database, an already-compromised edge VM, or
  arbitrary code execution on the host running `sng-agent` — an
  attacker with those primitives is outside the product's threat
  model.
- False positives or false negatives in the bundled policy
  templates, the DNS reputation feed, the SWG URL category feed,
  the inline DLP / AI governance / RBI classifiers, the DEM probe
  scoring thresholds, or the IDS/IPS Suricata rule pack. Tune those
  in your tenant's policy graph rather than reporting baseline
  coverage as a vulnerability.
- Performance issues without a security impact. File these as
  regular bugs.

## Crypto and signing posture

A short summary of the cryptographic invariants the product
relies on lives in [`ARCHITECTURE.md`](./ARCHITECTURE.md) §8:

- TLS 1.3 only (via `rustls`) on the SN360 native protocol
  between every edge / endpoint and the control plane.
- Mutual TLS with **device-bound Ed25519 identities** for every
  agent and edge VM; private keys never leave the device's
  hardware-backed key store where one is available (Windows TPM,
  macOS Secure Enclave, Linux kernel keyring or TPM 2.0).
- Policy bundles are **Ed25519-signed by the control plane** and
  verified before the edge / endpoint enforces them. Unsigned or
  version-mismatched bundles are rejected.
- Update manifests are **Ed25519-signed**; downgrade is rejected
  by monotonic version check, and the dual-bank install path
  refuses a swap if the new bank fails its health check inside
  the rollback window.
- Postgres row-level security (RLS) is the **primary** tenant
  isolation boundary on the control plane side; see
  [`docs/deploy.md`](./docs/deploy.md) for the role / GUC contract,
  and the "Defense-in-depth for tenant isolation" section below for
  the additional layers that backstop it.
- All telemetry is metadata-first; payloads are dropped at the
  edge unless the tenant's policy bundle opts in for that flow
  class.

If you find a way to bypass any of these invariants, that is a
security vulnerability and we want to hear about it.

## Operator authentication: HMAC excluded from production builds

The control plane supports a symmetric **HMAC (HS256)** JWT path for
operator-console authentication. This path exists purely for local
and dev workflows: it lets an engineer mint and verify console tokens
with a shared `AUTH_JWT_SECRET` without standing up an identity
provider. In `uat` and `prod` (`Environment.IsProduction()`), operator
identity is terminated at the gateway via **OIDC**; the control plane
never verifies an HMAC-signed token.

This is enforced by construction, not merely by a runtime flag:

- **The HMAC verification code is compiled out of production
  binaries.** The verifier in `internal/middleware/auth.go` is split
  behind a build tag. The real HMAC implementation lives in
  `auth_hmac.go` (`//go:build !production`); production builds
  (`-tags production`) instead link the stub in `auth_hmac_prod.go`
  (`//go:build production`), which always refuses with a
  `jwt_hmac_disabled` error. A production binary therefore contains no
  HMAC verification path at all — there is nothing to misconfigure or
  exploit.
- **Production refuses to boot with `AUTH_JWT_SECRET` set.** Config
  validation (`internal/config.validate`) hard-fails when
  `AUTH_JWT_SECRET` is non-empty in a production environment, so a
  leftover dev secret cannot create the illusion that HMAC auth is
  active.

Build production artifacts with `-tags production` (the release
pipeline does this) so the exclusion is in effect.

> **Operational prerequisite — an OIDC gateway is mandatory in
> production.** Because the HMAC path is compiled out, the only
> in-process authentication path a production control-plane binary has
> is the tenant/edge **API key** (`X-SNG-API-Key`). Every `Bearer`
> token — operator-console JWTs *and* the HMAC-signed device-bound
> mobile session tokens — flows through the same `verifyBearerJWT`
> verifier, which the production stub refuses with `jwt_hmac_disabled`.
> There is **no OIDC token-verification code in the control plane** —
> operator identity must be terminated at the gateway in front of it,
> which is responsible for translating an authenticated OIDC session
> into a credential the control plane accepts (a provisioned API key or
> a trusted, gateway-asserted header). Deploying the production binary
> without that gateway in place leaves operators with no console auth
> path, so the gateway must be configured **before** rolling out this
> build. See `docs/deploy.md` (“Operator authentication in production”).

### Upgrading an existing production deployment

A deployment that previously authenticated operators with an
HMAC-signed `AUTH_JWT_SECRET` must migrate before it can run a
production (`-tags production`) build, because that build refuses to
verify HMAC tokens and refuses to boot with `AUTH_JWT_SECRET` set:

1. **Terminate operator identity at the OIDC gateway first.** Stand up
   the gateway in front of the control plane and confirm it translates
   an authenticated OIDC session into a credential the control plane
   accepts (a provisioned `X-SNG-API-Key` or a trusted,
   gateway-asserted header). Verify operators can reach the console
   through it while the old build is still running.
2. **Unset `AUTH_JWT_SECRET`.** Remove it from the production
   environment/secret store. Config validation hard-fails if it is
   still set when the new build starts, so this must happen before the
   rollout.
3. **Roll out the production build.** Deploy the `-tags production`
   artifact (the release pipeline builds this by default). The HMAC
   verification path is now compiled out and operator auth flows
   entirely through the gateway.

## Defense-in-depth for tenant isolation

Postgres RLS is the primary tenant boundary, but a single boundary is
a single point of failure: an RLS policy that is accidentally dropped,
a query that runs on a connection whose `sng.tenant_id` GUC was never
set, or a transport that lets one tenant's agent publish into another
tenant's subjects would each silently breach isolation. We therefore
layer several independent checks so that no one mistake crosses a
tenant boundary on its own.

1. **Request edge — tenant assertion.** Every tenant-scoped route
   resolves the caller's tenant from the verified JWT `tenant_id`
   claim. `RequireTenant` rejects (403 `tenant_mismatch`) when a path
   `{tenant_id}` does not match the claim, and `AssertTenantContext`
   (`internal/middleware/tenant_assert.go`) fails closed (403
   `tenant_required`) if a tenant-scoped endpoint is reached with a
   credential carrying no tenant. Both stamp the resolved tenant as
   the request's *expected RLS tenant*
   (`postgres.WithExpectedTenant`), which the data layer below
   consumes to verify the query is scoped to that same tenant.

2. **Data layer — GUC read-back.** Before any tenant-scoped query, the
   repository sets the `sng.tenant_id` GUC and, in the same round trip,
   asserts the value Postgres actually applied equals the intended
   tenant (`internal/repository/postgres.setTenantGUC`, via
   `set_config(...)`'s return value). Because every RLS policy reads
   `current_setting('sng.tenant_id')`, a divergence here means RLS
   would evaluate against the wrong tenant; the transaction fails
   closed rather than risk a cross-tenant read or write. This catches
   a transaction-pooling middlebox that strips/rewrites `SET`, or a
   refactor that sets the GUC at the wrong scope. The same function
   also closes the request-edge → data-layer loop: when the context
   carries an *expected RLS tenant* (stamped by the middleware above),
   it asserts the tenant the query is about to scope to equals that
   resolved tenant, so a handler that authorized one tenant but issues
   a repository call for another fails closed instead of trusting the
   query's own tenant argument. Callers that legitimately span tenants
   (background jobs, MSP-level reads) simply do not stamp it.

3. **Analytics — ClickHouse query-level filtering.** ClickHouse
   readers do not rely on partitioning alone: every query carries an
   explicit `WHERE tenant_id = ?` predicate and refuses a nil tenant,
   so a mis-targeted partition cannot leak another tenant's telemetry.

4. **Transport — NATS per-tenant subject ACLs.** All control-plane
   subjects embed the tenant id (`sng.<tenant_id>.…`). The templates in
   [`deploy/nats/`](./deploy/nats/) fence each tenant's edge/endpoint
   credential to its own subjects (publish + subscribe), deny the
   cross-tenant DLQ and JetStream admin subjects, and reserve
   multi-tenant access for the trusted `sng-control` principal — so a
   compromised agent credential cannot publish into, or subscribe to,
   another tenant's streams.

5. **Continuous verification.** A cross-tenant integration sweep
   (`internal/repository/postgres/tenant_isolation_integration_test.go`,
   `//go:build integration`) seeds rows under tenant A across a
   representative set of repositories and asserts tenant B's `List`
   returns zero rows and `Get` returns `ErrNotFound`. Because every
   repository routes through the same `withTenant` path, a regression
   in the isolation mechanism breaks the whole sweep at once.

A breach now requires several independent failures at once, and any
single one of these layers catches the common mistakes. Bypassing any
layer is a reportable vulnerability.

## Hall of fame

Maintained on our website at
[https://sn360.com/security/credits](https://sn360.com/security/credits)
once we have credited reports to publish.
