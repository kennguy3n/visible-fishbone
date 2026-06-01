# Security Policy

ShieldNet Gateway (SNG) is a security product. We take vulnerability
reports seriously and prioritise them ahead of other work.

## Supported versions

We accept and triage vulnerability reports against the current
release branch (the most recent tagged release on `main`). Older
preview tags and unreleased pre-`v0.x` commits are not supported.

The product surface this policy covers, for code that lives in
*this* repository:

- The Rust workspace under `crates/`, including the edge VM image
  binary (`sng-edge`), the endpoint client binary (`sng-agent`),
  and every shared library crate (`sng-core`, `sng-pal`,
  `sng-comms`, `sng-policy-eval`, `sng-telemetry`, `sng-fw`,
  `sng-ips`, `sng-dns`, `sng-swg`, `sng-ztna`, `sng-sdwan`,
  `sng-updater`).
- The wire protocol described in
  [`ARCHITECTURE.md`](./ARCHITECTURE.md) §10 (the SN360 native
  protocol over TLS 1.3, HTTP/2, and MessagePack).
- The signed policy bundle / signed update manifest format
  (Ed25519 over a canonical MessagePack payload).

The SN360 SaaS control plane (admin UI, MSP portal, tenant +
identity service, policy graph compiler, telemetry pipeline,
REST API + integration gateway) lives in the sibling
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
repo and is covered by that repo's `SECURITY.md`. Reports that
straddle both surfaces — e.g. a wire-protocol issue that affects
both the gateway client and the control-plane endpoint — should
be sent to the address below; we will route internally.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion thread
for security vulnerabilities.**

Send the report to **[security@uney.com](mailto:security@uney.com)**.
Encrypt sensitive details with our PGP key (fingerprint published
at [https://uney.com/.well-known/security.txt](https://uney.com/.well-known/security.txt))
if the issue involves credentials, exploit code, or PII.

A useful report includes:

- A short description of the vulnerability and its impact.
- The affected SNG component (`sng-edge`, `sng-agent`, or a
  named library crate) and the version (`sng-edge --version`,
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
GitHub Security Advisory, changelog entry) credit the reporter
unless you ask to remain anonymous.

## Out of scope

The following are not vulnerabilities for the purposes of this
policy:

- Operator misconfiguration that disables a security feature (for
  example running `sng-edge` with `dns.filter_chain: []` or
  disabling TLS inspection for every flow). The defaults shipped
  in each binary's reference config are the supported
  configuration.
- Theoretical issues that require an already-compromised
  control-plane database, an already-compromised edge VM, or
  arbitrary code execution on the host running `sng-agent` — an
  attacker with those primitives is outside the product's threat
  model.
- False positives or false negatives in the bundled policy
  templates, the DNS reputation feed, the SWG URL category feed,
  or the IDS/IPS Suricata rule pack. Tune those in your tenant's
  policy graph rather than reporting baseline coverage as a
  vulnerability.
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
- Postgres row-level security (RLS) is the **only** tenant
  isolation boundary on the control plane side; see the
  control-plane repo for the role / GUC contract.
- All telemetry is metadata-first; payloads are dropped at the
  edge unless the tenant's policy bundle opts in for that flow
  class.

If you find a way to bypass any of these invariants, that is a
security vulnerability and we want to hear about it.

## Hall of fame

Maintained on our website at
[https://sn360.com/security/credits](https://sn360.com/security/credits)
once we have credited reports to publish.
