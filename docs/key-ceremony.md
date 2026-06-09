# Ed25519 Signing-Key Ceremony & Lifecycle

Status: operational runbook + control-plane reference (WS9).

This document is the authoritative lifecycle for the Ed25519 signing
keys the ShieldNet Gateway (SNG) control plane holds, and the
HSM-backed, dual-control ceremony that governs the high-value ones. It
is grounded in the code that already implements key state in this repo —
it documents the operating procedure around that code, not an invented
scheme.

## 1. Scope: which keys

SNG relies on several distinct Ed25519 keys (see
[`SECURITY.md`](../SECURITY.md) "Crypto and signing posture" and
[`ARCHITECTURE.md`](../ARCHITECTURE.md) §8). They fall into two
ceremony classes:

| Key | Purpose | Holder | Ceremony class |
|---|---|---|---|
| **Per-tenant policy-signing key** | Signs compiled policy bundles the edge/endpoint verify before enforcing | Control plane, per tenant | Automated (this doc §6) |
| **Evidence-bundle signing key** | Signs SOC2 evidence bundles for 7-year archival | Control plane (compliance) | Automated, but escrowed (§7) |
| **Update-manifest signing key** | Signs `sng-edge`/`sng-agent` update manifests; downgrade-rejected | Release infrastructure | **Dual-control HSM ceremony (§4–5)** |
| **Release artifact signing key** | Signs binaries/images/installers (SLSA provenance, [`ci.md`](#)) | Release infrastructure | **Dual-control HSM ceremony (§4–5)** |
| **Device-bound identity key** | mTLS identity of each edge VM / endpoint | The device's TPM/TEE | Device-generated, out of scope |
| **Platform KEK master / tenant CMK** | Wraps per-object DEKs ([`cmk-architecture.md`](./cmk-architecture.md)) | KMS/HSM | KMS-managed (§8) |

The **device-bound identity keys** are generated *on the device* in its
hardware key store (Windows TPM, macOS Secure Enclave, Linux kernel
keyring / TPM 2.0) and the private half never leaves it — there is no
ceremony to run, so they are out of scope here.

## 2. The code that backs this lifecycle

The per-tenant policy-signing-key lifecycle is implemented by
`KeyService` in `internal/service/policy/keys.go`, backed by
`repository.PolicySigningKeyRepository`:

- Keys are Ed25519, generated with stdlib `crypto/ed25519` over
  `crypto/rand` (`generateKey`), so the math is the same FIPS-compatible
  baseline the rest of the SN360 family uses.
- A tenant has **at most one `active` key at a time**, enforced by a
  partial unique index in the repository; older keys move to `rotated`
  (still valid for verification) or `revoked` (must be refused).
- Every state change (`signing_key_created`, `_rotated`, `_revoked`) is
  written to the append-only audit log (`appendAudit`), so the rotation
  trail is reconstructible without scraping the database.
- Private seeds are persisted only through the `PrivateKeyWrapper` seam
  (`PassthroughWrapper`, `AESGCMWrapper`), so at-rest protection is
  pluggable — see §8.

The evidence-bundle signer is `compliance.Signer`
(`internal/service/compliance/evidence.go`): `NewSigner` accepts a
32-byte seed or 64-byte expanded key; `GenerateSigner` mints one; `Sign`
produces the detached Ed25519 signature stored on the `EvidenceBundle`.

The ceremony below wraps these primitives with the operational controls
(HSM, dual control, escrow) the high-value keys require.

## 3. Ceremony principles

1. **Private keys for release/update signing are generated *inside* an
   HSM and are non-exportable.** The ceremony produces a public key and
   an HSM key handle; the private scalar never exists in host memory.
2. **Dual control / split knowledge.** No single person can generate,
   activate, rotate, or revoke a high-value key. Two authorized
   custodians from different functions (Security + Release) must each
   present their factor.
3. **Everything is witnessed and recorded.** Each ceremony has a third
   person as witness/scribe; the signed minutes are archived next to the
   audit-log entries the code emits.
4. **Fail-closed.** A ceremony that cannot complete its verification
   step (e.g. the freshly generated public key does not verify a test
   signature) is aborted; no partially provisioned key is left active.

## 4. Roles

| Role | Count | Responsibility |
|---|---|---|
| Key Custodian A (Security) | 1 | Holds HSM PED key / smartcard factor 1; initiates the ceremony |
| Key Custodian B (Release Eng) | 1 | Holds factor 2; co-authorizes every privileged HSM operation |
| Ceremony Witness/Scribe | 1 | Records minutes, verifies the script was followed, co-signs the record |
| Approver (Security lead) | 1 | Pre-authorizes the ceremony in the change ticket; not present at the HSM |

The HSM is configured for **`m of n = 2 of 3`** custodian quorum so a
single absent custodian does not block an emergency rotation (the third
custodian is a break-glass holder, sealed).

## 5. Ceremony procedures (update-manifest & release keys)

### 5.1 Generation (initial provisioning)

1. Approver opens a change ticket; records the key's intended purpose,
   label, and rotation interval.
2. Custodians A and B authenticate to the HSM (2-of-3 quorum). The
   witness confirms the HSM is the expected device (serial, attestation).
3. Generate the Ed25519 keypair **on the HSM**, marked non-exportable,
   with a label encoding purpose + generation date + monotonically
   increasing key-generation index.
4. Export **only the public key**. Verify it by having the HSM sign a
   fixed test vector and verifying the signature against the exported
   public key on a separate host. A verification failure aborts the
   ceremony.
5. Publish the public key to the verification trust store (the edge /
   endpoint update verifier; the release provenance verifier). For
   policy-bundle and evidence keys the equivalent step is registering the
   public key via the publication endpoint that `KeyService.List`
   serves so receivers can verify.
6. Record the key handle, public key, label, and generation index in the
   signed ceremony minutes. Archive minutes with the audit-log entry.

### 5.2 Activation

A newly generated signing key is **staged**, not active. Activation is a
separate dual-control step so a key can be pre-provisioned and verified
before it starts signing. For the control-plane policy keys this maps to
`KeyService.CreateInitial` / `RotateOrCreate` setting status `active`
under the one-active-key invariant.

### 5.3 Rotation

Routine rotation runs on the interval recorded at generation (default:
release/update signing keys annually; policy-signing keys on-demand or
per tenant policy). Rotation is **make-before-break**:

1. Run the §5.1 generation ceremony for the successor key; publish its
   public key alongside the incumbent's.
2. Flip signing to the successor (HSM label / `KeyService.Rotate`, which
   atomically moves the incumbent to `rotated` and inserts the successor
   as `active` in one transaction — see the TOCTOU-hardened
   `EnsureKey` / `RotateOrCreate` paths in `keys.go`).
3. **Keep the predecessor's public key published** until every artifact
   it signed has expired or been re-signed. Edge/endpoint verifiers must
   still accept `rotated`-key signatures; they must reject `revoked`
   ones. This mirrors the bundle-verification contract in
   [`SECURITY.md`](../SECURITY.md): "Unsigned or version-mismatched
   bundles are rejected", downgrade is rejected by monotonic version.

### 5.4 Revocation (incident)

Revocation is for compromise, not routine end-of-life:

1. Any custodian or the Security lead can *declare* an incident and
   initiate revocation; the privileged HSM revoke still requires the
   2-of-3 quorum.
2. Mark the key `revoked` (`KeyService.Revoke`, audited as
   `policy.signing_key_revoked`). Receivers MUST refuse artifacts signed
   by a revoked key from that point.
3. **No automatic re-provisioning.** This is encoded in the code: after
   the only active key is revoked, `KeyService.EnsureKey` refuses to
   lazy-create and returns `ErrNotFound` with the
   "admin rotation required" hint — distinguishing "no key yet" from
   "key was revoked" so a revocation incident cannot be silently papered
   over by an auto-create. An admin must run an explicit rotation
   ceremony to resume signing.
4. Re-sign or quarantine every artifact the revoked key signed, per the
   incident's blast-radius assessment.

## 6. Per-tenant policy-signing keys (automated lifecycle)

These are high-volume (one+ per tenant across 5,000 tenants) and are
**not** individually ceremonied — that would not scale and would be the
opposite of "no ops". Instead the controls are structural and live in
code:

- **Generation / rotation / revocation** are the `KeyService` methods in
  §2, each audited.
- **At-rest protection** of the seed is the `PrivateKeyWrapper`. In
  production this is the KMS/HSM-backed wrapper (§8), so even the
  per-tenant seeds are wrapped under an HSM-rooted master rather than
  living in the database in the clear.
- **One active key per tenant** is a database invariant (partial unique
  index), not a convention.
- **Verification continuity**: `KeyService.List` exposes the full
  rotation history (active + rotated + revoked public keys) so a
  receiver can verify any bundle it still holds.

The ceremony that *does* apply to this class is the **master-key
ceremony** (§8) that provisions the KEK wrapping all these seeds.

## 7. Escrow

Escrow applies only to keys whose **loss would destroy access to data we
are legally required to retain** — principally the evidence-bundle
signing key (SOC2 evidence has a 7-year retention obligation;
`compliance.DefaultRetentionYears`) and any data-at-rest KEK.

- **Signing keys are not escrowed for signing.** We never escrow a
  release/update private key — its loss is recoverable by rotating to a
  new key and re-publishing the public half. Escrowing it would only
  enlarge the attack surface.
- **Verification material is "escrowed" by publication.** Every public
  key is durably published (trust store / `KeyService.List`), so the
  ability to *verify* historical artifacts survives any custodian loss.
- **KEK escrow** is delegated to the KMS/HSM's own backup mechanism
  (AWS KMS key policies + multi-Region keys, Azure Key Vault
  backup/restore, GCP KMS) under the tenant's control for a CMK, or
  platform-operated for the platform master. Escrowed KEK backups are
  themselves dual-control and region-bound: a `eu-central-1` tenant
  CMK's escrow copy stays in-jurisdiction, consistent with the residency
  binding in [`cmk-architecture.md`](./cmk-architecture.md) §4.

## 8. Platform master / CMK provisioning ceremony

The KEK that wraps per-object DEKs (and per-tenant signing seeds) is
provisioned per [`cmk-architecture.md`](./cmk-architecture.md):

- **Platform master**: generated inside the deployment's HSM/KMS,
  non-exportable, delivered to the control plane only as the ability to
  call wrap/unwrap (or, for the in-process `AESGCMWrapper` /
  `LocalKeyProvider`, as a 32-byte master from a sealed secret —
  `policy.LoadAESGCMMasterFromEnv` — never on disk in plaintext).
  Rotation re-wraps on the next `KeyService.Rotate`, since AES-GCM
  ciphertext written under the old master cannot be opened under the new
  one (the master change invalidates the AAD-bound ciphertext by
  design).
- **Tenant CMK**: generated in the *tenant's* cloud KMS under their own
  ceremony; SNG only stores a `TenantKeyRef` (provider kind, region,
  key URI). The region-binding check (`EnforceWrite` in
  `CMKService.enforceRegionBinding`) refuses a CMK outside the tenant's
  residency region, so the customer's own ceremony cannot accidentally
  place key material out of jurisdiction.

## 9. Audit & evidence

Every automated key-state change emits an append-only audit-log entry
(`policy.signing_key_{created,rotated,revoked}`) with key id, algorithm,
status, and public key. Every manual ceremony produces signed minutes
referencing the corresponding audit entry / change ticket. Together
these satisfy the SOC2 **CC6.1** (logical access to keys),
**CC6.2/CC8.1** (change management of signing material), and **CC7.1**
(monitoring of key events) evidence requirements mapped in
[`compliance-certifications.md`](./compliance-certifications.md).
