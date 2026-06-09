# Customer-Managed Keys (CMK) — All-Tier Architecture

Status: design + control-plane core landed (WS9). Cloud KMS adapters
are wired in `cmd/sng-control` and tracked separately.

## 1. Why this exists

[`ARCHITECTURE.md`](../ARCHITECTURE.md) §8 lists two key invariants:

- **Region-aware KMS** — "keys live in the tenant's pinned region;
  cross-region replication is opt-in."
- **Customer-managed keys** — "available on higher tiers (Data Guard);
  HSM / external KMS bindings supported."

In the shipped code those promises were uneven. The control plane has a
real per-tenant envelope-encryption seam — `policy.PrivateKeyWrapper`
(`internal/service/policy/keys.go`) with an AES-256-GCM implementation
(`internal/service/policy/wrapper_aesgcm.go`) — but it protects exactly
one secret (the per-tenant Ed25519 policy-signing seed), it is keyed by
a single platform master, and it has no concept of a *customer*-owned
key or of the tenant's residency region. The other planes that persist
regulated tenant data — telemetry (ClickHouse, Tier 2), cold archives
(S3, Tier 3; `internal/service/telemetry/s3/archiver.go`), policy
bundles, RBI artifacts — rely on storage-level encryption (Postgres
TDE, S3 SSE, ClickHouse at-rest) under platform-held keys.

WS9 generalises CMK into a **tier-independent envelope scheme** with one
abstraction, `residency.TenantKeyProvider`, that every plane uses
identically. A tenant on any tier can keep using the platform-managed
key (the default, zero-config path) or bind a customer-managed key in
their own cloud KMS — AWS KMS, Azure Key Vault, or GCP KMS — without any
per-plane special-casing.

This document describes the abstraction, the envelope-encryption data
flow, the residency binding that makes it safe for the 5,000-tenant
multi-tenant SaaS, and the wiring boundary between the SDK-free core and
the cloud adapters.

## 2. Where it lives, and why in `residency`

The core lands in `internal/service/residency/`:

| File | Contents |
|---|---|
| `keyprovider.go` | `TenantKeyProvider` interface, value types (`TenantKeyRef`, `DataKey`, `WrappedDataKey`, `EncryptionContext`), ref validation, and the `KeyProviderRegistry`. SDK-free. |
| `keyprovider_local.go` | `LocalKeyProvider` — the AES-256-GCM implementation used as the production `platform` tier and as a faithful KMS test double. |
| `cmk.go` | `CMKService` — tenant KEK resolution, fail-closed residency region binding, tenant-bound encryption context, provider dispatch. |

CMK is co-located with residency, not given its own package, because the
two are inseparable: **a customer-managed key must live in the tenant's
designated data-residency region.** The residency package already owns
the region vocabulary (`Region`, `Normalize`, `ValidateRegion`), the
jurisdiction catalog (`catalog` in `residency.go`), and the fail-closed
write gate (`EnforceWrite`). The CMK region binding is the same
`EnforceWrite` check applied to the KEK's region, so putting CMK
anywhere else would either duplicate that logic or create an import
cycle. The cold-storage archiver already depends on residency through a
narrow one-method `ResidencyGuard` interface
(`internal/service/telemetry/s3/archiver.go`); CMK follows the same
"residency owns region-correctness" principle.

## 3. The envelope-encryption model

CMK uses standard two-level envelope encryption:

```
                tenant CMK / platform master  (KEK — never leaves the KMS)
                          │  wrap / unwrap
                          ▼
   per-object Data Encryption Key (DEK, 32-byte AES-256)
                          │  encrypt / decrypt
                          ▼
        tenant data  (telemetry batch, cold archive object,
                      policy bundle, RBI artifact)
```

- The **KEK** (key-encryption key) is the tenant's CMK in their cloud
  KMS, or the platform master for the default tier. It never leaves the
  KMS boundary; the control plane only ever asks the KMS to wrap or
  unwrap a DEK.
- The **DEK** (data-encryption key) is a fresh 32-byte AES-256 key
  minted per object/scope. The plane encrypts data with the plaintext
  DEK, persists the *wrapped* DEK next to the ciphertext, and zeroizes
  the plaintext DEK.
- To read, the plane hands the wrapped DEK back to the KMS to unwrap,
  decrypts, and zeroizes again.

The 32-byte DEK and AES-256-GCM layout (`nonce || ciphertext || tag`,
12-byte random nonce per NIST SP 800-38D §8.2.1) are deliberately
identical to the existing `AESGCMWrapper`, so the cold-archive sealing
and the CMK envelope share one cryptographic shape.

### 3.1 The interface

```go
// internal/service/residency/keyprovider.go
type TenantKeyProvider interface {
    Kind() KeyProviderKind
    GenerateDataKey(ctx, ref TenantKeyRef, ec EncryptionContext) (DataKey, error)
    UnwrapDataKey(ctx, ref TenantKeyRef, wrapped WrappedDataKey, ec EncryptionContext) ([]byte, error)
}
```

`GenerateDataKey` maps directly onto the native KMS primitive every
target provider exposes (AWS `kms:GenerateDataKey`, GCP
`GenerateRandomBytes` + `Encrypt`, Azure generate-then-`wrapKey`): the
KMS returns the DEK in plaintext *and* wrapped form in one call, so the
DEK is born under the CMK and the platform never chooses it.
`UnwrapDataKey` maps onto `kms:Decrypt` / `unwrapKey` / `Decrypt`.

### 3.2 Value types

`TenantKeyRef` is a validated handle to a tenant's KEK:

```go
type TenantKeyRef struct {
    TenantID uuid.UUID        // bound into every operation's AAD
    Kind     KeyProviderKind  // platform | aws_kms | azure_kv | gcp_kms
    Region   Region           // the KEK's region; for a CMK it MUST equal residency
    KeyURI   string           // ARN / Key Vault key URL / GCP resource name
}
```

`Validate()` enforces a provider-specific `KeyURI` shape with real
regexes so a misconfiguration (e.g. an AWS ARN pasted into an Azure
tenant record) fails loudly at config time, not at the first production
unwrap:

| Kind | `KeyURI` shape |
|---|---|
| `aws_kms` | `arn:aws:kms:<region>:<acct>:key/<id>` or `…:alias/<name>` |
| `azure_kv` | `https://<vault>.vault.azure.net/keys/<name>[/<version>]` (also `managedhsm.azure.net`) |
| `gcp_kms` | `projects/<p>/locations/<loc>/keyRings/<kr>/cryptoKeys/<k>[/cryptoKeyVersions/<n>]` |
| `platform` | empty (default master) or an opaque key id |

`WrappedDataKey` is what planes persist: `{Kind, KeyURI, Ciphertext,
KeyVersion}`. It records the KEK that produced it so a later unwrap
routes to the right provider/key **even after the tenant rotates to a
different KEK** (see §5).

`DataKey` carries `{Plaintext, Wrapped}` and exposes `Zeroize()`; the
package-level `Zeroize([]byte)` is the best-effort wipe used throughout.

### 3.3 Encryption context (AAD) and tenant binding

Every wrap/unwrap binds an `EncryptionContext` (a small string map) as
additional authenticated data. This is cryptographically enforced by
all three target KMSes (AWS KMS *encryption context*, GCP
*additionalAuthenticatedData*, Azure via the local AEAD AAD) and by the
`LocalKeyProvider`'s GCM AAD: unwrap fails unless the identical context
is supplied.

`CMKService` **always** stamps the authoritative `tenant_id` into the
context (`ContextTenantID`), and rejects a caller that pre-set a
conflicting value. This is the cryptographic backstop to the Postgres
RLS / NATS / S3-prefix tenant isolation described in
[`SECURITY.md`](../SECURITY.md) "Defense-in-depth for tenant isolation":
even on the *shared platform KEK*, a DEK wrapped for tenant A cannot be
unwrapped for tenant B, because the AAD carries A's UUID. Callers may
add their own scope keys (e.g. `plane=cold_storage`) for finer binding.

## 4. The residency binding (fail-closed)

`CMKService.GenerateDataKey` enforces, in order:

1. **Resolve** the tenant's `TenantKeyRef` via the `CMKResolver`
   (production: tenant record columns). A resolver error fails closed —
   we never fall back to plaintext or silently to the platform key. A
   zero-`Kind` ref means "no CMK configured" and resolves to the
   `platform` provider (CMK is opt-in, exactly like residency).
2. **Override** `ref.TenantID` with the requested tenant — a resolver is
   never trusted to bind a ref to a different tenant.
3. **Validate** the ref (`§3.2`).
4. **Region-bind** (the crux): if the ref is a CMK and the tenant has a
   designated residency region, require the KEK's region to equal it via
   `EnforceWrite(designated, ref.Region, PlaneKeyManagement)`. A
   mismatch returns `ErrResidencyViolation` and a zero `DataKey`. This
   guarantees key material for a tenant pinned to, say, `eu-central-1`
   (DE, BDSG/GDPR) is wrapped by a KEK that physically lives in
   `eu-central-1` — the key never leaves the jurisdiction the data is
   pinned to. The platform master is exempt (it is a control-plane
   global key, not tenant data pinned to a jurisdiction; the *data* it
   protects is still residency-guarded at the data plane).
5. **Dispatch** to the registry-resolved provider. An unwired provider
   kind returns `ErrUnknownProvider` — fail-closed, never a downgrade.

`PlaneKeyManagement` is a residency plane added for this check. It is
deliberately **not** persisted to the `residency_audit` table —
migration `046_residency_audit` constrains `plane IN ('telemetry',
'policy_bundle', 'cold_storage')` — so a key-binding rejection is
surfaced as a `Violation` and logged structurally
(`slog.WarnContext`), while data-plane residency rejections keep their
durable audit row. Admin-initiated CMK changes are audited through the
platform audit log on the API path.

## 5. Read path and rotation

`UnwrapDataKey` intentionally differs from the write path:

- It routes to the provider named by **`wrapped.Kind`**, not the
  tenant's *current* KEK. A DEK wrapped last year under the platform
  master must still decrypt after the tenant adopts an AWS CMK this
  year. The wrapped envelope is self-describing; the read follows it.
- It does **not** re-check the residency region binding. The key
  already exists; re-validating residency on read would break
  legitimate decryption of historical data after a residency change.
  Residency is enforced where data and keys are *written*.

This makes KEK rotation a pure write-path change: point the tenant's
ref at the new KEK and new writes use it; old objects keep their
self-describing wrapped DEKs and decrypt against the historical KEK as
long as it remains accessible in the KMS. It mirrors the policy
signing-key rotation model (`KeyService.Rotate` in
`internal/service/policy/keys.go`), where old public keys stay published
so pre-rotation bundles still verify.

## 6. The platform tier and the test double

`LocalKeyProvider` (`keyprovider_local.go`) is a real AES-256-GCM
implementation, not a stub. It serves two production-grade roles:

- **The `platform` tier** — the default, no-CMK path. The platform
  master key is delivered via a sealed secret / KMS-decrypted env (never
  on disk in plaintext), exactly as `policy.LoadAESGCMMasterFromEnv`
  loads the policy wrapper master today. It holds a keyring (a default
  key plus optional named keys) so platform-master rotation is a
  keyring entry, addressed by `KeyURI`.
- **A KMS test double** — constructed with `Kind()` reporting any
  provider, it enforces the encryption-context AAD exactly as the cloud
  KMSes do, letting `CMKService` and every data-plane integration be
  exhaustively unit-tested with no cloud account. The package tests
  cover roundtrip, wrong-AAD rejection, ciphertext tamper, kind
  mismatch, cross-tenant unwrap rejection, region-binding fail-closed,
  unknown-provider fail-closed, and rotation across providers.

## 7. Wiring boundary: cloud KMS adapters

The residency package imports **no** cloud SDK, matching the repo
convention where pure service packages stay SDK-free and the concrete
backends are wired at the edge:

- `compliance.ObjectStore` is an interface; the S3 implementation lives
  in `internal/service/compliance/s3store.go`.
- `telemetry/s3` defines its own `ArchiverAPI` and `ResidencyGuard`
  rather than importing the AWS SDK or the residency service directly.
- `policy.PrivateKeyWrapper` is an interface with in-tree
  `Passthrough`/`AESGCM` impls; the KMS variants are wired in
  production.

The AWS KMS / Azure Key Vault / GCP KMS adapters each implement the
three-method `TenantKeyProvider` against their SDK and are registered in
`cmd/sng-control` at startup:

```go
reg, _ := residency.NewKeyProviderRegistry(
    platformProvider,    // residency.LocalKeyProvider, Kind()=platform
    awskms.New(cfg),     // Kind()=aws_kms
    azurekv.New(cfg),    // Kind()=azure_kv
    gcpkms.New(cfg),     // Kind()=gcp_kms
)
cmk, _ := residency.NewCMKService(tenantRefResolver, regionResolver, reg, logger)
```

Each adapter is a thin shim: `GenerateDataKey` → the provider's
generate-data-key call with the tenant id (and caller scope) as
encryption context; `UnwrapDataKey` → the provider's decrypt with the
same context. The DEK never leaves the adapter except as the in-memory
plaintext the calling plane immediately uses and zeroizes. The only
dependency the registry imposes is at-startup validation: duplicate or
empty `Kind()` is rejected so a misconfiguration is caught before the
first request.

A provider kind that is configured on a tenant but not registered at
startup yields `ErrUnknownProvider` at use — fail-closed by
construction, so a half-rolled-out KMS integration degrades to "key
operations rejected", never to "data written unencrypted".

## 8. Per-tier posture

| Tier | KEK default | CMK option |
|---|---|---|
| Workforce Access / Core Branch | `platform` master, region-aware | opt-in CMK (aws/azure/gcp), region-bound |
| Data Guard | `platform` master, region-aware | CMK is the headline feature; same interface, no separate code path |

The point of the all-tier design is that **there is no separate code
path per tier**. A tier policy decides whether a tenant is *allowed* to
configure a CMK; the envelope mechanism, the residency binding, and the
tenant-AAD isolation are identical whether the KEK is the platform
master or a customer's HSM-backed CMK. That is what keeps the operational
burden flat ("no ops") across 5,000 tenants: one seam, one set of
invariants, one test surface.

## 9. Security invariants (summary)

1. **Fail-closed everywhere** — resolver error, invalid ref, unknown
   provider, or cross-region CMK all reject; none degrade to plaintext.
2. **Residency-bound CMK** — a customer key must live in the tenant's
   designated region (`EnforceWrite`); enforced on write.
3. **Tenant-bound AAD** — `tenant_id` is cryptographically bound to
   every DEK, backstopping RLS/NATS/S3 isolation even on a shared KEK.
4. **KEK never in the control plane** — only wrap/unwrap cross the KMS
   boundary; plaintext DEKs are short-lived and zeroized.
5. **Self-describing envelopes** — `WrappedDataKey` records its KEK, so
   rotation and provider migration never strand historical data.
6. **SDK-free, exhaustively testable core** — cloud adapters live at the
   wiring edge; the envelope logic is unit-tested against an in-process
   AEAD double.
