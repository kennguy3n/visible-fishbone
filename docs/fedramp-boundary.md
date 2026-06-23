# FedRAMP Authorization Boundary & Data-Flow Definition

Status: boundary definition (WS9). This defines the authorization
boundary and the data flows across it for a prospective FedRAMP
authorization of the ShieldNet Gateway (SNG) SaaS. It is grounded in the
components that actually exist in this repo and the sibling SN360 repos;
where a FedRAMP control depends on something not yet present (FIPS
140-validated modules, a dedicated government region), it is called out
as a gap rather than asserted.

## 1. Purpose

The authorization boundary is the single most scrutinized artifact in a
FedRAMP package: it enumerates **everything the CSP is responsible for**,
every **external service** it connects to, and every **data flow** that
crosses the boundary. This document defines that boundary for SNG so the
SSP (System Security Plan) and the boundary diagram can be derived from
real architecture, not aspiration.

## 2. System description

SNG is a multi-tenant SaaS network-security platform (NGFW, IDS/IPS,
SWG with inline DLP / AI governance / RBI, DNS security, ZTNA
agent-based + clientless browser, SD-WAN, DEM, CASB/DLP) for ~5,000 SME
tenants. It has
three deployable software elements (see
[`ARCHITECTURE.md`](../ARCHITECTURE.md)):

- **`sng-control`** — Go control plane (API + workers), the SaaS core.
- **`sng-edge`** — Rust edge VM appliance (customer premises / cloud).
- **`sng-agent`** — Rust endpoint client (managed devices).

## 3. The authorization boundary

### 3.1 Inside the boundary (CSP responsibility)

The components the CSP builds, operates, and authorizes:

| Component | Role | Repo location |
|---|---|---|
| `sng-control` API + worker | Tenant/policy/telemetry/compliance services | `cmd/sng-control`, `internal/` |
| `sng-migrate` | One-shot schema migration runner | `cmd/sng-migrate`, `migrations/` |
| Postgres (RLS) | Authoritative tenant config/state; **primary tenant isolation** | `internal/repository/postgres` |
| ClickHouse | Tier-2 searchable telemetry (per region) | ARCH §7.2 |
| Object storage (S3-compatible) | Tier-3 cold archive + WORM compliance evidence | `compliance/s3store.go`, `telemetry/s3` |
| NATS | Per-tenant subject bus (`sng.<tenant>.…`) | ARCH §6, §7.4 |
| KMS/HSM (platform master) | KEK for envelope encryption + key wrapping | [`cmk-architecture.md`](./cmk-architecture.md) |
| Signing infrastructure | Ed25519 policy/update/release/evidence signing | [`key-ceremony.md`](./key-ceremony.md) |

The **`sng-edge`** and **`sng-agent`** binaries run in the *customer's*
environment. Their **management interface** (the SN360 native protocol
connection back to the control plane) is inside the boundary; the
customer's premises/devices themselves are a customer responsibility
documented in the SSP's customer-responsibility matrix.

### 3.2 At the boundary edge (entry/exit points)

- **Operator OIDC gateway** — in production the control plane has **no
  in-process OIDC verifier**; operator identity is terminated at a
  gateway that translates an authenticated OIDC session into a
  credential the control plane accepts (`SECURITY.md` §"Operator
  authentication in production"). This gateway is a boundary component
  and an external interconnection to the IdP.
- **Tenant/edge API** — REST surface (`api/openapi.yaml`) authenticated
  by per-tenant API keys (`X-SNG-API-Key`).
- **SN360 native protocol listener** — TLS 1.3 + HTTP/2 + MessagePack;
  mutual TLS with device-bound Ed25519 identities (ARCH §10,
  `SECURITY.md`).

### 3.3 External services & interconnections (outside the boundary)

Each is an interconnection requiring an agreement / inherited
authorization in the FedRAMP package:

| External service | Relationship | Boundary treatment |
|---|---|---|
| IaaS provider (compute/network/storage) | Hosts the SaaS | **Inherited** controls via the provider's FedRAMP authorization (subservice org) |
| Customer cloud KMS (AWS KMS / Azure KV / GCP KMS) | Holds tenant CMKs | Interconnection; key material stays in the customer's KMS (see §5) |
| Identity Provider (OIDC) | Operator authN | Interconnection at the OIDC gateway |
| [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | Shared tenant identity, policy graph, telemetry; alert forwarding | SN360-family interconnection (ARCH §9) |
| [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent), [`sn360-agent-vm`](https://github.com/kennguy3n/sn360-agent-vm), [`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s) | Posture feed / telemetry correlation | SN360-family interconnections |

A complete boundary diagram is the union of §3.1 (inside), §3.2 (edge),
and §3.3 (external, with directional flows from §4).

## 4. Data flows across the boundary

### 4.1 Ingress — enforcement telemetry & posture (edge/endpoint → control plane)

```
sng-edge / sng-agent ──TLS 1.3, mTLS (device Ed25519), MessagePack──▶ control plane
   metadata-first flow records, verdicts, posture snapshots
        │
        ├─▶ NATS  sng.<tenant>.telemetry.*   (subject ACL per tenant)
        ├─▶ ClickHouse  (Tier 2, per region, RLS-equivalent partitioning)
        └─▶ S3  (Tier 3 cold archive, tenant_id/yyyy=/mm=/dd=, envelope-encrypted)
```

Payloads are **dropped at the edge** unless the tenant policy opts in for
a flow class (`SECURITY.md`); the default ingress is metadata, which
minimizes regulated-data exposure inside the boundary.

### 4.2 Egress — policy & update distribution (control plane → edge/endpoint)

```
control plane ──Ed25519-signed policy bundle / update manifest──▶ sng-edge / sng-agent
   verified before enforcement; unsigned/version-mismatched rejected;
   downgrade rejected by monotonic version (SECURITY.md)
```

### 4.3 Operator plane (operator → control plane)

```
operator ──OIDC──▶ gateway ──provisioned credential / asserted header──▶ control plane API
   every privileged action lands in the append-only audit log
```

### 4.4 Key-management flow (control plane ↔ KMS/HSM)

```
control plane ──GenerateDataKey / wrap / unwrap (DEK only; KEK never leaves KMS)──▶ KMS/HSM
   encryption context binds tenant_id (cmk-architecture.md §3.3)
```

### 4.5 Persistence (control plane → data stores, all in-boundary)

Postgres (RLS), ClickHouse (partitioned), S3 (prefix-isolated + WORM for
evidence), each tenant-isolated per ARCH §7.4.

## 5. Data types & residency within the boundary

| Data type | Tier / store | Protection |
|---|---|---|
| Tenant config / policy graph | Postgres | RLS + GUC read-back (defense-in-depth, `SECURITY.md`) |
| Flow metadata / verdicts | ClickHouse (T2) | per-tenant partitioning + tokens |
| Cold event archive | S3 (T3) | prefix isolation + envelope encryption (CMK) |
| Compliance evidence | S3 | Ed25519-signed + object-lock COMPLIANCE (7y) |
| Signing keys / KEK | KMS/HSM | non-exportable; dual-control ceremony |
| Regulated tenant data (opt-in) | per residency designation | **data-residency enforcement** (`internal/service/residency`) — fail-closed `EnforceWrite` |

**Residency is a boundary property.** The residency service pins a
tenant's regulated data (telemetry, policy bundles, cold archives, RBI
artifacts) to a designated region and refuses cross-region writes
fail-closed. CMK extends this to key material: a tenant's KEK must live
in the same region as their data (`cmk-architecture.md` §4). For a
FedRAMP boundary this is what lets a US-region authorization boundary be
asserted cleanly — data and keys for an in-boundary tenant do not leave
the authorized region.

## 6. Cryptographic boundary

Per `SECURITY.md` §"Crypto and signing posture" and ARCH §8:

- **In transit**: TLS 1.3 only (`rustls`) on the native protocol; mTLS
  with device-bound Ed25519 identities.
- **At rest**: AES-256-GCM envelope encryption (32-byte DEK, 12-byte
  nonce) under KMS/HSM-held KEKs; per-tenant CMK option.
- **Integrity/authenticity**: Ed25519 over canonical MessagePack/JSON
  for bundles, manifests, and compliance evidence.

## 7. FedRAMP-specific gaps (honest)

These are required for an actual authorization and are **not** yet
satisfied by the current code; they are tracked, not asserted:

1. **FIPS 140-2/3 validated crypto modules.** The product uses Go stdlib
   `crypto/ed25519` + AES-GCM and Rust `rustls`. FedRAMP requires
   *validated* modules (e.g. a FIPS-validated provider / boringcrypto
   build, validated HSM). **Gap**: select and build against validated
   modules for the in-boundary deployment.
2. **Authorized region / government cloud.** The boundary must sit in a
   FedRAMP-authorized region of the IaaS provider. The residency
   catalog (`residency.go`) lists commercial regions (SG/TH/MY/AE/DE/CH)
   — **gap**: add the authorized US gov/commercial region and pin the
   boundary to it.
3. **Continuous monitoring (ConMon).** Monthly vulnerability scans, POA&M
   management, and inventory reporting. The compliance evidence pipeline
   (`compliance/`) is a strong substrate but ConMon artifacts are
   broader. **Gap**: map ConMon deliverables onto/around the evidence
   pipeline.
4. **Boundary diagram + SSP control narratives** for the full
   NIST 800-53 baseline (Low/Moderate). This document seeds the boundary
   and data-flow sections; the remaining control families are GRC work.
5. **Subservice org coverage.** The IaaS provider's FedRAMP
   authorization must be referenced (inherited controls) and the
   customer-responsibility matrix completed for `sng-edge`/`sng-agent`
   premises.

## 8. Summary

The architecture already gives a FedRAMP boundary most of its hard
parts: a clearly separable control plane, defense-in-depth tenant
isolation, signed artifacts, envelope encryption with region-bound keys,
fail-closed data residency, and signed immutable compliance evidence.
The remaining work is FedRAMP-specific (validated crypto modules, an
authorized region, ConMon, and the SSP/GRC narrative) — additive, not a
redesign. This document is the authoritative source for the boundary and
data-flow inputs to that package.
