# Traffic Classification and Steering Framework

> Architecture document for the ShieldNet Gateway (SNG) traffic
> classification engine. Companion to `ARCHITECTURE.md` §4.4a.

## 1. Motivation

A naive "inspect everything in the cloud" policy is fatal for SME
economics: at 100% cloud-proxied traffic, even a 50-user tenant
generates enough TLS-decrypt CPU and egress bandwidth to wipe out
the gross margin SNG depends on.

The classification engine inverts the default: every flow is
slotted into one of six **traffic classes** and steered to the
**cheapest enforcement path that still provides adequate
protection**. The result is the same security outcome as cloud
inspection for high-risk flows (~10-20% of traffic) while letting
the well-known 70-80% — Microsoft 365, Google, YouTube, OS
updates, etc. — bypass the cloud proxy entirely.

The framework is deployment-mode-aware. The same tenant policy
produces different steering actions for a branch with an edge VM
than for a home-office user behind the agent, because the set of
cost-effective enforcement points is different in each case.

## 2. The Six Traffic Classes

| Class | Protection Applied | Telemetry | Typical % of SME Traffic |
|---|---|---|---|
| `trusted_direct` | DNS verification + cert-pin + IP-range binding. **No** TLS decryption, **no** proxy. | Metadata only (5-tuple, bytes, SNI, app id, verdict) | 35-50% |
| `trusted_media_bypass` | DNS verification + cert-pin. Same as `trusted_direct` but tuned for high-bandwidth media/CDN flows that would saturate the proxy. | Metadata only; coarse-grained sampling | 20-30% |
| `inspect_lite` | DNS verification + URL category lookup. **No** TLS decryption. Used for top-Alexa domains, well-known CDNs, banking. | Metadata + URL-cat verdict | 10-20% |
| `inspect_full` | Full SWG: TLS decrypt, URL-cat, malware verdict, AV scan, IPS, DLP, content filtering. | Metadata + (optionally) decrypted payload, when tenant policy opts in. | 10-20% |
| `tunnel_private` | mTLS overlay to a tenant-private destination (ZTNA app, internal LOB system). No inspection — point-to-point encrypted. | Metadata + ZTNA decision record | 1-5% |
| `block` | Connection refused at the earliest possible enforcement point (DNS sink, edge drop, agent block). | Block event with reason | < 5% |

The class assignment for a flow is the **effective traffic class**
— the per-tenant override (if any), falling back to the global
app-registry classification, falling back to `inspect_full` when
no classification exists.

## 3. Steering Behavior by Deployment Mode

A traffic class names *what protection is appropriate*. The
deployment mode determines *where that protection is enforced*.

|  | `branch` (edge VM) | `hub` (inter-site) | `cloud_only` (no on-prem) | `home_office` (agent only) |
|---|---|---|---|---|
| `trusted_direct` | Edge ASIC fast-path. NGFW logs metadata, IPS skipped, SWG bypassed. | Same as branch when traffic terminates at hub. | Endpoint stub → direct internet egress. Agent verifies cert pin locally. | Direct internet egress from the host NIC; agent verifies cert pin + IP range. |
| `trusted_media_bypass` | Same as `trusted_direct` but logged at sampled rate to control telemetry cost. | Same as branch. | Direct egress, sampled telemetry. | Direct egress, sampled telemetry. |
| `inspect_lite` | Edge SWG: URL-cat hit only, no TLS-MITM, no AV scan. | Forwarded to spoke branch for SWG. | Endpoint sends DNS to cloud DNS proxy for category lookup; HTTPS itself goes direct. | Same as `cloud_only`. |
| `inspect_full` | Edge SWG: full TLS decrypt + AV + IPS. CPU stays on the customer's VM. | Forwarded to spoke branch (full SWG runs at the spoke). | Endpoint tunnels HTTPS to the regional cloud PoP for full inspection. | Same as `cloud_only`. This is the **only** class that pays full cloud-egress + decrypt cost. |
| `tunnel_private` | Edge SD-WAN overlay tunnel to the private destination. | Same as branch; hub may relay if the destination sits at another site. | Endpoint runs ZTNA client to the private destination directly. | Same as `cloud_only`. |
| `block` | Dropped at NGFW / DNS sink before the flow leaves the LAN. | Dropped at hub. | DNS sink at the endpoint resolver; if it bypasses DNS, edge / cloud agent drops the TCP SYN. | Same as `cloud_only`. |

The compiler emits one steering rule set per (deployment-mode,
traffic-class) pair into the relevant bundle:

- **Edge bundle** (`branch`, `hub`): full per-class table — DNS
  allowlists, SWG bypass lists, IPS skip lists, SD-WAN
  app-class mappings.
- **Endpoint bundle** (`cloud_only`, `home_office`,
  agent-on-managed): DNS verification lists + per-class steering
  decisions (which class goes direct vs. cloud proxy vs. tunnel).
- **Cloud bundle**: the accept list (only `inspect_full` and
  `tunnel_private` arrive here) plus the reject/redirect rules
  for traffic that should never have been sent to the proxy.
- **Mobile bundle**: ZTNA destinations + tunnel decisions only —
  no SWG or IPS classes, because the mobile platform doesn't
  carry that data path.

## 4. Safety Guarantees

A trusted class is only as safe as the binding from name to
identity. The framework enforces three layers before honoring a
`trusted_*` decision:

1. **DNS verification.** The endpoint / edge resolves the domain
   against a trusted DNSSEC-validating resolver. If resolution
   fails or returns SERVFAIL, the flow falls back to
   `inspect_full` (fail-closed).
2. **Cert-pin validation.** The TLS handshake's certificate
   chain is hashed and matched against the
   `app_registry.cert_pins` set for the app. A mismatch demotes
   the live flow to `inspect_full` and emits a
   `cert_pin_mismatch` event into the demotion engine.
3. **Domain-to-IP binding.** The destination IP must fall inside
   the `app_registry.ip_ranges` declared for the app. A
   mismatch is *especially* suspect for a trusted class because
   it suggests DNS spoofing or a tunneled exfiltration channel
   wearing a known-app SNI. Mismatch demotes the flow and
   feeds the demotion engine.

The fail-safe direction is always toward `inspect_full`. A
trusted classification can be demoted to inspect; an inspect
classification can never be silently promoted to trusted.

## 5. Demotion Rules

Demotion is the runtime response to evidence that a previously
trusted classification is currently unsafe. The demotion engine
(see `internal/service/appdb/demotion.go`) listens on four
signals:

| Trigger | Demotion Scope | TTL |
|---|---|---|
| Threat feed hit (NATS `sng.intel.dns`/`sng.intel.ip`) | Global, all tenants | Permanent until cleared by operator |
| Cert-pin mismatch ≥ N devices in time window | Global if ≥ M tenants observe; tenant-scoped otherwise | 24h auto-expire; operator confirm to make permanent |
| IP range mismatch | Tenant-scoped | 6h auto-expire |
| Baseline-model anomaly (exfil pattern on trusted app) | Tenant-scoped | 24h auto-expire |

Every demotion is:

- **Immediate.** Pushed via NATS subject `sng.appdb.demotions` to
  every edge / agent receiver subscribed to the tenant.
- **Audited.** Inserted into `audit_log` with action
  `app.demoted` and the trigger reason.
- **Operator-notifiable.** Fires the `app.demoted` webhook event
  on every subscribed endpoint.
- **Auto-expiring** (except threat-feed permanent demotions).
  When the TTL elapses the engine clears the override; the
  operator can confirm earlier to make the demotion permanent.

## 6. Cost Analysis

The cost difference between classes is the entire motivation for
the framework. Approximate per-GB egress + processing cost in a
cloud-only deployment:

| Class | Cloud Egress | Decrypt CPU | URL-Cat / AV | Net Cost / GB |
|---|---|---|---|---|
| `trusted_direct` | $0 (direct ISP egress) | $0 | $0 | ~$0.00 |
| `trusted_media_bypass` | $0 | $0 | $0 | ~$0.00 |
| `inspect_lite` | $0 (DNS lookup only) | $0 | ~$0.001 | ~$0.001 |
| `inspect_full` | ~$0.09 (typical AWS NAT) | ~$0.03 | ~$0.005 | ~$0.125 |
| `tunnel_private` | $0.01 (overlay only) | $0 | $0 | ~$0.01 |
| `block` | $0 | $0 | $0 | $0 |

For a 100-user tenant generating ~1 TB/month, a naive
"everything through the cloud" policy costs ~$125/mo just in
inspection cost. Smart classification with the default mix
(50% trusted, 25% media bypass, 15% inspect-full, 10% other)
brings that to ~$22/mo — an 82% reduction without compromising
the protection actually applied to risky traffic.

For branch deployments the saving accrues differently: the
edge VM's CPU budget is no longer overwhelmed by URL-cat lookups
for every YouTube chunk, and the SD-WAN MPLS bill is unchanged
because trusted classes egress directly from the local internet
circuit.

## 7. App Registry — Schema Overview

The classification database has two layers:

- **`app_registry`** — curated global database of well-known
  apps (Microsoft 365, Google Workspace, Zoom, Netflix, …),
  shipped as system-managed data and refreshed by a periodic
  sync job that pulls vendor-published endpoint lists.
- **`app_registry_overrides`** — per-tenant overrides allowing
  the operator to promote (e.g. trust an internally-vetted
  vendor) or demote (e.g. force a SaaS through `inspect_full`
  for compliance reasons) any classification.

Tenant resolution is left-fold: tenant override wins, otherwise
global registry wins, otherwise fall back to `inspect_full`.

The schema is defined in `migrations/008_app_registry.up.sql`;
RLS is enabled on `app_registry_overrides` following the same
`sng.tenant_id` GUC pattern as every other tenant-scoped table
(see `docs/deploy.md` for the RLS contract). The
`app_registry` table is intentionally **global** (no RLS) — it
is the same curated dataset for every tenant.

## 8. Vendor Endpoint Sync

Apps with a `metadata_url` (Microsoft publishes M365 endpoint
ranges, Google publishes Workspace SPF + IP lists, etc.) are
auto-refreshed by a periodic sync job
(`internal/service/appdb/sync.go`). The job:

1. Fetches the vendor URL on a 24h cadence.
2. Diffs the new endpoint set against the stored one.
3. On non-empty diff, updates `domains` / `ip_ranges` and
   stamps `updated_at`.
4. Emits an `app.synced` audit + webhook event so operators see
   trust-list movements without polling.

A failed sync does not invalidate the existing classification —
edges continue to use the last good list. Sustained sync
failures (≥ 3 attempts) fire `app.sync_failed` so the operator
can investigate.

## 9. Integration with the Policy Compiler

During bundle compilation (`internal/service/policy/service.go`
`Compile`), the policy compiler calls
`appdb.Service.CompileSteeringRules(tenantID, targetType)` and
embeds the resulting `SteeringRuleSet` into the bundle envelope
under the new `steering` section. Each enforcement target sees
the steering rules relevant to *its* enforcement domain:

- `edge` and `cloud` bundles receive the full SWG bypass list +
  full URL-cat skip list + SD-WAN app-class mapping.
- `endpoint` bundles receive DNS verification lists and the
  per-class steering decisions.
- `mobile` bundles receive only ZTNA destinations.

The compiler treats the steering section as deterministic
input: the bytes are sorted before serialisation so a no-op
recompile produces a byte-identical bundle and the agent's
ETag / If-None-Match short-circuit keeps holding.

## 10. Telemetry Visibility

Every flow event the edge / agent emits carries the
`traffic_class` it was steered into (added to
`schema.FlowEvent`). The ClickHouse `sng_telemetry` table grows
a `traffic_class` column (`LowCardinality(String)`) and the
`ORDER BY` includes the class so per-tenant cost dashboards can
roll up by class without a full scan.

Operators see, per tenant:

- Bytes per class per day.
- Apps generating the most `inspect_full` traffic (candidates
  for promotion).
- Cert-pin / IP-range mismatch counts (candidates for
  investigation).

This visibility feeds the AI policy-tightening suggestions in
Phase 5: *"App Foo accounts for 15% of your `inspect_full`
traffic and has been clean for 90 days; promote to
`trusted_direct`?"*

## 11. Failure Modes

| Mode | Behavior |
|---|---|
| `app_registry_overrides` row created with invalid `traffic_class_override` | Rejected at API boundary (DB CHECK constraint + service-layer validation). |
| `app_registry` row drift between vendor endpoint list and stored value | Detected by the sync job; corrected on next successful pull. Edges keep using last good list. |
| Demotion engine cannot reach NATS | Demotion still records in `audit_log` and `app_registry_overrides`; receivers pick it up at the next bundle pull (slower but consistent). |
| Resolver returns SERVFAIL for a `trusted_*` domain | Flow falls back to `inspect_full` (fail-closed). |
| Cert chain hash not in `cert_pins` | Flow demoted to `inspect_full`; `cert_pin_mismatch` event recorded. |
| Destination IP not in `ip_ranges` | Flow demoted to `inspect_full`; `ip_range_mismatch` event recorded. |
| Steering bundle compile fails | Policy compile returns an error; previous bundle stays live (atomic swap). Operator is paged via the existing policy-compile-failure alert. |
