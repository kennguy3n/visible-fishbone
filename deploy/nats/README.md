# NATS per-tenant authorization (defense-in-depth)

These templates show how to constrain NATS subjects **per tenant** so
a compromised or buggy edge/endpoint credential for tenant *A* cannot
publish into — or subscribe to — tenant *B*'s subjects. This is a
defense-in-depth layer: the control plane already stamps the tenant
into every subject, and Postgres RLS + ClickHouse query filtering
isolate stored data. NATS subject ACLs close the transport layer so
isolation does not depend solely on well-behaved publishers.

See `SECURITY.md` (“Defense-in-depth for tenant isolation”) for how
this fits with the other layers.

## Subject taxonomy (source of truth: `internal/nats`)

All control-plane subjects are tenant-scoped. The tenant UUID is a
token inside the subject:

| Purpose | Subject pattern | Defined in |
|---------|-----------------|------------|
| Telemetry (single-partition) | `sng.<tenant_id>.telemetry.<class>` | `SubjectForTelemetry` |
| Telemetry (fan-out / partitioned) | `sng.<partition>.<tenant_id>.telemetry.<class>` | `SubjectForTelemetryPartition` |
| Policy notifications | `sng.<tenant_id>.policy.<kind>` | `SubjectForPolicy` |
| Control-plane events | `sng.<tenant_id>.events.<kind>` | `SubjectForEvent` |
| Dead-letter queue | `sngdlq.>` | `DLQSubjectFor` |

`<class>` ∈ {flow, dns, http, ips, ztna, sdwan, agent}.

> **Important — the partitioned form moves the tenant token.** When
> telemetry fan-out is enabled the partition slot sits *before* the
> tenant (`sng.<partition>.<tenant_id>.telemetry.>`). A naive
> `sng.<tenant_id>.>` allow-rule would therefore NOT cover partitioned
> telemetry. The per-tenant template below grants **both** shapes:
> `sng.<tenant_id>.>` and `sng.*.<tenant_id>.telemetry.>`.

## Trust model

- **Edge / endpoint credentials** are tenant-scoped. They may
  *publish* their own telemetry and *subscribe* to their own policy
  bundles. They may not touch any other tenant's subjects, the DLQ, or
  JetStream API subjects (`$JS.API.>`).
- **The control plane** (`sng-control`) is the only trusted multi-tenant
  principal. It publishes policy/events for any tenant, consumes all
  telemetry, re-publishes telemetry to its origin subject during DLQ
  replay, and owns the DLQ and JetStream management subjects.

## Files

- `authorization.conf` — a complete `authorization {}` block for the
  centralized (server-config) auth model: the control-plane service
  user plus one rendered per-tenant example. Drop it into the NATS
  server config via `include`.
- `tenant-user.template.conf` — the per-tenant user block. Render once
  per tenant, substituting `{{TENANT_ID}}` (lowercase UUID) and
  `{{TENANT_PASSWORD}}` (or swap `password` for `nkey`), and splice the
  rendered blocks into the `users: [...]` list of `authorization.conf`.

## Rendering

Render the per-tenant block for each active tenant. Example with `sed`:

```sh
TENANT_ID=11111111-1111-1111-1111-111111111111
sed -e "s/{{TENANT_ID}}/${TENANT_ID}/g" \
    -e "s/{{TENANT_PASSWORD}}/$(openssl rand -hex 24)/g" \
    deploy/nats/tenant-user.template.conf
```

In production prefer **nkeys** (or decentralized account/operator JWTs
with per-account subject permissions) over passwords; the subject
allow/deny rules are identical — only the credential type differs. For
the decentralized model, each tenant maps to its own NATS *account*
whose exports/imports are limited to the same subject shapes shown
here, which additionally gives hard subject-space isolation at the
account boundary.

## Validating an ACL change

After editing, validate the config and reload without dropping
connections:

```sh
nats-server -c /etc/nats/nats.conf -t   # parse/type-check only
nats-server --signal reload=/var/run/nats.pid
```

Then confirm a tenant credential is correctly fenced (should FAIL):

```sh
# Using tenant A's creds to publish into tenant B's subject must error
nats pub --user tenantA --password ... \
  sng.<TENANT_B_ID>.telemetry.flow '{}'   # -> Permissions Violation
```
