# ShieldNet Gateway — Control-Plane Deployment Runbook

This runbook covers the database-side operational concerns for
deploying the ShieldNet Gateway (SNG) control plane: PostgreSQL
role hierarchy, the row-level-security (RLS) GUC contract, the
privileges the migration runner needs, and how to roll forward and
back safely.

The application-level layout (containers, Helm charts, edge VM
images) is covered in [`ARCHITECTURE.md`](../ARCHITECTURE.md); this
document only addresses the bits of provisioning that operators
touch directly.

---

## Role hierarchy

SNG uses two PostgreSQL roles in production:

| Role            | Privileges                                         | Used by                                  |
|-----------------|----------------------------------------------------|------------------------------------------|
| `sng_migrate`   | Schema owner: DDL + GRANT + ALTER DEFAULT PRIVILEGES on `public`. Typically a superuser or member of a `sng_dba` group. | The migration runner (`cmd/sng-migrate` or `Makefile migrate-up`). One-shot per deploy. |
| `sng_app`       | `USAGE` on `public`, `SELECT/INSERT/UPDATE/DELETE` on all tables, `USAGE` on all sequences. **NOT** a superuser — RLS is enforced. | The control-plane runtime (every long-running pod / VM that handles HTTP requests, NATS consumers, webhook dispatchers, etc.). |

Two operating invariants follow from this split:

1. **The runtime never has DDL rights.** A compromised
   control-plane process cannot ALTER, DROP, or TRUNCATE any
   table. Schema changes are exclusively a migration-time concern.
2. **The runtime is subject to RLS.** Postgres `FORCE ROW LEVEL
   SECURITY` bypasses superuser checks; `sng_app` is not a
   superuser, so every tenant-scoped query must set
   `sng.tenant_id` before the rows become visible.

A third role (`sng_admin`) for destructive operations like
`TRUNCATE` or cross-tenant maintenance is reserved for future
work — today the migration runner is the only escalated role.

---

## RLS contract

Every tenant-scoped table created by `migrations/001_initial_schema.up.sql`
enables and **forces** row-level security with a policy of the
form:

```sql
CREATE POLICY <table>_tenant_isolation ON <table>
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
```

The application contract is:

* Before any tenant-scoped query, the caller MUST issue
  `SELECT set_config('sng.tenant_id', '<uuid>', true)` inside the
  same transaction.
* The `true` argument scopes the GUC to the transaction — it
  resets at `COMMIT`/`ROLLBACK`, so a connection pool can safely
  recycle the same physical connection across tenants without
  cross-contamination.
* A connection that has NOT set `sng.tenant_id` sees **zero
  rows**, not an error. This is the intentional fail-closed
  behaviour: a forgotten `set_config` produces empty result sets,
  never accidentally cross-tenant data.

The `sng.` namespace is deliberately chosen to avoid collision
with the sibling SN360 product (which uses `sn360.tenant_id`)
when both run against the same pooler.

---

## Initial provisioning

The migration runner refuses to run if `sng_app` is missing
(`migrations/002_role_bootstrap.up.sql` raises
`role "sng_app" does not exist` with a remediation hint). This is
intentional: role lifecycle is an operator concern, not a schema
concern.

Run the following once per database, as a superuser, **before**
the first migration deploy:

```sql
-- 1. Runtime role. NOINHERIT means membership in this role does
--    NOT automatically grant its privileges to outer sessions;
--    callers must `SET ROLE sng_app` explicitly.
CREATE ROLE sng_app NOINHERIT NOLOGIN;

-- 2. (Optional) Login user for the runtime. Typical pattern is
--    a per-environment service account whose only privilege is
--    membership in sng_app.
CREATE ROLE sng_app_login LOGIN PASSWORD <strong_password>;
GRANT sng_app TO sng_app_login;

-- 3. Migration runner. Schema owner. Privileges depend on your
--    org's IAM model; the migration set requires CREATE on the
--    target schema plus the ability to GRANT to sng_app.
CREATE ROLE sng_migrate LOGIN PASSWORD <strong_password>;
GRANT sng_app TO sng_migrate; -- so ALTER DEFAULT PRIVILEGES targets sng_app correctly
```

Once those roles exist, the migration runner will apply 002 and
GRANT the runtime role the privileges it needs.

> **A note on `ALTER DEFAULT PRIVILEGES`.** This statement only
> affects objects created **by the role that ran it**. The
> control-plane convention is that every migration runs as
> `sng_migrate`, so every future table inherits the runtime
> grants automatically. If a one-off DDL is executed by a
> different role, that role's tables will need explicit
> per-object GRANTs — prefer to channel all DDL through the
> migration set.

---

## Running migrations

The migration set is embedded in the `sng-control` binary via
`migrations/embed.go` and exposed by `cmd/sng-migrate`. Two
operational shapes are supported:

### `cmd/sng-migrate` (recommended)

```bash
PG_DSN='postgres://sng_migrate@db.internal:5432/sng?sslmode=verify-full' \
  ./sng-migrate up
```

Runs every pending migration in order. Exits non-zero on the first
failure with the failing migration version logged. Safe to re-run
on success (golang-migrate tracks the applied version in
`schema_migrations`).

### Makefile target

```bash
make migrate-up DSN='postgres://sng_migrate@db.internal:5432/sng?sslmode=verify-full'
```

Equivalent to the binary form, useful during local development.

### Rolling back

```bash
./sng-migrate down 1   # roll back the most recent migration only
```

> The down path for `002_role_bootstrap` revokes the grants but
> deliberately leaves `sng_app` in place — role lifecycle is owned
> by ops. If you need to drop the role entirely, do it
> out-of-band after running `./sng-migrate down`.

---

## Health checks

The control-plane exposes two health endpoints:

| Endpoint     | Probe target                  | Expected on healthy system |
|--------------|-------------------------------|----------------------------|
| `/healthz`   | Process is up, config parsed  | 200 OK                     |
| `/readyz`    | DB pool + NATS reachable      | 200 OK                     |

Both run as `sng_app`. If `/readyz` returns 503 with a "permission
denied" message, the most common cause is that migration 002 did
not run (or was rolled back) — re-applying the migration set
restores the grants.

---

## Backup considerations

* **`pg_dump`** can dump the schema and data as either
  `sng_migrate` (full dump including DDL) or `sng_app` (data-only,
  subject to RLS). For disaster-recovery snapshots, always dump as
  `sng_migrate` so the full schema is captured.
* **Restoring into a fresh database**: run the role-provisioning
  step above, then `pg_restore` the dump. The `GRANT` statements
  in the dump should be a no-op (they restore the migration-time
  grants); the runtime role's membership chain is preserved.
* **Point-in-time recovery**: standard Postgres PITR works
  unchanged. The `sng.tenant_id` GUC is a session-level setting,
  not stored in the WAL, so PITR has no special concerns around
  it.

---

## Connection-pool configuration

Production pools (PgBouncer, pgcat, RDS Proxy, etc.) MUST be
configured for **session pooling**, not transaction pooling. This
is because:

* `SET ROLE sng_app` is connection-scoped, not transaction-scoped.
  Transaction pooling would multiplex the same physical connection
  across multiple roles within a single second.
* Several application code paths (notably the audit-log writer)
  rely on `set_config(..., true)` lasting for the entire
  transaction. Statement pooling would break the contract.

Session pooling preserves both semantics. The application's own
`pgxpool` is already configured for the session model — only
external poolers need explicit configuration.
