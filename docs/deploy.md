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

The migration runner refuses to run if `sng_app` is missing.
`migrations/002_role_bootstrap.up.sql` raises a `SQLSTATE 42704`
(`undefined_object`) error with the verbatim message:

> `sng_app role missing; provision it before running migrations (see docs/deploy.md)`

…and the HINT `CREATE ROLE sng_app NOLOGIN; GRANT sng_app TO <migration_runner>;`.
This is intentional: role lifecycle is an operator concern, not a
schema concern.

Run the following once per database, as a superuser, **before**
the first migration deploy:

```sql
-- 1. Runtime role. NOLOGIN — nobody connects as `sng_app`
--    directly; login users (below) acquire its privileges via
--    `SET SESSION ROLE sng_app`. The NOINHERIT attribute on a
--    role only governs what THAT role inherits from roles it is
--    a member of (irrelevant for `sng_app` — it's not a member
--    of anything else). The actual control over whether
--    `sng_app_login` auto-acquires `sng_app`'s privileges lives
--    on `sng_app_login` itself (next step).
CREATE ROLE sng_app NOLOGIN;

-- 2. (Optional) Login user for the runtime. Typical pattern is
--    a per-environment service account whose only privilege is
--    membership in `sng_app`. NOINHERIT on the login user is
--    what forces an explicit `SET SESSION ROLE sng_app` at
--    connection time — without it, the login user would
--    silently inherit `sng_app`'s grants and the per-connection
--    `SET SESSION ROLE` hook would be a no-op.
CREATE ROLE sng_app_login LOGIN NOINHERIT PASSWORD <strong_password>;
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

* `SET SESSION ROLE sng_app` is connection-scoped: the role
  persists across `COMMIT`/`ROLLBACK` for the lifetime of the
  physical connection. (Bare `SET ROLE` is equivalent to `SET
  SESSION ROLE`; `SET LOCAL ROLE` is the variant that reverts at
  end-of-transaction. We use the explicit `SESSION` form on the
  pool's connection-setup hook for clarity, not because the bare
  form would be incorrect.) Transaction pooling would multiplex
  the same physical connection across multiple roles within a
  single second, which breaks the per-connection role assumption.
* Several application code paths (notably the audit-log writer)
  rely on `set_config(..., true)` lasting for the entire
  transaction. Statement pooling would break the contract.

Session pooling preserves both semantics. The application's own
`pgxpool` is already configured for the session model — only
external poolers need explicit configuration.

### Runtime enforcement of `SET SESSION ROLE`

The `sng-control` binary's pool configuration in
`cmd/sng-control/main.go::openPostgres` installs an `AfterConnect`
hook on every new physical connection that:

1. Issues `SET SESSION ROLE <PG_APP_ROLE>` (default `sng_app`,
   identifier-sanitised). An empty `PG_APP_ROLE` disables the hook
   for dev environments where a single login user is granted DML
   directly — production must always set `PG_APP_ROLE`.
2. Verifies `SELECT current_user` returns the requested role and
   returns an error from `AfterConnect` if it doesn't. pgx then
   discards the connection, so the misconfiguration is loud (a
   stream of `current_user = "..." want "..."` errors at boot)
   rather than silent (queries running as the wrong role and
   bypassing RLS).

The boot-time probe doesn't catch the transaction-pooler scenario
on its own — if a downstream pooler discards the `SET SESSION
ROLE` between transactions, the first transaction succeeds and
subsequent ones see `permission denied`. The combination of
session-pooling at every layer + the boot-time probe + readiness
checks running as `sng_app` is what closes the loop.

## Policy signing-key modes

The control plane signs every compiled policy bundle with an
Ed25519 keypair. Two modes are supported; they differ in **where
the key lives** and **what `kid=active` resolves to**.

### Mode A — DB-backed (default)

The `policy_signing_keys` table holds the canonical keypair set
per tenant (one row per (tenant_id, key_id)). One row per tenant
carries `status = 'active'` at any time; `Compile` pulls that row,
signs the bundle, and embeds the row's `key_id` in the bundle
envelope. Rotation is a DB-level transition: the previous active
row flips to `status = 'rotated'` and a new active row is
inserted. Receivers verifying a historical bundle resolve its
`key_id` against the row history; the route
`/tenants/{tid}/policy/signing-keys/{kid}/public-key` returns the
matching public key.

### Mode B — File-backed (single-key deployments)

Setting `POLICY_SIGNING_KEY_PATH=/path/to/seed` at boot loads a
file-backed `KeySigner` that signs **every** bundle for **every**
tenant with the same seed. The signer's `key_id` is derived
deterministically from the seed's public-key SHA-256 (first 16
hex chars), so it is stable across restarts as long as the seed
file is unchanged.

This mode is intended for single-host deployments and air-gapped
test rigs where DB-backed rotation is overkill. Operators rotate
by replacing the seed file and restarting the process; the new
`key_id` takes effect on next boot.

The `/public-key` route is mode-aware:

- `kid == <file-backed key_id>` or `kid == "active"` returns the
  file-backed public key directly (no DB lookup).
- Any other `kid` falls through to the DB-backed row history, so
  bundles signed under Mode A before the operator switched to
  Mode B remain verifiable.

### Operational semantics of `kid=active` across mode switches

When `POLICY_SIGNING_KEY_PATH` is set, `kid=active` resolves to
the file-backed key regardless of whether the tenant also has a
DB-backed active row. The DB-backed active row is unreachable via
the `active` alias in this configuration — it remains reachable
by its explicit `key_id`.

Switching from Mode B back to Mode A (unsetting
`POLICY_SIGNING_KEY_PATH` and restarting) silently re-points
`kid=active` to the DB-backed row. Bundles signed during the
Mode B window were signed under the file-backed key, NOT the DB
row, so a receiver that pinned `kid=active` and cached the result
will start failing verification after the switch.

Recommendation: receivers SHOULD pin against the explicit `kid`
embedded in the bundle envelope (`bundle.kid`), NOT against the
`active` alias. The alias is only useful for boot-time discovery
in admin tooling; it has no role in the verification path. The
boot log at `cmd/sng-control/main.go` emits
`policy: file-backed signer loaded kid=<…>` when Mode B is in
effect so operators have a paper trail across restarts.

## API-key inventory cap

The operator-facing `POST /api/v1/tenants/{tenant_id}/api-keys`
endpoint enforces a per-tenant cap on the number of active (non-
revoked, non-expired) keys. The cap protects against unbounded
key creation by an authenticated caller (either a human user via
JWT or an existing API key) and bounds the response size of the
un-paginated `GET /api/v1/tenants/{tenant_id}/api-keys`. Callers
that exceed the cap receive HTTP 429 with the JSON error body
`{"error":{"code":"resource_exhausted","message":"tenant has N
active api keys; cap is M (revoke unused keys or contact platform
to raise the cap)"}}`.

The cap is configured via `AUTH_API_KEY_MAX_ACTIVE_PER_TENANT`
(default 64). The default covers realistic operator workflows
(multiple CI bots, integration accounts, scoped per-env keys)
without leaving an unbounded tail. Production deployments that
genuinely need a higher cap can raise the env var; production
boot refuses values <= 0 (set the env var to a positive integer
or remove it to inherit the default).

Audit attribution: every `apikey.create` and `apikey.revoke`
audit row records the *user* who initiated the change in the
`actor_id` column when the request was authenticated via JWT.
When the request was authenticated via API key (a machine
identity, not a user), `actor_id` is NULL and the acting key's
ID is stamped into the audit `details` JSON under the key
`acting_api_key_id`. Operators correlating a key compromise to
its blast radius should query the `details` column for that key
alongside the `actor_id` column for human actions. The same
enrichment applies to every audit-writing service (tenants,
sites, identity, RBAC, webhooks, signing keys) so the rule
holds uniformly across the platform.
