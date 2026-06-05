# Migration consolidation plan

This document describes the SNG control-plane Postgres migration set,
a plan to **consolidate** migrations `001`–`041` into a single
baseline for new deployments, and the **online-migration pattern**
every future migration must follow to avoid taking long
`ACCESS EXCLUSIVE` locks.

It complements `docs/deploy.md` (operational runbook) and the
tooling in `cmd/sng-migrate` + `internal/migrate`.

## Why consolidate

Every fresh database currently replays all 41 migrations in
sequence. That is correct but increasingly slow and noisy: it
applies-then-rewrites schema (e.g. a column added in `008` and
altered in `037`), and a single boot replays four years of schema
churn. Consolidation collapses that history into one **baseline**
for *new* deployments while leaving the individual files untouched
for *existing* deployments, which have already applied them and must
continue from wherever they are.

We deliberately do **not** delete or rewrite the historical files:
existing databases record their schema version in
`schema_migrations`, and removing a file an existing DB has already
applied (or renumbering one) would corrupt that bookkeeping. The
baseline is strictly additive and opt-in.

## Migration inventory (001–041)

The numbering is golang-migrate's `NNN_name.{up,down}.sql`. Each
migration is reversible (`.down.sql` present) and tenant-scoped
tables enable + force RLS (established in `001`/`002`).

| Range | Theme | Notable dependencies |
|-------|-------|----------------------|
| `001` initial_schema | Tenants, sites, users, roles, devices, claim_tokens, audit_log, policy_graphs, policy_bundles; RLS enabled+forced | Foundation for everything |
| `002` role_bootstrap | `sng_app` runtime role + grants | Depends on `001` tables; `/readyz` grants live here |
| `003`–`004` webhooks | Webhook config + delivery atomic-claim | `004` builds on `003` |
| `005` policy_signing_keys | Per-tenant Ed25519 key store | Consumed by policy bundle signing |
| `006` tenant_api_keys | Production tenant API-key store | — |
| `007` policy_bundle_sha256 | Bundle integrity column | Alters `001` `policy_bundles` |
| `008`–`009` app_registry (+seed) | Traffic classification app DB + curated seed | `009` seeds rows into `008` |
| `010`–`011` policy_rollouts / is_draft | Progressive rollout state machine; draft graphs | Alter `001` `policy_graphs` |
| `012` baseline_models | Per-tenant statistical baselines | — |
| `013` alerts | Operator alert store + suppression | — |
| `014` integrations | Integration connectors | — |
| `015` msps | MSP hierarchy | References `tenants` |
| `016`–`017` casb / dlp | CASB discovery + DLP | — |
| `018`–`019` browser_policies / data_classification | Browser protection + taxonomy | — |
| `020`–`021` scim_external_ids / device_enrollment | SCIM IDs; enrollment tables | `020` alters `users`; `021` alters `devices` |
| `022`–`026` compliance / playbooks / executions / approvals / ai_suggestions | Compliance reports + playbook engine + approvals + AI suggestions | `024`→`023`, `025`→`024` |
| `027`–`028` reserved | Intentional no-op placeholders | Keep numbering contiguous |
| `029` ai_correlations | AI alert correlations | References `alerts` (`013`) |
| `030` scheduled_reviews | Policy-review scheduler tables | Leader-elected writer |
| `031` ops_health | Operational health snapshots | — |
| `032`–`033` kb_entries / troubleshoot_sessions | Troubleshooting assistant | `033` references `032` |
| `034` idp_configs | Per-tenant OIDC IdP configs | Underpins production OIDC auth |
| `035` site_ha | Active/passive HA posture | Alters `sites` |
| `036` sdwan_sla | Per-tenant SD-WAN SLA templates | — |
| `037` inline_casb | Inline CASB | May alter CASB tables (`016`) |
| `038` pops | Cloud PoP service | — |
| `039` compliance_evidence | SOC2 Type II evidence automation | Builds on `022` |
| `040` metering | Cost metering + budget guardrails | — |
| `041` devices_pubkey_unique | Unique Ed25519 device pubkey constraint | Alters `devices` (`001`/`021`) |

ClickHouse migrations live separately under `migrations/clickhouse/`
(`001_sng_telemetry`, `002_casb_dlp_telemetry`) and are **not** part
of this consolidation — they are managed on their own timeline.

## The squash baseline

`sng-migrate squash` generates the consolidated baseline. It reads
the embedded migration SQL (no database connection required),
concatenates every `up` in ascending version order into one file and
every `down` in descending order into its reverse, and writes the
pair to an output directory:

```sh
# Generates migrations/baseline/041_consolidated_baseline.{up,down}.sql
sng-migrate squash

# Custom location / overwrite an existing baseline
sng-migrate squash --out deploy/baseline --force
```

The generated baseline:

- is named with the **highest** consolidated version
  (`041_consolidated_baseline.*`) so that applying it records schema
  version `41`, and migrations `042+` apply on top unchanged;
- carries a `DO NOT EDIT BY HAND` header and a per-source banner
  (`-- NNN_name.up.sql`) before each segment so the provenance of
  every statement is auditable;
- is validated for completeness at generation time: `squash` errors
  if any version is missing its `.up`/`.down` counterpart or if a
  version number is duplicated, so the baseline can never silently
  drop SQL.

### Deployment process

| Deployment | What it runs | Resulting `schema_migrations` |
|------------|--------------|-------------------------------|
| **New** (empty DB) | the baseline pair, then `042+` | `41`, then advances |
| **Existing** | the individual files it has not yet applied | unchanged bookkeeping |

A new deployment points its migration source at a directory
containing the baseline pair plus any post-baseline files (`042+`);
an existing deployment keeps its source at the full `migrations/`
directory. Both converge on identical schema and apply future
migrations the same way. The baseline must be **regenerated**
(`sng-migrate squash --force`) whenever the consolidation cut line
moves forward (e.g. after a future re-baseline), and the regenerated
file committed.

### Verifying a baseline

Before trusting a baseline, prove it produces a schema identical to
the step-by-step replay:

1. DB A: apply `001..041` individually.
2. DB B: apply the baseline.
3. `pg_dump --schema-only` both and diff. The dumps must be
   byte-identical (modulo the `schema_migrations` rows, which differ
   by construction — A has 41 rows, B has 1).

## Online-migration pattern (required for all future migrations)

Future migrations (`042+`) MUST be lock-safe: a migration may not
hold `ACCESS EXCLUSIVE` on a hot table for more than the time of a
catalog-only change. `sng-migrate validate` (and `sng-migrate
--online up`) enforce this statically via `internal/migrate`'s
validator; new files are gated while the historical baseline is
grandfathered. The rules:

- **No `ADD COLUMN ... NOT NULL` without a `DEFAULT`.** On a
  non-empty table that rewrites every row under `ACCESS EXCLUSIVE`.
  Add the column nullable (or with a constant default, which
  Postgres 11+ records in the catalog without a rewrite), backfill in
  batches, then add the `NOT NULL` constraint via `NOT VALID` +
  `VALIDATE CONSTRAINT`.
- **No `CREATE INDEX` without `CONCURRENTLY`.** A plain create takes
  a `SHARE` lock blocking writes for the whole build. Use
  `CREATE INDEX CONCURRENTLY` (outside a transaction).
- **No `ALTER COLUMN ... TYPE` in place.** A type change rewrites the
  table under `ACCESS EXCLUSIVE`. Use the **shadow-column / shadow
  table** pattern instead.
- **No explicit `LOCK TABLE`** and **no raw `DROP COLUMN`.** Columns
  are removed through a deprecation sequence (stop reading → stop
  writing → drop in a later release) so a rolling deploy never has a
  running version referencing a dropped column.

### Shadow-table / shadow-column pattern

For a column type change or a non-trivial rewrite, never mutate the
live column in place. Instead:

1. **Expand.** Add a new nullable shadow column (or a shadow table)
   in the target shape — a catalog-only change, no rewrite.
2. **Dual-write.** Deploy application code that writes both the old
   and new column. Existing rows still have only the old value.
3. **Backfill.** Copy old → new in bounded batches (e.g.
   `... WHERE new IS NULL LIMIT N`), each its own transaction with a
   short `lock_timeout`, so no single statement holds a long lock.
   The `OnlineMigrator` + `LockMonitor` in `internal/migrate` drive
   this with a bounded `lock_timeout` per step.
4. **Contract.** Once backfill is complete and every running version
   reads the new column, add constraints (`NOT NULL` via `NOT VALID`
   + `VALIDATE`), swap reads, and drop the old column in a *later*
   migration.

Every DDL statement in a migration runs with a bounded `lock_timeout`
(`sng-migrate --online up --lock-timeout DUR`, default
`DefaultLockTimeout`) so a statement that cannot acquire its lock
promptly fails fast and is retried, rather than queuing behind a long
transaction and blocking all traffic to the table.
