-- Reverse migration for the workshard shard-lease ledger (077).
--
-- Dropping the ledger is fail-safe: with no lease table the workshard
-- distributor falls back to single-owner ("own all shards") behaviour,
-- so per-tenant background jobs keep running on every replica that can
-- reach Postgres — they simply stop being partitioned across replicas
-- until the table returns.
DROP TABLE IF EXISTS workshard_shard_leases;
