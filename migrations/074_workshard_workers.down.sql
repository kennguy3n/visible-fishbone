-- Reverse migration for the workshard worker registry (074).
--
-- Dropping the registry is fail-safe: the workshard distributor falls
-- back to single-owner ("own all shards") behaviour when it cannot read
-- the registry, so per-tenant background jobs continue to run — they
-- merely stop being distributed across replicas until the table returns.
DROP TABLE IF EXISTS workshard_workers;
