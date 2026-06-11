-- Migration 059 (down): drop the cross-region tenant migration state
-- machine. Dropping the table removes its RLS policies, indexes, and
-- the updated_at trigger implicitly.

DROP TABLE IF EXISTS tenant_migrations;
