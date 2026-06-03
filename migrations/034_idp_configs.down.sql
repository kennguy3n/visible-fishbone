-- Migration 034 (down): drop the idp_configs table and its policies.
-- Dropping the table removes its RLS policies and indexes implicitly.

DROP TABLE IF EXISTS idp_configs;
