-- Migration 038 (down): drop the cloud-PoP tables. Dropping each
-- table removes its RLS policies, indexes, and triggers implicitly.
-- Drop in FK-dependency order: the two tables that reference pops
-- first, then pops itself.

DROP TABLE IF EXISTS tenant_pop_assignments;
DROP TABLE IF EXISTS pop_health;
DROP TABLE IF EXISTS pops;
