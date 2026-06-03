-- Migration 036 (down): drop the sdwan_sla_policies table and its
-- policies. Dropping the table removes its RLS policies and indexes
-- implicitly.

DROP TABLE IF EXISTS sdwan_sla_policies;
