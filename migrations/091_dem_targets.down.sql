-- Migration 091 (down): drop the dem_targets table. Dropping the
-- table removes its RLS policies and indexes implicitly.

DROP TABLE IF EXISTS dem_targets;
