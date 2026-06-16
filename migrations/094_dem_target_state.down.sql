-- Migration 094 (down): drop the dem_target_state table. Dropping the
-- table removes its RLS policies and indexes implicitly.

DROP TABLE IF EXISTS dem_target_state;
