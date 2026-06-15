-- Migration 092 (down): drop the dem_probe_results table. Dropping the
-- table removes its RLS policies and indexes implicitly.

DROP TABLE IF EXISTS dem_probe_results;
