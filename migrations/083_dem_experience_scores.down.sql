-- Migration 083 (down): drop the dem_experience_scores table.
-- Dropping the table removes its RLS policies and indexes implicitly.

DROP TABLE IF EXISTS dem_experience_scores;
