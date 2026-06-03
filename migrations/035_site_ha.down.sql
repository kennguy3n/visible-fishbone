-- 035_site_ha — down migration.
--
-- Drop the partial index first: it references ha_peer_device_id,
-- the column we are about to remove.
DROP INDEX IF EXISTS sites_ha_peer_device_idx;

ALTER TABLE sites DROP COLUMN IF EXISTS ha_peer_device_id;
ALTER TABLE sites DROP COLUMN IF EXISTS ha_mode;
