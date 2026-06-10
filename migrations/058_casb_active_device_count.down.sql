-- 058_casb_active_device_count (down)
--
-- Drop the windowed active-device column. users_count is left intact;
-- the windowed signal is reconstructable from the next shadow-IT flush
-- after re-applying the up migration.

ALTER TABLE casb_discovered_apps
    DROP COLUMN IF EXISTS active_device_count;
