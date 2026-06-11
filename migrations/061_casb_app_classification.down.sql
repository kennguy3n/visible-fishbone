-- 061_casb_app_classification (down)
--
-- Drop the CASB NoOps pipeline state. The underlying
-- casb_discovered_apps inventory (migration 016) is untouched; after
-- re-applying the up migration the pipeline rebuilds classifications,
-- actions and digests from the next shadow-IT flush and reconcile.
-- Order: drop the dependent tables before any referenced parents
-- (here all reference only tenants, so order is for clarity).

DROP TABLE IF EXISTS casb_app_digest_state;
DROP TABLE IF EXISTS casb_app_actions;
DROP TABLE IF EXISTS casb_app_action_policies;
DROP TABLE IF EXISTS casb_app_classifications;
