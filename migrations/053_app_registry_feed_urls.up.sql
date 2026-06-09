-- 053_app_registry_feed_urls
--
-- Correct three app_registry rows whose seeded metadata_url could not
-- be synced by internal/service/appdb/sync.go, producing a recurring
-- "appdb sync per-app failure" WARN on every control-plane boot.
--
--   * Microsoft Teams Media — the M365 endpoints API rejects requests
--     that omit a clientrequestid GUID (HTTP 400). The seed URL had
--     only ?ServiceAreas=Skype. Add a clientrequestid, matching the
--     working Microsoft 365 row.
--   * Salesforce — the seed pointed at a help.salesforce.com HTML
--     article, not a machine feed. Salesforce publishes no stable
--     public IP feed, so classify by domain only (metadata_url NULL),
--     consistent with Okta / Entra ID / GCP Console.
--   * Azure Portal — the seed pointed at a microsoft.com download HTML
--     page (no direct feed). The portal.azure.com / *.azure.com
--     domains already cover it; clear the metadata_url.
--
-- Idempotent: matched by the stable (name) natural key.

UPDATE app_registry
SET metadata_url = 'https://endpoints.office.com/endpoints/worldwide?ServiceAreas=Skype&clientrequestid=f7b14f21-ec26-422a-9c35-2f1e88846994'
WHERE name = 'Microsoft Teams Media';

UPDATE app_registry SET metadata_url = NULL WHERE name = 'Salesforce';
UPDATE app_registry SET metadata_url = NULL WHERE name = 'Azure Portal';
