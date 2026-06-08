-- Revert 053_app_registry_feed_urls: restore the original (un-syncable)
-- metadata_url values exactly as seeded by 009_app_registry_seed.

UPDATE app_registry
SET metadata_url = 'https://endpoints.office.com/endpoints/worldwide?ServiceAreas=Skype'
WHERE name = 'Microsoft Teams Media';

UPDATE app_registry
SET metadata_url = 'https://help.salesforce.com/articleView?id=000334193'
WHERE name = 'Salesforce';

UPDATE app_registry
SET metadata_url = 'https://www.microsoft.com/en-us/download/details.aspx?id=56519'
WHERE name = 'Azure Portal';
