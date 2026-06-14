-- 068_tenant_hibernation (down)
--
-- Drop the per-tenant hibernation state. The state is controller-derived
-- parking intent, not source data: re-applying the up migration creates
-- an empty table in which every tenant is back to the default `active`
-- (absence == active), exactly the fail-safe posture a fresh deployment
-- starts from. Waking is idempotent, so any tenant whose row is dropped
-- simply resumes full work on the next cycle.

DROP TRIGGER IF EXISTS tenant_hibernation_set_updated_at ON tenant_hibernation;

DROP TABLE IF EXISTS tenant_hibernation;
