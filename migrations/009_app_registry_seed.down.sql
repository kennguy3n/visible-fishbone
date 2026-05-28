-- 009_app_registry_seed — rollback.
--
-- Removes only the rows the seed migration inserted. Operator-added
-- rows (is_system = FALSE) are preserved so a down/up cycle does
-- not destroy operator data.

DELETE FROM app_registry WHERE is_system = TRUE;
