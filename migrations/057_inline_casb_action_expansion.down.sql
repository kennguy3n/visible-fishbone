-- 057_inline_casb_action_expansion (down)
--
-- Restore the original four-verb action set. Any rows using one of
-- the five new actions would violate the restored constraint, so
-- delete them before re-adding it (unlike a column default there is
-- no safe verb to demote a login / admin_config_change rule to, and
-- silently rewriting a security rule's action would change its
-- meaning — dropping the unsupported rows is the honest rollback).

DELETE FROM inline_casb_rules
    WHERE action IN (
        'login', 'admin_config_change', 'api_key_create',
        'external_share', 'bulk_export'
    );

ALTER TABLE inline_casb_rules
    DROP CONSTRAINT IF EXISTS inline_casb_rules_action_check;

ALTER TABLE inline_casb_rules
    ADD CONSTRAINT inline_casb_rules_action_check
    CHECK (action IN ('upload', 'download', 'share', 'delete'));
