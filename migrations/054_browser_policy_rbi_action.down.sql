-- 054_browser_policy_rbi_action (down)
--
-- Restore the original block/allow/warn/log action set. Any rows
-- using the 'rbi' action would violate the restored constraint, so
-- demote them to 'block' (the table default) before re-adding it.

UPDATE browser_policies SET action = 'block' WHERE action = 'rbi';

ALTER TABLE browser_policies
    DROP CONSTRAINT IF EXISTS browser_policies_action_check;

ALTER TABLE browser_policies
    ADD CONSTRAINT browser_policies_action_check
    CHECK (action IN ('block', 'allow', 'warn', 'log'));
