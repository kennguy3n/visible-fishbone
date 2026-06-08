-- 054_browser_policy_rbi_action
--
-- Allow the 'rbi' browser-protection action.
--
-- The domain model (internal/repository/types.go) added
-- BrowserPolicyActionRBI = "rbi" for Gap #8 (Remote Browser
-- Isolation): a browser policy can redirect a matching page to the
-- RBI proxy so it renders in a disposable container instead of the
-- endpoint's local browser. BrowserPolicyAction.IsValid() accepts
-- "rbi", but the browser_policies CHECK constraint from migration
-- 018 predates that action and only permits block/allow/warn/log.
--
-- The mismatch meant any attempt to persist an RBI browser policy
-- failed with a CHECK violation (SQLSTATE 23514), which the Postgres
-- repository maps to ErrInvalidArgument — the feature was
-- unreachable. This migration realigns the schema with the model.

ALTER TABLE browser_policies
    DROP CONSTRAINT IF EXISTS browser_policies_action_check;

ALTER TABLE browser_policies
    ADD CONSTRAINT browser_policies_action_check
    CHECK (action IN ('block', 'allow', 'warn', 'log', 'rbi'));
