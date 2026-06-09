-- 055_inline_casb_action_expansion
--
-- WS4 — Inline CASB Expansion. Widens the inline_casb_rules action
-- vocabulary from the four launch verbs to the nine the control
-- plane (internal/service/casb/inline.go InlineAction) and the data
-- plane (crates/sng-swg/src/casb_rules.rs CasbAction) now share.
--
-- Migration 037 created the column with an inline CHECK permitting
-- only ('upload', 'download', 'share', 'delete'); persisting a rule
-- for any of the five new actions (login, admin_config_change,
-- api_key_create, external_share, bulk_export) would fail with a
-- CHECK violation (SQLSTATE 23514) — the expansion would be
-- unreachable from the SQL store. This migration realigns the
-- schema with the model.
--
-- The inline CHECK from migration 037 was unnamed; Postgres
-- auto-named it inline_casb_rules_action_check. DROP ... IF EXISTS
-- tolerates either the auto-generated name or a prior explicit one.

ALTER TABLE inline_casb_rules
    DROP CONSTRAINT IF EXISTS inline_casb_rules_action_check;

ALTER TABLE inline_casb_rules
    ADD CONSTRAINT inline_casb_rules_action_check
    CHECK (action IN (
        'upload', 'download', 'share', 'delete',
        'login', 'admin_config_change', 'api_key_create',
        'external_share', 'bulk_export'
    ));
