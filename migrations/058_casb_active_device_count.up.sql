-- 058_casb_active_device_count
--
-- WS4 — Inline CASB Expansion. casb_discovered_apps now has two
-- independent writers with different semantics for "how many users":
--
--   * API-mode connector sync (internal/service/casb/service.go)
--     writes users_count = the app's full account roster pulled from
--     the vendor API (e.g. 500 licensed users).
--   * Shadow-IT discovery (internal/service/casb/shadow_it.go) writes
--     a windowed count of distinct devices that reached the app's
--     hostnames in the last flush window (e.g. 5 active devices in the
--     last 5 minutes) — a "recently active" signal, not a roster.
--
-- When an operator names a connector byte-identically to a shadow
-- catalog app the two writers collide on (tenant_id, name) and the
-- smaller window count would clobber the accurate roster. Splitting
-- the windowed device count into its own column lets each writer own a
-- distinct column so neither regresses the other: users_count stays
-- the roster (and can still legitimately decrease), active_device_count
-- carries the shadow-IT window signal. The operator portal renders
-- both ("N licensed / M active").
--
-- Backfill: existing rows were written exclusively by one path. Rows
-- with no connector (pure shadow-IT) carry their window count in
-- users_count today; seed active_device_count from users_count so the
-- portal keeps showing the active signal after the writers split, then
-- let the next flush refine it. Rows from API-mode keep users_count as
-- the roster and start active_device_count at 0 until shadow traffic
-- is observed. We cannot distinguish the two origins DB-side, so the
-- backfill copies users_count into active_device_count for every row;
-- API-mode rows self-correct on their next sync (which leaves
-- active_device_count untouched) and shadow rows on their next flush.

ALTER TABLE casb_discovered_apps
    ADD COLUMN IF NOT EXISTS active_device_count INTEGER NOT NULL DEFAULT 0;

UPDATE casb_discovered_apps
    SET active_device_count = users_count
    WHERE active_device_count = 0
      AND users_count <> 0;
