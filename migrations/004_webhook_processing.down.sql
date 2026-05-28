-- ShieldNet Gateway (SNG) — revert webhook delivery atomic-claim migration.
--
-- Reverting means narrowing the CHECK back to four states. Any
-- rows in 'processing' state at the time of the down-migration are
-- reset to 'pending' so the constraint can be re-tightened without
-- violating it; their next_retry_at is left as-is so the legacy
-- (non-atomic) ListPending will pick them up again. The legacy
-- duplicate-delivery hazard returns under this revert — the
-- migration was added precisely to fix it.

DROP INDEX IF EXISTS idx_webhook_deliveries_claimable;

UPDATE webhook_deliveries
    SET status = 'pending'
    WHERE status = 'processing';

ALTER TABLE webhook_deliveries
    DROP CONSTRAINT IF EXISTS webhook_deliveries_status_check;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_status_check
        CHECK (status IN ('pending', 'delivered', 'failed', 'exhausted'));

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending_next
    ON webhook_deliveries (status, next_retry_at)
    WHERE status = 'pending';
