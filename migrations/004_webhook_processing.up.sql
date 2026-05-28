-- ShieldNet Gateway (SNG) — webhook delivery atomic-claim migration.
--
-- Background. Migration 002 modelled webhook_deliveries.status with
-- four states: pending → delivered | failed | exhausted. The
-- delivery worker drained pending rows via a SELECT ... FOR UPDATE
-- SKIP LOCKED in `ListPending`, then released the lock by
-- committing the transaction *before* the worker processed each
-- row (the worker iterates over the returned slice and calls
-- UpdateStatus for each delivery). The SKIP LOCKED hint is
-- therefore ineffective: the moment the SELECT transaction commits,
-- the locks are released and a second worker (or even the same
-- worker on a subsequent tick) can fetch the same rows again,
-- producing duplicate HTTP POSTs to subscribers.
--
-- Fix. Add an explicit `processing` state and turn ListPending into
-- an atomic claim: `UPDATE ... SET status='processing' WHERE ...
-- RETURNING ...`. Worker observes a row in 'processing' state and
-- knows it owns the delivery exclusively. On success the worker
-- transitions processing → delivered; on transient failure
-- processing → pending (with next_retry_at advanced); on terminal
-- failure processing → exhausted. A crashed worker leaves rows
-- stuck in 'processing'; the next call to ListPending re-claims any
-- row whose last_attempt_at is older than a configurable
-- processing-timeout window (default 5 minutes), bounding worst-case
-- delivery delay to that window without ever double-delivering
-- within it.
--
-- This migration is additive — existing 'pending' / 'delivered' /
-- 'failed' / 'exhausted' rows are untouched; only the CHECK
-- constraint is widened to admit 'processing'. The partial index
-- previously WHERE status='pending' is replaced with one covering
-- both pending and processing rows so the atomic-claim query stays
-- index-driven.

ALTER TABLE webhook_deliveries
    DROP CONSTRAINT IF EXISTS webhook_deliveries_status_check;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_status_check
        CHECK (status IN ('pending', 'processing', 'delivered', 'failed', 'exhausted'));

DROP INDEX IF EXISTS idx_webhook_deliveries_pending_next;

-- Composite index optimised for the atomic-claim query. The
-- (status, next_retry_at) order is intentional: the WHERE clause
-- always filters on status first and then orders by next_retry_at,
-- so a btree on these columns is index-only-scan friendly. The
-- predicate is widened to include both 'pending' and 'processing'
-- so the same index serves both the normal-claim and the stuck-row
-- reaper paths.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_claimable
    ON webhook_deliveries (status, next_retry_at)
    WHERE status IN ('pending', 'processing');
