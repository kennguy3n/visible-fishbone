-- Reverse migration 060 (down): drop the DLP review queue. Dropping the
-- table removes its RLS policy and both indexes implicitly; the explicit
-- DROP POLICY keeps the down migration readable and idempotent.
DROP POLICY IF EXISTS dlp_review_queue_tenant_isolation ON dlp_review_queue;
DROP TABLE IF EXISTS dlp_review_queue;
