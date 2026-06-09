-- 055_audit_log_global_idx (down)
--
-- Drop the global-audit partial index. DROP INDEX CONCURRENTLY does
-- not take an ACCESS EXCLUSIVE lock on the parent table, mirroring the
-- non-blocking CREATE in the up step. Like the up step it must be the
-- only statement in the file because CONCURRENTLY cannot run inside a
-- transaction block. IF EXISTS keeps the rollback idempotent.
DROP INDEX CONCURRENTLY IF EXISTS audit_log_global_idx;
