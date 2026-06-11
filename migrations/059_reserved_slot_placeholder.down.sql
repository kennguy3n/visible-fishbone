-- 059_reserved_slot_placeholder (down)
--
-- The up migration is a pure no-op placeholder that only occupies the
-- 059 version slot to keep the migration sequence contiguous; it
-- changes no schema, so there is nothing to undo. This down is a
-- matching no-op (a valid, executable statement so golang-migrate does
-- not see an empty body) and exists solely to satisfy the up/down
-- pairing invariant enforced by TestSourceFS_Pairs and
-- CheckVersionSequence.
SELECT 1;
