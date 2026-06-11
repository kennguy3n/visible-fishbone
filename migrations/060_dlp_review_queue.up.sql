-- Migration 060: human-in-the-loop DLP review queue.
--
-- The endpoint DLP engine's AI-app exfiltration signal (crates/sng-dlp,
-- `ai_app`) is COACH-FIRST: by default it monitors/coaches and does not
-- block, to avoid false-positive backlash. Flagged uploads that warrant
-- a human decision land here, in a per-tenant review queue, where a
-- reviewer approves, blocks, or dismisses them. This table is the
-- durable backing store for `internal/service/dlpreview`.
--
-- Privacy posture: a row stores ONLY redacted aggregates about a
-- flagged upload — the destination app id, severity, a confidence
-- score, and an `evidence_redacted` JSON document of finding *summaries*
-- (kind/label/count/severity, never the matched bytes). No raw payload,
-- match span, or surrounding content is ever persisted. This mirrors the
-- redaction invariant the Rust signal enforces (its `AiAppSignal` is
-- metadata-only), so the queue cannot become a secondary copy of the
-- very data it is protecting.
--
-- Tenant isolation: the table is RLS-scoped under the same
-- `sng.tenant_id` GUC as every other tenant table, with FORCE ROW LEVEL
-- SECURITY so even the table owner is constrained. One tenant can never
-- read or decide another tenant's queued events.
--
-- State machine: `state` starts at 'pending' and transitions exactly
-- once to a terminal state ('approved' | 'blocked' | 'dismissed'). The
-- audit columns (`decided_at`, `decided_by`) are populated iff the row
-- is terminal — enforced by a CHECK so a half-recorded decision is
-- impossible at the storage layer, not just in application code.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, and the two indexes are built on that same
-- brand-new table in the same migration, so they hold no meaningful
-- lock (and CONCURRENTLY would be illegal inside the migration's
-- implicit transaction). See internal/migrate/validator.go.

CREATE TABLE IF NOT EXISTS dlp_review_queue (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The signal that produced the event, e.g. 'ai_app_upload'. Kept as
    -- free-ish text (not an enum) so a new endpoint signal can feed the
    -- same queue without a schema migration.
    signal              TEXT        NOT NULL CHECK (signal <> ''),
    -- Stable AI-app id from the Rust catalog (e.g. 'chatgpt') or the
    -- 'suspected_ai_app' sentinel for a long-tail heuristic match. Never
    -- a full URL — only the app identity, so no path/query is stored.
    destination_app     TEXT        NOT NULL CHECK (destination_app <> ''),
    -- Mirrors the Rust `Severity` ladder.
    severity            TEXT        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    -- Detector confidence in [0,1] that the upload is a real exposure.
    confidence          DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    -- Review state machine; 'pending' until a human decides.
    state               TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (state IN ('pending', 'approved', 'blocked', 'dismissed')),
    -- Redacted finding aggregates ONLY (see header). Defaults to an
    -- empty JSON array so the column is never NULL.
    evidence_redacted   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Audit trail of the decision. Both NULL while pending; both set
    -- once terminal (enforced by the CHECK below). `decided_by` is the
    -- reviewer's stable actor id (never PII-bearing free text).
    decided_at          TIMESTAMPTZ,
    decided_by          TEXT,
    CONSTRAINT dlp_review_queue_decision_consistency CHECK (
        (state = 'pending'  AND decided_at IS NULL     AND decided_by IS NULL)
        OR
        (state <> 'pending' AND decided_at IS NOT NULL AND decided_by IS NOT NULL)
    )
);

ALTER TABLE dlp_review_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_review_queue FORCE ROW LEVEL SECURITY;

CREATE POLICY dlp_review_queue_tenant_isolation ON dlp_review_queue
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- The hot read path is "show me this tenant's pending backlog, newest
-- first". A partial index over only pending rows keeps the index small
-- (terminal rows, the vast majority over time, are excluded) and serves
-- both the reviewer queue and the digest's pending count directly.
CREATE INDEX IF NOT EXISTS dlp_review_queue_pending_idx
    ON dlp_review_queue (tenant_id, created_at DESC)
    WHERE state = 'pending';

-- General per-tenant, per-state listing / aggregation (the digest groups
-- by state and severity over a time window).
CREATE INDEX IF NOT EXISTS dlp_review_queue_tenant_state_idx
    ON dlp_review_queue (tenant_id, state, created_at DESC);
