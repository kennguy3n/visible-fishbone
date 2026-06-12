-- Deterministic DLP review-queue seed (illustrative).
--
-- In production the dlp_review_queue table is populated only by the
-- real enforcement path: the endpoint DLP engine's coach-first AI-app
-- exfiltration signal (crates/sng-dlp, `ai_app`) flags an upload it did
-- NOT block, and the control plane enqueues a redacted summary for a
-- human decision. There is deliberately no "create event" API — an
-- operator can only approve / block / dismiss.
--
-- For the blog's review-queue screenshot we therefore seed a handful of
-- pending rows directly, mirroring exactly the redacted shape the real
-- producer writes (kind/label/count/severity finding aggregates only —
-- never matched bytes). Re-run any time to reproduce the screenshot:
--
--   PGPASSWORD=sng psql -h 127.0.0.1 -U sng -d sng -f dlp_review_seed.sql
--
-- Idempotent: deletes the seeded rows for the Acme tenant first.

BEGIN;
SET LOCAL sng.tenant_id = '92112770-7c0a-410b-b0f4-09dde70e063a';

DELETE FROM dlp_review_queue
 WHERE tenant_id = '92112770-7c0a-410b-b0f4-09dde70e063a'
   AND state = 'pending';

INSERT INTO dlp_review_queue
    (tenant_id, signal, destination_app, severity, confidence, state, evidence_redacted, occurred_at, created_at)
VALUES
 ('92112770-7c0a-410b-b0f4-09dde70e063a','ai_app_upload','suspected_ai_app','critical',0.95,'pending',
   '[{"kind":"phi","label":"mrn","count":5,"severity":"critical"},{"kind":"pci","label":"credit_card_pan","count":8,"severity":"high"}]'::jsonb,
   NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour'),
 ('92112770-7c0a-410b-b0f4-09dde70e063a','ai_app_upload','chatgpt','high',0.88,'pending',
   '[{"kind":"pci","label":"credit_card_pan","count":3,"severity":"high"},{"kind":"pii","label":"email","count":12,"severity":"medium"}]'::jsonb,
   NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours'),
 ('92112770-7c0a-410b-b0f4-09dde70e063a','ai_app_upload','claude','medium',0.71,'pending',
   '[{"kind":"source_code","label":"private_key_block","count":1,"severity":"high"}]'::jsonb,
   NOW() - INTERVAL '7 hours', NOW() - INTERVAL '7 hours'),
 ('92112770-7c0a-410b-b0f4-09dde70e063a','ai_app_upload','gemini','low',0.42,'pending',
   '[{"kind":"pii","label":"phone_number","count":2,"severity":"low"}]'::jsonb,
   NOW() - INTERVAL '20 hours', NOW() - INTERVAL '20 hours');

COMMIT;
