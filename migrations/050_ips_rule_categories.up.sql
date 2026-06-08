-- ShieldNet Gateway (SNG) — IPS per-tenant rule categories migration.
--
-- Backs Workstream 3 Step 2: enhanced Suricata IPS rule management.
-- The edge (crates/sng-ips) categorises every Suricata rule into a
-- threat class (malware, exploit, lateral_movement, c2, exfiltration,
-- dos, other) derived from the rule's classtype/msg, and can drop a
-- whole category via crate sng_ips::rules::CategorySelection. The
-- control plane (internal/service/policy/ips_rules.go) stores one
-- enablement row per (tenant, category) here and compiles a
-- tenant-specific selection the edge enforces.
--
-- Adds two tables:
--   - ips_rule_categories      : per-tenant per-category enablement.
--   - ips_rule_category_stats  : per-tenant per-category daily hit
--                                counts (the "hits/day" stat the
--                                management API surfaces). Populated
--                                from the normalised IPS alert stream.
--
-- Both are RLS-scoped to `sng.tenant_id`, matching every other
-- tenant-scoped table.

-- Per-tenant category enablement. A missing row means the category
-- is enabled (fail-open: a fresh tenant gets full coverage), so this
-- table holds only explicit operator overrides. The category string
-- is constrained to the known set; the edge's RuleCategory enum and
-- the Go IPSRuleCategory constants share these exact ids.
CREATE TABLE IF NOT EXISTS ips_rule_categories (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    category    TEXT        NOT NULL
                CHECK (category IN
                    ('malware', 'exploit', 'lateral_movement',
                     'c2', 'exfiltration', 'dos', 'other')),
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, category)
);

-- Hot-path: "list this tenant's category overrides". The PK already
-- indexes (tenant_id, category); this partial index serves the
-- compile path that reads only the disabled categories to subtract.
CREATE INDEX IF NOT EXISTS idx_ips_rule_categories_tenant_disabled
    ON ips_rule_categories (tenant_id) WHERE enabled = FALSE;

CREATE TRIGGER ips_rule_categories_set_updated_at
    BEFORE UPDATE ON ips_rule_categories
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE ips_rule_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE ips_rule_categories FORCE ROW LEVEL SECURITY;

CREATE POLICY ips_rule_categories_tenant_isolation ON ips_rule_categories
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- Per-tenant per-category daily hit counts. One row per
-- (tenant, category, day); the IPS alert ingestion path increments
-- `hits` as Suricata alerts are normalised, so the management API
-- can render a "hits/day" sparkline per category without scanning
-- the full alert table.
CREATE TABLE IF NOT EXISTS ips_rule_category_stats (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    category    TEXT        NOT NULL
                CHECK (category IN
                    ('malware', 'exploit', 'lateral_movement',
                     'c2', 'exfiltration', 'dos', 'other')),
    -- UTC calendar day the hits accrued on.
    day         DATE        NOT NULL,
    hits        BIGINT      NOT NULL DEFAULT 0
                CHECK (hits >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, category, day)
);

-- Hot-path: "hits for this tenant over the last N days", newest first.
CREATE INDEX IF NOT EXISTS idx_ips_rule_category_stats_tenant_day
    ON ips_rule_category_stats (tenant_id, day DESC);

CREATE TRIGGER ips_rule_category_stats_set_updated_at
    BEFORE UPDATE ON ips_rule_category_stats
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE ips_rule_category_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE ips_rule_category_stats FORCE ROW LEVEL SECURITY;

CREATE POLICY ips_rule_category_stats_tenant_isolation ON ips_rule_category_stats
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
