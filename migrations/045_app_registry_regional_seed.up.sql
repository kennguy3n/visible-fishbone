-- 045_app_registry_regional_seed — Regional trusted-app lists
-- (Session 2B, Traffic Classification Optimization).
--
-- The baseline seed (009) covers globally-ubiquitous SaaS plus a first
-- tranche of regional apps (Grab, Gojek, LINE, Deutsche Bank, …). SME
-- tenants in our launch regions push a large share of their traffic to
-- *additional* regional apps — marketplaces, local banks and
-- government portals — that 009 does not list. Without them, that
-- traffic falls through to the inspect_full default and hits the
-- expensive cloud proxy, blowing the 10–20% cloud-proxied target
-- (docs/cost-model.md) and the $0.30–1.20/user/month envelope.
--
-- Region-code convention (MUST match migration 009 and
-- internal/region): each row carries a broad continental code AND the
-- specific ISO country codes it covers, e.g. {APAC,SG,MY}. The traffic
-- engine (internal/service/appdb) resolves a tenant's region marker to
-- a coarse GROUP (SEA / GCC / DACH) via internal/region and applies a
-- regional row only when one of the row's ISO codes resolves to the
-- same group. Broad codes (APAC/MENA/EU) are intentionally NOT used
-- for matching — they span more than one group — so every row below
-- pins the precise ISO codes that define its applicability.
--
-- Class/category follow 009's precedent for the same kinds of app:
-- regional banks, government portals and super-apps are inspect_lite
-- (kept off the expensive full cloud proxy, but still lightly
-- inspected — prudent for finance/government), mirroring 009's
-- Deutsche Bank / GOV.UK / Grab / Gojek rows.
--
-- Apps already seeded by 009 (Grab, Gojek, LINE) are NOT repeated, and
-- no domain seeded by 009 (e.g. *.bund.de via "Bundesregierung (DE)")
-- is duplicated. Idempotent: ON CONFLICT (name) DO NOTHING.

-- ---------------------------------------------------------------------
-- SEA — South-East Asia marketplaces and regional banks.
-- ---------------------------------------------------------------------
INSERT INTO app_registry (name, vendor, traffic_class, scope, regions, domains, category)
VALUES
    ('Tokopedia', 'GoTo Group', 'inspect_lite', 'regional',
     ARRAY['APAC', 'ID'],
     ARRAY['*.tokopedia.com', 'tokopedia.com', '*.tokopedia.net'],
     'ecommerce'),
    ('Shopee', 'Sea Limited', 'inspect_lite', 'regional',
     ARRAY['APAC', 'SG', 'ID', 'MY', 'TH', 'PH', 'VN'],
     ARRAY['*.shopee.com', 'shopee.com', '*.shopee.sg', '*.shopee.co.id',
           '*.shopee.com.my', '*.shopee.co.th', '*.shopee.ph'],
     'ecommerce'),
    ('DBS Bank', 'DBS', 'inspect_lite', 'regional',
     ARRAY['APAC', 'SG'],
     ARRAY['*.dbs.com.sg', 'dbs.com.sg', '*.dbs.com'],
     'finance'),
    ('OCBC Bank', 'OCBC', 'inspect_lite', 'regional',
     ARRAY['APAC', 'SG'],
     ARRAY['*.ocbc.com', 'ocbc.com'],
     'finance'),
    ('Maybank', 'Malayan Banking Berhad', 'inspect_lite', 'regional',
     ARRAY['APAC', 'MY'],
     ARRAY['*.maybank.com', '*.maybank2u.com.my', 'maybank2u.com.my'],
     'finance')
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------
-- GCC — Gulf super-app, regional banks, government portals.
-- ---------------------------------------------------------------------
INSERT INTO app_registry (name, vendor, traffic_class, scope, regions, domains, category)
VALUES
    ('Careem', 'Careem', 'inspect_lite', 'regional',
     ARRAY['MENA', 'AE', 'SA'],
     ARRAY['*.careem.com', 'careem.com', '*.careem-engineering.com'],
     'mobility'),
    ('Emirates NBD', 'Emirates NBD', 'inspect_lite', 'regional',
     ARRAY['MENA', 'AE'],
     ARRAY['*.emiratesnbd.com', 'emiratesnbd.com'],
     'finance'),
    ('Al Rajhi Bank', 'Al Rajhi Bank', 'inspect_lite', 'regional',
     ARRAY['MENA', 'SA'],
     ARRAY['*.alrajhibank.com.sa', 'alrajhibank.com.sa'],
     'finance'),
    ('Saudi National Bank', 'SNB', 'inspect_lite', 'regional',
     ARRAY['MENA', 'SA'],
     ARRAY['*.alahli.com', '*.snb.com', 'snb.com'],
     'finance'),
    ('UAE PASS', 'UAE Government', 'inspect_lite', 'regional',
     ARRAY['MENA', 'AE'],
     ARRAY['*.uaepass.ae', 'uaepass.ae'],
     'government'),
    ('Absher', 'Saudi Ministry of Interior', 'inspect_lite', 'regional',
     ARRAY['MENA', 'SA'],
     ARRAY['*.absher.sa', 'absher.sa'],
     'government'),
    ('Dubai Now', 'Government of Dubai', 'inspect_lite', 'regional',
     ARRAY['MENA', 'AE'],
     ARRAY['*.dubai.gov.ae', 'dubai.gov.ae'],
     'government')
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------
-- DACH — Swiss / German / Austrian post, banks, government services.
-- ---------------------------------------------------------------------
INSERT INTO app_registry (name, vendor, traffic_class, scope, regions, domains, category)
VALUES
    ('Swiss Post', 'Die Post', 'inspect_lite', 'regional',
     ARRAY['EU', 'CH'],
     ARRAY['*.post.ch', 'post.ch'],
     'logistics'),
    ('PostFinance', 'PostFinance', 'inspect_lite', 'regional',
     ARRAY['EU', 'CH'],
     ARRAY['*.postfinance.ch', 'postfinance.ch'],
     'finance'),
    ('UBS', 'UBS Group', 'inspect_lite', 'regional',
     ARRAY['EU', 'CH'],
     ARRAY['*.ubs.com', 'ubs.com'],
     'finance'),
    ('ELSTER', 'German Tax Administration', 'inspect_lite', 'regional',
     ARRAY['EU', 'DE'],
     ARRAY['*.elster.de', 'elster.de'],
     'government'),
    ('oesterreich.gv.at', 'Austrian Federal Government', 'inspect_lite', 'regional',
     ARRAY['EU', 'AT'],
     ARRAY['*.gv.at', 'oesterreich.gv.at'],
     'government')
ON CONFLICT (name) DO NOTHING;
