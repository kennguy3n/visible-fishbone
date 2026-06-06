-- Reverse migration 045 (down): remove the regional trusted-app seed
-- rows. Deletes strictly by the names seeded in the up migration so
-- the 009 baseline rows and any operator-curated regional apps (added
-- via the admin API) are left untouched.
DELETE FROM app_registry
WHERE scope = 'regional'
  AND name IN (
    -- SEA
    'Tokopedia', 'Shopee', 'DBS Bank', 'OCBC Bank', 'Maybank',
    -- GCC
    'Careem', 'Emirates NBD', 'Al Rajhi Bank', 'Saudi National Bank',
    'UAE PASS', 'Absher', 'Dubai Now',
    -- DACH
    'Swiss Post', 'PostFinance', 'UBS', 'ELSTER', 'oesterreich.gv.at'
  );
