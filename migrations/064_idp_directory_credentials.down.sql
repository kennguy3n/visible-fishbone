-- 064_idp_directory_credentials (down)
--
-- Drop the directory-credential secret store. The credentials are
-- operator-supplied secrets, not derived state: re-applying the up
-- migration creates an empty table that an operator must re-populate
-- through the admin surface.

DROP TRIGGER IF EXISTS idp_directory_credentials_set_updated_at ON idp_directory_credentials;

DROP TABLE IF EXISTS idp_directory_credentials;
