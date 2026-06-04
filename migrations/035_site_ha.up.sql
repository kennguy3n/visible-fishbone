-- 035_site_ha — Active/passive HA posture for site edge appliances.
--
-- Adds the control-plane side of Session C's edge HA feature: a
-- site can run a single edge VM (standalone, the default) or a
-- VRRP-class active/passive pair that fails the site VIP over
-- between two edge devices. The enforcement-plane half lives in
-- the `sng-ha` crate (wired into `sng-edge`); these columns let
-- the control plane record the operator's intent and the partner
-- device so dashboards / Terraform / the API can reason about a
-- site's failover topology.
--
--   * ha_mode            — 'standalone' | 'active_passive'. CHECK
--                          constraint mirrors `SiteHAMode` in
--                          internal/repository/types.go. Backfilled
--                          to 'standalone' for every existing site
--                          via the NOT NULL DEFAULT, so the column
--                          is safe to add to a populated table.
--   * ha_peer_device_id  — nullable FK onto devices(id), the
--                          partner edge in an active/passive pair.
--                          ON DELETE SET NULL: de-enrolling the
--                          peer device must not cascade-delete the
--                          site; it simply drops the pairing and
--                          the operator re-pairs a replacement.
--
-- RLS: `sites` already has tenant-isolation ROW LEVEL SECURITY
-- enabled in migration 001 (policy `sites_tenant_isolation` keyed
-- on the `sng.tenant_id` GUC). Adding columns to an existing
-- RLS-protected table inherits that policy, so no new policy is
-- required here.
ALTER TABLE sites
    ADD COLUMN IF NOT EXISTS ha_mode TEXT NOT NULL DEFAULT 'standalone'
        CHECK (ha_mode IN ('standalone', 'active_passive'));

ALTER TABLE sites
    ADD COLUMN IF NOT EXISTS ha_peer_device_id UUID REFERENCES devices(id) ON DELETE SET NULL;

-- Partial index on the partner FK: failover-topology lookups and
-- the integrity sweep that checks "is any site paired to this
-- device?" only ever care about rows that actually have a peer.
CREATE INDEX IF NOT EXISTS sites_ha_peer_device_idx
    ON sites (ha_peer_device_id)
    WHERE ha_peer_device_id IS NOT NULL;
