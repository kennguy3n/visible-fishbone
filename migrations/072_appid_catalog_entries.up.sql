-- ShieldNet Gateway (SNG) — Application-ID catalog entries (WP1).
--
-- The per-application signature rows for each catalog version. The
-- authoritative distribution artifact is the signed bundle (073); these
-- rows are the queryable, structured projection of that same content so
-- an operator can inspect / diff a version's signatures in SQL without
-- decoding a bundle, and so a future re-sign (key rotation) can rebuild
-- the payload from stored entries rather than re-deriving it.
--
-- NOT tenant-scoped (global catalog; no RLS), same rationale as 071.
--
-- Each row is one application signature. The match keys mirror the Rust
-- catalog schema (crates/sng-appid): SNI/host suffixes, JA3 hints, and
-- small bounded byte-probe prefixes (hex strings), plus weak port /
-- transport modifiers. Arrays default to '{}' (never NULL) so the Go
-- and Rust models agree on "no values" without a null/empty split.
--
-- (serial, app_id) is the natural primary key: an app appears at most
-- once per version. The FK to appid_catalog_versions with ON DELETE
-- CASCADE keeps entries and their version row atomic — dropping a
-- version removes its entries. The PK's leftmost column (serial) also
-- serves the "all entries for version N, ordered by app_id" read and
-- the FK cascade lookup, so no secondary index is created.
--
-- Lock safety: CREATE TABLE on a brand-new empty table takes no
-- table-rewrite lock; no standalone CREATE INDEX.

CREATE TABLE IF NOT EXISTS appid_catalog_entries (
    serial        BIGINT    NOT NULL
                  REFERENCES appid_catalog_versions (serial) ON DELETE CASCADE,
    -- Stable application identifier, e.g. "microsoft.teams".
    app_id        TEXT      NOT NULL,
    -- Coarse grouping, e.g. "collaboration", "storage", "ai".
    category      TEXT      NOT NULL DEFAULT '',
    -- TLS SNI / HTTP Host suffix patterns (normalised dotted suffixes).
    sni_suffixes  TEXT[]    NOT NULL DEFAULT '{}',
    host_suffixes TEXT[]    NOT NULL DEFAULT '{}',
    -- Optional JA3 fingerprint hints (lowercase hex md5).
    ja3           TEXT[]    NOT NULL DEFAULT '{}',
    -- Small bounded byte-probe prefixes for non-TLS protocols (hex).
    byte_prefixes TEXT[]    NOT NULL DEFAULT '{}',
    -- Weak port / transport modifiers (never an identity on their own).
    ports         INTEGER[] NOT NULL DEFAULT '{}',
    transport     TEXT      NOT NULL DEFAULT 'tcp'
                  CHECK (transport IN ('tcp', 'udp', 'any')),
    -- Base confidence contributed by a content match, in [0,100].
    confidence    INTEGER   NOT NULL DEFAULT 0
                  CHECK (confidence >= 0 AND confidence <= 100),

    PRIMARY KEY (serial, app_id)
);
