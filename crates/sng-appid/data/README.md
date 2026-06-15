# App-ID seed catalog

`catalog.json` is the **canonical** seed signature catalog for the
ShieldNet Gateway application-identification subsystem. It is embedded
into the Rust data plane at compile time via `include_str!` (see
`crates/sng-appid/src/catalog.rs`) and is the baseline the matcher uses
before the control plane pushes a signed bundle.

## Schema (`schema_version: 1`)

```jsonc
{
  "schema_version": 1,
  "apps": [
    {
      "app_id":       "microsoft.teams",   // stable, unique identifier
      "category":     "collaboration",     // coarse grouping
      "sni_suffixes": ["teams.microsoft.com"], // TLS SNI host suffixes
      "host_suffixes":["teams.microsoft.com"], // HTTP Host suffixes
      "ja3":          [],                  // optional JA3 hint hashes
      "ports":        [443],               // port hints (modifier only)
      "transport":    "tcp",               // tcp | udp
      "byte_prefixes":[],                  // hex leading-byte probes
      "confidence":   90                   // base confidence 0..=100
    }
  ]
}
```

Matching is **longest-suffix wins** on dotted label boundaries, so
listing an apex (`slack.com`) also identifies `files.edge.slack.com`.
An entry must declare at least one *content* signal (`sni_suffixes`,
`host_suffixes`, `ja3`, or `byte_prefixes`); a bare port/transport
entry is rejected because a port is only a weak modifier, never an
identity on its own.

## Cross-language sync (IMPORTANT)

There are **two byte-content copies** of this catalog, kept identical:

1. `crates/sng-appid/data/catalog.json` — canonical, embedded by Rust.
2. `internal/service/appid/catalog_seed.json` — embedded by Go
   (`//go:embed`). Go's `embed` cannot reference a path outside its own
   package directory (no `..`), so the file is duplicated rather than
   symlinked.

Both copies are guarded by invariant tests on each side (entry count,
unique `app_id`s, valid categories, non-empty match keys). When you
change one, change the other to match. The curated source generator
lives outside the tree (it is a one-off authoring aid, not part of the
build); only the generated JSON is committed.
