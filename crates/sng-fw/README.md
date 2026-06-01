# sng-fw

Firewall engine for the ShieldNet Gateway edge VM. Translates the
NGFW slice of a verified policy bundle (consumed via
`sng-policy-eval`) into a deterministic nftables rule set, with
zone-based segmentation, conntrack-aware state tracking, NAT
(SNAT / DNAT / masquerade), L7 application identification (HTTP /
TLS-SNI / DNS / QUIC / SSH / RDP / SMB), and a TLS interception
policy that respects industry-standard "do not decrypt" lists.

The crate is trait-based at every external boundary
(`NftablesBackend`) so the unit + integration test suites run
without root, without an actual `nft` binary, and without touching
the kernel; the in-tree mock backend captures the rule text the
production `ShellNftables` impl would shell out to `nft -f` so the
test assertions check the wire-format the kernel sees.

## Module layout

* `rule` — `FirewallRule`, `RuleAction`, `RuleMatch`,
  `Protocol`, the closed set of L3 / L4 predicates.
* `zone` — `Zone`, `ZonePolicy`, `ZoneTable`, default-deny
  inter-zone segmentation.
* `nat` — SNAT / DNAT / masquerade rule generation.
* `conntrack` — `ConntrackState` state machine for stateful
  filtering (`NEW` / `ESTABLISHED` / `RELATED` / `INVALID`).
* `l7` — protocol signature identification, TLS SNI extraction,
  HTTP host / URI matching, `AppId` to `TrafficClass` mapping.
* `tls_policy` — decrypt vs. bypass decision engine, industry
  default "do not decrypt" list, operator-controlled bypass
  categories.
* `compile` — turns the NGFW rule slice of a `LoadedBundle`
  into a `CompiledRuleSet` (rule set + zone table + NAT table)
  plus a deterministic nftables script.
* `nftables` — `NftablesBackend` trait + `ShellNftables`
  (production `nft -f` shell-out) + `MockNftables` (tests).
* `engine` — top-level `FirewallEngine` that owns the compiled
  rule set, hot-swaps it atomically on bundle rotation, and
  exposes the per-flow evaluation surface the data path queries.

## Wire compatibility

The serialised rule / zone / NAT shapes round-trip through the
Go-side compiler output (`internal/service/policy/`); inline
matchers reuse the `sng-policy-eval::matcher::SubjectMatch` enum
so an `ngfw` rule in a graph compiles into the same predicate
tree the SWG / DNS subsystems see.
