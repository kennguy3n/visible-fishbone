# sng-dns

DNS security subsystem for the ShieldNet Gateway agent and edge.
Wraps a recursive resolver (Unbound-class) with a per-tenant filter
chain (reputation feed → category filter → sinkhole) and emits
per-query events into the [`sng-telemetry`](../sng-telemetry)
pipeline.

The crate is trait-based at every external boundary
(`Resolver`, `Filter`) so the unit and integration test suites
run without network and without an external resolver binary.

## Module layout

* [`qtype`] — typed DNS query type + RCODE enums.
* [`wire`] — RFC 1035 wire-format encoder / decoder.
* [`error`] — [`DnsError`] mapped to
  [`sng_core::error::ErrorCode`].
* [`query`] — agent-facing [`DnsQuery`] / [`DnsResponse`] types
  plus `canonicalize_name` / `domain_suffix_match` helpers.
* [`filter`] — [`Filter`] trait + hot-swappable
  [`FilterChain`] with `combine_verdicts` semantics.
* [`reputation`] — exact-match reputation feed → `NXDOMAIN`.
* [`category`] — per-tenant per-category Allow / Log / Block.
* [`sinkhole`] — suffix-match list → synthetic A / AAAA.
* [`resolver`] — async [`Resolver`] trait, [`UdpResolver`]
  production impl, and [`StaticResolver`] for tests.
* [`service`] — end-to-end [`DnsService`] orchestrator that
  emits [`HandledQuery`] events into the `sng-telemetry`
  pipeline.

## Hot-swap

`FilterChain` rotates atomically against concurrent readers
via `arc_swap::ArcSwap` — same pattern as `sng-policy-eval`.
A new chain compiled from a freshly received policy bundle
replaces the live one without dropping in-flight queries.

## Wire format

`sng_dns::wire` is a hand-rolled RFC 1035 encoder / decoder
rather than an off-the-shelf parser so the subsystem can:

* Bound resident memory on a malformed packet (no recursive
  allocator behaviour from a third-party parser).
* Round-trip the exact byte sequence the resolver returned, so
  the integration tests can assert wire equality on the
  forwarded response.

## Local verification

```sh
cargo +1.85 test  -p sng-dns
cargo +1.85 clippy -p sng-dns --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
