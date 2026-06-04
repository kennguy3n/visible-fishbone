# sng-dlp

Endpoint Data Loss Prevention (DLP) for the ShieldNet Gateway
desktop agent (`sng-agent`).

Where `internal/service/dlp` on the control plane handles web / SaaS
DLP (content posted through the SWG / CASB path), this crate is the
endpoint half: it inspects content as it crosses on-device egress
**channels** — clipboard paste, file write, print spool, USB copy,
browser upload — and emits a verdict the agent enforces locally.

## Pipeline

```text
sng-pal channel hook → ContentEvent (channel + bytes + metadata) ↓
ContentClassifier     → ClassificationResult (matched rule ids)    ↓
DlpEngine             → DlpVerdict (allow / warn_user / block / log)
```

## Surface

- **`DlpRule`** (`rules`) — a single detector: `id`, `name`,
  `pattern_type` (`regex` / `keyword` / `fingerprint` / `mip_label`),
  `pattern_data`, `severity`, `action`, and the `channels` it applies
  to. Compiled from the endpoint policy bundle.
- **`ContentClassifier`** (`classifier`) — applies the compiled rule
  set to a content buffer. Detection methods: compiled `regex`
  `RegexSet` for patterns, an `aho-corasick` automaton for keyword
  dictionaries, Microsoft Information Protection (MIP) label
  membership, and SimHash document fingerprinting (wire-compatible
  with the Go `fingerprint.go` SimHash).
- **`DlpChannel`** (`channels`) — the egress channel taxonomy plus
  the `ChannelInterceptor` contract `sng-pal` implements per OS.
- **`DlpPolicy`** (`policy`) — the active rule set + per-channel
  configuration, deserialised from the endpoint bundle (policy graph
  domain `dlp`).
- **`DlpEngine`** (`engine`) — orchestrates classification + policy
  evaluation and produces a `DlpVerdict`. Rule reads are lock-free
  (`arc-swap`); the policy hot-swaps atomically.

## Redaction invariant

The crate **never** serialises raw DLP-matched bytes. A
`ClassificationResult` carries only match *metadata* — the matched
rule id, the byte offset / length of the hit, and a confidence
score — so a leaked verdict event can never reconstruct the
sensitive payload that triggered it. This mirrors the
`sn360-desktop-agent` redaction invariant.
