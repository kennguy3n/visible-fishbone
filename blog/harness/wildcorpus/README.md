# `wildcorpus` — deterministic noisy wild-traffic corpus generator

This generator emits the **wild-traffic** corpus replayed by
[`bench/efficacy`](../../../bench/efficacy) under sustained concurrent load to
produce the informational `*_wild` / `*_fpr_load` efficacy rows.

## Why a separate, noisier corpus

The curated FW/SWG/ZTNA/IPS/DLP/malware corpora in `bench/efficacy` are
*decision-boundary* corpora: every case is hand-placed on the correct side of a
rule, so they score ~100% **by construction**. That is a correctness proof of
the enforcement code — **not** a real-world catch rate.

This corpus is an honest, noisier signal. It blends benign and malicious
payloads at a realistic ratio across mixed file types and payload shapes, and
deliberately includes the two things a curated corpus omits:

- **benign-but-suspicious** traffic the signature engine genuinely flags —
  legitimate PE/ELF installers, real apps that call `String.fromCharCode`,
  interactive PDF forms carrying `/JavaScript` → **honest false positives**;
- **evasive / novel-packed** malware a signature engine genuinely misses —
  encrypted droppers with no static marker → **honest false negatives**.

It is still **synthetic, inert stand-in** content — NOT captured production
traffic. It does not establish a universal real-world catch rate; it is a
*noisier proxy* that surfaces FPR/FN behaviour the curated suite cannot.

## Determinism & provenance

The corpus is fully reproducible. A single seeded PRNG
(`math/rand`, default seed `0x0053475744` = ASCII `"SGWD"`) drives every random
choice **and** the final shuffle, so the same seed yields byte-identical
output. The artifact records its `seed` and an order-independent
`content_sha256` (per-entry SHA-256 digests sorted, then rolled) so a
regenerated corpus can be verified against the committed one regardless of
entry order.

```bash
# Regenerate the committed artifact in place (default --out path):
go run ./blog/harness/wildcorpus

# Verify determinism (sha256 must match the committed corpus):
go run ./blog/harness/wildcorpus -out /tmp/regen.json
jq -r .content_sha256 bench/efficacy/fixtures/wild/wild-corpus.json /tmp/regen.json
```

Flags: `-seed <int>` (default `0x0053475744`), `-scale <n>` (replicate every
family `n×`, default `1`), `-out <path>` (default
`bench/efficacy/fixtures/wild/wild-corpus.json`).

## Blend & size

| | |
| --- | --- |
| Schema | `sng-wild-corpus/v1` |
| Total samples | **2087** |
| Malicious | 457 (**21.9 %**) — target 20 % |
| Benign | 1630 (**78.1 %**) — target 80 % |
| YARA lane | 1342 samples |
| DLP lane | 745 samples |

The ~1-in-5 malicious density is **denser than live traffic on purpose**: it
gives each malicious class a statistically meaningful sample, so the catch-rate
per attack family is not dominated by sampling noise. The false-positive-rate
is therefore measured against the large benign majority (the ~80 % benign
slice), which is where production traffic actually lives.

## Schema

```jsonc
{
  "schema": "sng-wild-corpus/v1",
  "generator": "blog/harness/wildcorpus",
  "seed": 1398901060,
  "description": "...honesty caveats...",
  "blend": { "malicious_fraction_target": 0.20, "benign_fraction_target": 0.80 },
  "counts": { "total": 2087, "benign": 1630, "malicious": 457,
              "by_engine": { "yara": 1342, "dlp": 745 }, "by_family": { ... } },
  "content_sha256": "07b2e837...",
  "entries": [
    { "id": "yara-eicar-0000", "label": "malicious", "engine": "yara",
      "family": "eicar", "desc": "...", "payload_b64": "..." }
  ]
}
```

`label` is the ground truth (`malicious` | `benign`); `engine` routes the entry
to the YARA or DLP lane in the harness; `payload_b64` is the base64-encoded
raw bytes scanned.

## Payload families

29 families total: 16 malicious + 13 benign for YARA, 7 malicious + 6 benign
for DLP. The benign YARA set includes 4 *benign-but-suspicious* families
(installer PE/ELF, `fromCharCode` JS, interactive PDF form) that the
elevated-risk signature posture flags — the honest false positives. The benign
DLP set includes *near-miss* tokens (Luhn-invalid cards, malformed AWS keys)
that the structural validators must suppress. The malicious YARA set includes
`novel_packed_evasive` — an encrypted dropper with no static marker — the
honest false negative.
