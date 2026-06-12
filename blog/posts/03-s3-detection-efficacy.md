# Detection efficacy: the catch-rate matrix (S3)

> **Post 3 of 8.** Persona: **Lena**, MSP SOC analyst. Outcome: high catch-rate,
> low false-positive load — and, crucially, *numbers that come from the real
> enforcement code*, not a slide.

## What "efficacy" means here (read this first)

This is the post where it's easiest to lie with statistics, so here's exactly
what the numbers are and aren't:

- The efficacy harness ([`bench/efficacy`](../../bench/efficacy)) drives the
  **real crate APIs** — `YaraEngine::scan`, `ZtnaService::evaluate`, the SWG
  `ExtAuthzHandler` categorize→deny-list path, the DNS `ThreatIntelSinkhole`
  Bloom matcher, the `sng-dlp` `ContentClassifier`, and Suricata via SNG's
  rendered config. These are not re-implementations for the benchmark.
- The **gating corpora are curated** — generated national-ID strings with
  valid/invalid check digits, EICAR/PE/ELF/macro/ransomware malware samples,
  known-bad threat feed domains, labelled PII sentences. They exercise the
  decision boundary, so a 100% catch-rate means "the real code classified every
  curated case correctly," not "SNG catches 100% of all real-world threats."
- This cycle we **also added the harder measurements** the earlier drafts said
  were missing: a kernel-enforcement leg, adversarial/evasion corpora, and a
  larger **wild** corpus with a **published false-positive rate under load**.
  Those rows are reported separately and explicitly marked informational — a
  wild catch-rate is never used as a gate, and we publish the FPR even when it's
  ugly.

With that contract stated, here is the full matrix, captured verbatim from
[`efficacy-report.json`](../artifacts/efficacy-report.json) (suite verdict:
**PASS**, git `c3d99ce`). The first block is the **gating** corpus (correctness
of the enforcement code); the second is the **adversarial** corpus; the third is
the **wild / FPR-under-load** corpus, which is informational by design:

| function | crate | kind | cases | catch | FPR | acc | verdict |
| --- | --- | --- | ---: | ---: | ---: | ---: | :---: |
| firewall | sng-fw | enforcement | 12 | 1.000 | 0.000 | 1.000 | PASS |
| firewall_kernel | sng-fw | enforcement | 12 | 1.000 | 0.000 | 1.000 | PASS |
| swg | sng-swg | enforcement | 11 | 1.000 | 0.000 | 1.000 | PASS |
| ztna | sng-ztna | enforcement | 20 | 1.000 | 0.000 | 1.000 | PASS |
| dlp | sng-dlp | detection | 4800 | 1.000 | 0.000 | 1.000 | PASS |
| dlp_ml_ner | sng-dlp | detection | 47 | 0.974 | 0.000 | 0.979 | PASS |
| malware | sng-swg | detection | 14 | 1.000 | 0.000 | 1.000 | PASS |
| dns | sng-dns | detection | 23 | 1.000 | 0.000 | 1.000 | PASS |
| ips | sng-ips | detection | 13 | 1.000 | 0.000 | 1.000 | PASS |
| malware_adversarial | sng-swg | detection | 61 | 1.000 | 0.000 | 1.000 | PASS |
| ips_adversarial | sng-ips | detection | 14 | 1.000 | 0.000 | 1.000 | PASS |
| malware_wild | sng-swg | detection | 1342 | 0.901 | 0.096 | 0.903 | WARN (info) |
| malware_fpr_load | sng-swg | detection | 1040 | 1.000 | 0.096 | 0.904 | WARN (info) |
| dlp_wild | sng-dlp | detection | 745 | 1.000 | 0.000 | 1.000 | PASS (info) |
| dlp_fpr_load | sng-dlp | detection | 590 | 1.000 | 0.000 | 1.000 | PASS (info) |
| ips_wild | sng-ips | detection | 13 | 1.000 | 0.000 | 1.000 | PASS (info) |

Three things changed materially since the last draft, and they're the whole
point of this cycle:

- **`firewall_kernel` is now a real row.** The SNG-rendered ruleset was installed
  in a network namespace and each corpus flow's verdict was read back from the
  kernel forward path (veth + nft counter). No kernel/userspace divergence — the
  earlier "methodology-only on this VM" caveat is retired.
- **Adversarial corpora exist.** `malware_adversarial` (61 packed/polymorphic /
  archive-nested / double-extension samples) and `ips_adversarial` (14 evasion
  PCAPs) both clear at 100% — the cases signature engines are supposed to
  struggle on are now measured, not hand-waved.
- **A wild corpus with a published FPR.** `malware_wild` replays a 1,342-sample
  noisy corpus (seeded, reproducible) through the **real** YaraEngine and reports
  an honest **90.1% catch / 9.6% FPR** — far below the 100% gating number,
  exactly as a real-traffic measurement should be. It is *informational*: it
  never gates the suite, and we'd rather show the 9.6% than hide it.

The highest-volume gating row by far is **DLP** (4,800 + 47 cases) — the
on-device ML story we go deep on in Post 5. That post also covers the
**edge-driven wake**
([PR #135](https://github.com/kennguy3n/visible-fishbone/pull/135)) that fires the
classifier the instant a file is written or the clipboard changes, rather than on
a fixed poll — the detection-*trigger* counterpart to this catch-rate matrix.

## What each row actually verified (the honest notes)

The report carries a `notes` field per function. These are the caveats that keep
the matrix honest:

- **firewall:** verified the **fail-closed default** (no ruleset → Deny) and that
  the SNG-rendered nftables ruleset is accepted by the kernel parser
  (`nft -c -f -` exit 0).
- **firewall_kernel:** the rendered ruleset was **installed in a network
  namespace** and every corpus flow's verdict read back from the kernel forward
  path (veth + nft counter) — kernel enforcement matches the userspace engine on
  all 12 flows. This is the leg the earlier draft could not run on a VM without
  `nft`; it now runs here.
- **swg:** real categorize→deny-list path; malware/phishing/gambling/adult
  blocked, sanctioned + uncategorized permitted.
- **ztna:** real brokering denies unknown app/device/identity, stale posture,
  stale MFA, missing entitlement, and **cross-tenant requests**; admits
  authorized engineers on compliant devices.
- **dns:** real Bloom sinkhole + tunneling detector; known-bad domains *and their
  subdomains* sinkholed with allowlist override; encoded-QNAME / query-volume /
  TXT-abuse tunneling flagged.
- **malware:** real `YaraEngine::scan` over the **signed** built-in rule set;
  benign text/scripts/macro-free docs pass clean.
- **ips:** real **Suricata 6.0.4** driven by SNG's `ConfigGenerator`-rendered
  `suricata.yaml`, offline PCAP replay in IDS mode, EVE alerts normalised through
  `sng_ips::EveAlert::to_ips_event`.
- **adversarial (`malware_adversarial` / `ips_adversarial`):** the same engines
  replayed against packed/polymorphic, archive-nested, and double-extension
  malware samples and Suricata evasion PCAPs — the evasion classes the previous
  draft admitted it didn't measure.
- **wild (`malware_wild` / `*_fpr_load` / `ips_wild`):** a 2,087-sample noisy
  corpus (~22% malicious, seeded and reproducible) replayed through the real
  YaraEngine + DLP classifier + Suricata-over-PCAP **under load**. These rows
  carry honest false positives and false negatives and are reported as
  informational — they exist precisely so the 100% gating numbers aren't mistaken
  for a wild catch-rate.

## Walking it in the console

Detection lands in the Alerts surface. The anomaly view plots z-score outliers;
the table below carries the per-alert evidence:

![Alerts — anomaly scatter](../artifacts/screenshots/s3-alerts-anomaly-scatter.png)

These alerts are real anomaly-detector output. From
[`s3-acme-alerts.json`](../artifacts/payloads/s3-acme-alerts.json), one row on the
`newly_registered_domain_hits` dimension carries a full EWMA evidence envelope:

```json
{
  "dimension": "newly_registered_domain_hits",
  "baseline_mean": 9.148, "baseline_stddev": 3.411,
  "evidence": { "alpha": 0.1, "baseline_ewma": 8.883, "...": "..." }
}
```

The detector is an EWMA z-score model: it keeps an exponentially-weighted moving
baseline per dimension and flags deviations, so the "evidence" is the actual
statistical state that produced the alert — not an opaque score.

## Where we fall short

This is the post where the gap list shrank the most this cycle — three of the
four caveats from the previous draft are now measured rows above. What honestly
remains:

- **The wild corpus is seeded, not a live tap.** `malware_wild`'s 90.1% catch /
  9.6% FPR is a real measurement through the real engine over its 1,342-sample
  slice (the full wild corpus is 2,087 samples, ~22% malicious, shared across the
  malware + DLP wild rows). But it is a *seeded, reproducible* noisy corpus, not
  a live production traffic capture. It's a far better signal than the gating
  corpus alone — it just isn't a tap on a real network, which would need a
  labelled capture this VM doesn't have.
- **The 9.6% FPR is a number to improve, not celebrate.** Publishing it is the
  honest move; it is still higher than a production deployment would tune for,
  and lowering it (corpus-specific allowlisting, score thresholds) is real work
  ahead, not a solved problem.
- **IPS still needs Suricata present.** The IPS rows are real here because
  Suricata 6.0.4 is installed; on a host without it, those rows are
  methodology-only — unchanged, and stated.
- **ML-NER isn't perfect, and we don't round it up.** `dlp_ml_ner` is 97.4%
  catch / 97.9% accuracy, not 100% — reported as measured.

## Competitive note

Catch-rate marketing is universal in this space and almost never reproducible.
What's defensible about SNG's number is that the harness is in-repo, drives the
real code, and ships its corpora — so the claim is *auditable*. That's a
different (and rarer) thing than a vendor's "99.x% efficacy" footnote.

Next: retiring the VPN with zero-trust access.
