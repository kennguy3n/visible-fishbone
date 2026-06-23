# Treat detection efficacy as a measured discipline

> **Build series, Post 7 of 10 — the quality model.** Reader: both, because
> "how good is your detection?" is the question that decides the deal and the
> on-call rota. The decision: *how do you know your security actually works, and
> how do you keep a noisy detector from sinking a small team?*

Most security products answer "how good is your detection?" with a logo wall and
a percentage with no denominator. That is not a discipline; it is marketing. If
you are building for a tiny operations team (Post 1), you cannot afford a noisy
product — every false positive is a human interruption you do not have staff for.
So efficacy has to be *measured, budgeted, and honestly published.*

## The build: a harness that drives the real enforcement code

SNG's efficacy harness (`bench/efficacy`) runs the **actual crate APIs** against
labelled corpora and emits a single report
([`efficacy-report.json`](../artifacts/efficacy-report.json), suite verdict
**PASS**). It scores **16 functions**, and the structure is the discipline:

- **Curated corpora, per function.** `firewall`, `firewall_kernel`, `swg`,
  `swg_ai_governance`, `swg_rbi`, `swg_dlp_inline`, `ztna`, `ztna_clientless`, `dlp`,
  `dlp_ml_ner`, `malware`, `dns`, `ips`, `dem` — each with bad and good cases,
  scored for catch rate *and* false-positive rate. On the curated sets the
  gating detectors run 100% catch / 0% false-positive (e.g. structured `dlp` at
  **3,800 bad / 3,800 good**, 100/0). The add-on capabilities are additionally
  covered by their crate unit tests (AI governance 24, inline DLP 22, RBI 16,
  clientless ZTNA 11, DEM 10).
- **Adversarial corpora.** `malware_adversarial` and `ips_adversarial` —
  evasion-shaped inputs — both hold 100%.
- **Wild corpora.** `malware_wild`, `dlp_wild`, `ips_wild` — noisy,
  real-world-shaped traffic — to find where the curated number stops being true.
- **False-positive load corpora.** `malware_fpr_load` and `dlp_fpr_load` —
  all-benign sets sized to measure the false-positive rate under volume.

The numbers carry a verdict each (`PASS` / `WARN`), and throughput is reported
alongside accuracy so "accurate but too slow to matter" is visible: ZTNA
evaluates at **1.81M decisions/s** (551.8 ns/op), structured DLP classifies at
**830,540 scans/s under load** (180.2 MB/s).

## The honesty that makes it a discipline

The load-bearing decision is what happens when a number is *bad*. On wild
traffic, `malware_wild` catches **90.1%** with a **9.6% false-positive rate** —
and the harness marks it **WARN, not PASS.** Crucially, **that WARN never
gates** a release, and the capability it measures runs **monitor-first, not
block-first.** We publish the 90.1% and the 9.6% in the same table as the 100%
curated numbers, because hiding the wild number would be the dishonest move. A
detector you cannot yet trust to block is run in monitor mode and labelled as
such — that is the difference between an efficacy *discipline* and an efficacy
*claim*.

## The business call: a false-positive budget is an operations budget

The scenario: **Lena, a SOC analyst,** has finite hours. A detector at 99% catch
but 5% false-positive rate will bury her in benign alerts and she will start
ignoring the channel — at which point the 99% catch is worthless. So SNG treats
the false-positive rate as a *budget* the product spends deliberately: gating
detectors must hit 0% FP on curated sets, anything noisier runs monitor-first
until it earns block. For the buyer, this is the promise that the product respects
the analyst's attention — which, for a team that cannot hire more analysts, is the
whole value proposition.

## How the incumbents approached it

- The incumbents publish **third-party lab results** (the AV-Comparatives /
  MITRE-ATT&CK / NSS-style evaluations) — credible, but periodic, externally run,
  and not reproducible by the buyer on demand.
- **Fortinet and Palo Alto** lean on FortiGuard / Unit 42 threat research and lab
  certifications as the efficacy story; the numbers are real but the buyer cannot
  re-run them.
- **Zscaler, Netskope, Cato** point to cloud-scale telemetry and lab results;
  again, trustworthy but not a `make`-able artifact in the buyer's hands.

SNG's distinctive call is an **in-repo, reproducible harness** that drives the
real enforcement code and publishes catch *and* false-positive numbers — including
the WARNs — as a regenerable artifact. It will never match a major lab's corpus
breadth, but it is honest and reproducible in a way a periodic certification is
not.

## Build it yourself

1. **Drive the real code, not a model of it.** The harness must call the same
   APIs production calls, or the number is fiction.
2. **Measure false positives explicitly,** with all-benign load corpora, and
   treat the FP rate as a budget — not an afterthought.
3. **Add wild and adversarial corpora** so you discover where the curated number
   stops being true, and publish those numbers next to the clean ones.
4. **Let bad numbers WARN, not gate** — and run the capabilities they measure in
   monitor mode until they earn block. Then publish everything.

## Where this approach falls short

- **Our corpora are small next to a major lab's.** The honest claim is
  *reproducible and transparent*, not *comprehensive*. A buyer should still want
  third-party validation.
- **Wild malware is genuinely not solved.** 90.1% / 9.6% is a real gap; running
  monitor-first is the honest mitigation, not a fix.
- **A harness can be gamed by its own corpora.** If you only test what you are
  good at, 100% means nothing. The discipline depends on adversarially-chosen
  corpora and the willingness to publish the WARNs — which is a cultural
  commitment (Post 10), not just code.
