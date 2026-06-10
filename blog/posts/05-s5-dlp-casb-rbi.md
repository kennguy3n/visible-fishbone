# Keep regulated data from leaving: DLP, CASB, browser isolation (S5)

> **Post 5 of 8.** Personas: **Lena** (SOC) and **Tom** (compliance). Outcome:
> stop regulated data exfiltration with on-device ML classification, CASB
> visibility, and remote browser isolation — and an honest story about the three
> routes that used to be broken.

## The "broken routes" backstory

This scenario's three surfaces — DLP, CASB/Browser protection — were the most
honest finding of the whole audit. Walking all 31 console routes, three rendered
**"Could not load data (HTTP 404)"**: DLP, Browser protection, and Terraform/IaC.

The root cause wasn't a UI bug. These features had DB schema, services, HTTP
handlers, and full UI — but **no Postgres repository implementations** (only
in-memory ones used by tests), so they were never constructed or wired into the
router. `deps.DLP/Browser/Terraform` were nil and their routes were never
registered → stdlib 404.

We fixed it properly in [PR #116](https://github.com/kennguy3n/visible-fishbone/pull/116):
implemented the six missing Postgres repos (DLP policy/fingerprint/match/model,
Browser policy, Data classification) following the existing RLS repo pattern,
wired the three services into `main.go`, and added migration 054 so the `rbi`
browser-isolation action persists. We did **not** screenshot around the bug.

## Walking it in the console

DLP templates — compliance-pack starting points (PCI-DSS, HIPAA):

![DLP — templates](../artifacts/screenshots/s5-dlp-templates.png)

The classifier sandbox — paste content, see the live classification:

![DLP — classifier sandbox](../artifacts/screenshots/s5-dlp-classifier-sandbox.png)

CASB connectors — the seeded SaaS connectors (M365, Slack, Google, Salesforce):

![CASB — connectors](../artifacts/screenshots/s5-casb-connectors.png)

Browser protection policies — category actions including remote isolation (`rbi`):

![Browser protection — policies](../artifacts/screenshots/s5-browser-policies.png)

## The real classification behind it

The DLP classifier sandbox is backed by a real endpoint. The captured
request/response pair
([`s5-dlp-classify-request.json`](../artifacts/payloads/s5-dlp-classify-request.json)
→ [`s5-dlp-classify-response.json`](../artifacts/payloads/s5-dlp-classify-response.json))
shows content going in and labels coming out.

The efficacy matrix (Post 3) is where DLP earns its keep — it's the highest-volume
row by far:

- **`dlp` (1100 cases):** the `ContentClassifier` over generated Asia + GCC
  national-ID corpora. Valid identifiers (correct check digit) must be detected;
  same-length identifiers with a *wrong* check digit must be suppressed by the
  validators. 550 bad / 550 good, zero false positives. This is the check-digit
  validation doing real work — it's not a regex that fires on anything that looks
  like a number.
- **`dlp_ml_ner` (31 cases):** real on-device **ONNX NER** (`ner_v1.onnx`) over a
  labelled PII corpus across six entity classes, with benign and
  capitalised-non-name controls. Spec targets were precision > 0.90 and recall >
  0.85; the run cleared them.

## How it works under the hood

- **On-device ML, not a cloud round-trip.** The NER model runs locally via ONNX
  Runtime. (It needs `libonnxruntime.so` present — the environment blueprint
  provisions it; without it, those tests are labeled and skipped rather than
  faked.)
- **Validators, not just matchers.** National-ID detection validates check
  digits, which is why the 550 invalid controls produce zero false positives.
- **RBI as a policy action.** Remote browser isolation is a first-class action in
  the browser-policy model (migration 054), so "isolate uncategorized sites" is a
  policy verdict, not a bolt-on.
- **Tier differentiation is real.** Umbrella (starter) has **zero** DLP policies
  — captured deliberately as
  [`s5-umbrella-dlp-policies-emptystate.json`](../artifacts/payloads/s5-umbrella-dlp-policies-emptystate.json)
  — so the empty state in the UI is an honest tier difference, not a load failure.

## Edge-driven wake: classify on-write, not on a timer

On-device DLP only matters if it catches an exfiltration *as it happens*. The
endpoint monitors used to busy-poll — a fixed 50 ms async poll per channel — which
both burned CPU on idle endpoints and added up to 50 ms of detection latency.
[PR #135](https://github.com/kennguy3n/visible-fishbone/pull/135) replaces that
with an **edge-driven wake** in `sng-pal`:

- **inotify file-write monitor + X11 clipboard monitor** now pulse a
  `tokio::sync::Notify` the moment the kernel reports a write or the X selection
  changes, mirroring the existing udev wake on the USB-transfer monitor. The
  classifier consumer parks on `notified()` instead of spinning, with a defensive
  shutdown-poll fallback only.
- Because `Notify` stores a permit when no waiter is parked, an event that races
  the await is **never lost** — correctness doesn't depend on the timing of the
  wake.
- The result: the fixed ~20 wakeups/sec/channel idle busy-poll is gone, and
  write-to-detection latency drops from up-to-50 ms to ~0. The same release adds
  native macOS (FSEvents / Pasteboard / IOKit) and Windows (RDCW / clipboard /
  WMI / spooler / WFP) endpoint-DLP backends so the on-write trigger is uniform
  across platforms.

This is a *trigger* change, not a detection-quality change: the same
`ContentClassifier` and ONNX NER from the matrix above run on the woken content —
they just run sooner and without the idle tax.

## Where we fall short

- **Corpus is synthetic.** As with all of Post 3: the 1100-case result proves the
  validators and the classifier code are correct on a decision-boundary corpus,
  not that real document exfiltration is caught at that rate.
- **NER is six entity classes.** A mature DLP suite ships dozens of
  jurisdiction-specific detectors and document fingerprinting at scale. Ours is a
  credible on-device core.
- **CASB is connector-shaped, not full inline-CASB-at-scale.** We model
  connectors and inline rules; we don't claim the SaaS API coverage of a
  dedicated CASB vendor.

## Competitive note

On-device ML DLP is genuinely differentiated against appliance-era DLP that
backhauls content to a scanner. The honest comparison target is Netskope and
Zscaler's data-protection tiers — both deep, both cloud-scanning-heavy. SNG's
on-device inference is a latency and privacy story (content doesn't leave the
endpoint to be classified); the gap is detector breadth and managed-corpus
maturity.

Next: the AI assistant — and why it has a verifier, not a vibe.
