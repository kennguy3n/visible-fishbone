# AI-assisted operations — with a verifier, not a vibe (S6)

> **Post 6 of 8.** Personas: **Lena** (SOC) and **Devraj** (SME). Outcome: faster
> *and safe* operations. The headline: SNG's AI features are grounded in the
> compiled policy graph and gated by a deterministic verifier, so a model
> hallucination can't become an enforced policy.

## The thesis: AI proposes, the policy engine disposes

Most "AI in security" features are a chat box wired to a model. SNG's design
principle is the opposite: the model is an *assistant*, and every answer that
touches enforcement is either (a) re-derived deterministically from the compiled
bundle, or (b) checked by a verifier before it can be applied. When the model is
unavailable, the deterministic path still works.

## Walking it in the console

The natural-language policy query. Asking *"Can user finance access app
private-apps from a managed device?"* returns a grounded verdict with a citation:

![AI assistant — NL policy query](../artifacts/screenshots/s6-assistant-nl-policy-query.png)

Note the badge: **"Compiled-Bundle · Deterministic."** This answer did **not**
come from an LLM.

## The real response behind it

Verbatim from
[`s6-acme-nl-policy-query-response.json`](../artifacts/payloads/s6-acme-nl-policy-query-response.json):

```json
{
  "verdict": "inspect",
  "evaluation_mode": "compiled-bundle",
  "matched_rules": ["policy-graph:b70aebd7-7706-40ca-b8e7-c18b8d5e9c30@v1"],
  "ai_generated": false,
  "confidence": 0.7,
  "explanation": "Verdict \"inspect\" from tenant policy graph ... for
    user=finance, app=private-apps. Note: user-subject rules were not evaluated
    — user identity is not represented in the synthesized access envelope, so
    this verdict reflects only app/device and default-action matching."
}
```

Three things make this trustworthy:

1. `ai_generated: false` and `evaluation_mode: compiled-bundle` — the verdict is
   the *real* policy evaluator's output, parsed from a natural-language question
   by a deterministic intent parser, then evaluated against the compiled graph.
   No model was consulted to produce the verdict.
2. `matched_rules` cites the exact policy graph and version — the answer is
   auditable back to a rule.
3. The `explanation` self-discloses its own limitation. It does not invent a
   user-identity verdict it can't support.

## The posture report

The AI posture report (`GET /ai/reports/posture`) is similarly grounded. From
[`s6-acme-posture-report.json`](../artifacts/payloads/s6-acme-posture-report.json):

```json
{
  "ai_generated": false,
  "policy_health": { "active_policies": 10, "total_policies": 12,
                     "coverage_pct": 83.33 },
  "overview": { "total_alerts": 4, "alerts_by_severity":
                { "critical": 1, "warning": 3 }, "trend": "degrading" },
  "recommendations": [
    "Investigate 1 critical alert(s) immediately.",
    "Alert volume is increasing; review detection thresholds.",
    "4 alert(s) remain open; prioritise triage."
  ]
}
```

That `coverage_pct: 83.33` (10 of 12 policies active) is itself a bug we fixed:
`PolicyCounts` used to hard-error on a legacy-graph parse and 500 the whole
report. We made it mirror the compiler's verbatim-rules fallback — it now counts
the live graph and only reports an honest `0/0` for a truly opaque graph
([PR #119](https://github.com/kennguy3n/visible-fishbone/pull/119)).

## Playbooks: human-in-the-loop automation

Automated response runbooks gate on approval. Acme's seeded playbooks fire on
real trigger conditions:

![Playbooks](../artifacts/screenshots/s6-playbooks.png)

From [`s6-acme-playbooks.json`](../artifacts/payloads/s6-acme-playbooks.json), the
"Quarantine PCI cardholder-data exfil" playbook:

```json
{
  "name": "Quarantine PCI cardholder-data exfil",
  "trigger_condition": "dlp.violation && dlp.template == 'pci-dss'",
  "steps": [
    { "action": "block_transfer" },
    { "action": "require_approval", "role": "security_admin" },
    { "action": "notify", "channel": "soc" }
  ],
  "enabled": true
}
```

The `require_approval` step is the point: automation proposes a containment
action; a human signs off before it executes. Globex's set
([`s6-globex-playbooks.json`](../artifacts/payloads/s6-globex-playbooks.json))
even includes a deliberately *disabled* "Revoke access on impossible travel"
playbook — staged but not armed — so the enabled/disabled distinction is real.

The same human-in-the-loop principle now has a dedicated data-plane sibling: the
**DLP review queue** (`internal/service/dlpreview`, migration 060) shipped this
cycle, where coach-first AI-app DLP events that aren't auto-resolved wait for a
human verdict (`pending → approved / blocked / dismissed`) instead of being
silently enforced. It's walked in [Post 5](05-s5-dlp-casb-rbi.md) and
[business Post B3](business/10-ai-dlp-coaching.md) — and, honestly, it still
needs an operator console API before it's reachable end-to-end. (#158)

## The model itself (and the deterministic fallback)

The default model is the self-hosted **Ternary-Bonsai-8B**
([PR #102](https://github.com/kennguy3n/visible-fishbone/pull/102) /
[fishbone-access #35](https://github.com/kennguy3n/fishbone-access/pull/35)), with
compact-model prompt adaptation and a hardened JSON-extraction path.

This cycle pinned the *exact* artifact rather than "whatever the registry serves."
[PR #155](https://github.com/kennguy3n/visible-fishbone/pull/155) bakes the
specific **2-bit Q2_0 (ternary) GGUF** into the AI image with a checksum-verified
download (`deploy/ollama/`). The turnkey server is llama.cpp's `llama-server`
(`Dockerfile.llamacpp`, `docs/ai-model-setup.md`); `Modelfile.Q2_0-prism` is kept
as a reference recipe but is explicitly documented as *not* loadable by stock
Ollama, because the Q2_0 kernels aren't upstream yet — an honesty note that lives
in the file's own header, not just the blog. The point of the 2-bit quant is to
fit an 8B reasoning model on commodity tenant hardware so the self-hosted path is
actually affordable (the cost angle is Post 7 and
[business Post B5](business/12-cost-and-competition.md)).

Critically, when `AI_LLM_ENDPOINT` is unset (as on this VM), the assistant runs
**template-only / deterministic** mode:

- NL policy query → deterministic policy evaluation (shown above), no LLM needed.
- Troubleshoot / suggest-policy → return `503` rather than fabricate an answer.

So the screenshots and payloads here are the *fallback* path working correctly —
which is the path that must never break, because it's what runs when the model is
down.

## Live inference, measured

Earlier drafts of this post conceded we had *not* run live model generation. We
have now. [`blog/harness/llm_validation`](../harness/llm_validation) drives the
**real** `NLQueryEngine` against a model served over Ollama's
OpenAI-compatible endpoint, runs 20 curated AI-assistant queries spanning every
intent kind, and asserts the four properties the design promises:

1. **JSON validity** — the model's structured reply parses as JSON.
2. **`ai_generated` flag** — true *only* when the LLM was consulted *and*
   returned valid JSON; false on every fallback path.
3. **Verifier correctness** — policy-verdict questions resolve through the
   deterministic compiled-bundle evaluator, never a model guess.
4. **Agreement with the deterministic fallback** — the LLM-augmented engine's
   classification and verdict routing are *identical* with and without the
   model. The model only fills free-form entity references the deterministic
   tokenizer missed; it can never change the security-relevant routing.

The same harness is wired into CI (`llm-validation` job in
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)): it installs
Ollama, pulls a small test model, and fails the build if any property regresses.
For CI speed we serve `qwen2.5:0.5b` — a ~400 MB quantized model — as a faithful,
cheap stand-in for the self-hosted Ternary-Bonsai-8B; the contract being
validated (structured JSON intent + deterministic verification) is model-agnostic.

CI results (the contract gate), verbatim from
[`llm_validation/quality_report.json`](../artifacts/llm_validation/quality_report.json):

| Metric | Result |
|---|---|
| Queries | 20 |
| Parse success rate (valid JSON) | 100% |
| Verifier pass rate | 100% |
| Classification accuracy | 100% |
| Fallback agreement | 100% |
| `ai_generated` correctness | 100% |
| Raw-parse agreement vs deterministic ground truth | 100% |
| Latency p50 / p95 / p99 | 890 / 1093 / 1093 ms (CPU, 0.5B) |

The headline number is the one that matters for the thesis: **fallback agreement
is 100%.** Turning the model on did not change a single verdict the deterministic
engine already computes — exactly what "AI proposes, the policy engine disposes"
should mean in practice.

### Now measured at 8B scale (not just the CI stand-in)

Earlier drafts caveated that the published numbers were from the 0.5B CI
stand-in, *not* the real 8B. That gap is now closed. We brought up the actual
**Ternary-Bonsai-8B Q2_0** GGUF (`n_params = 8.19B`, the SHA-pinned
`Ternary-Bonsai-8B-Q2_0.gguf`) on `llama-server` built from the pinned prism
commit (`PrismML-Eng/llama.cpp@9b98ac8`, the `prism` branch — the build that
carries the Q2_0 ternary CPU kernels; see
[`deploy/ollama/README.md`](../../deploy/ollama/README.md)) and re-ran the *same*
harness against it. Results verbatim from
[`s6-llm-validation-bonsai-8b-q2_0.json`](../artifacts/payloads/s6-llm-validation-bonsai-8b-q2_0.json):

| Metric | Result (real 8B, Q2_0) |
|---|---|
| Queries | 20 |
| Parse success rate (valid JSON) | 100% (20/20) |
| Verifier pass rate | 100% |
| Classification accuracy | 100% |
| Verdict accuracy | 100% |
| Fallback agreement | 100% |
| `ai_generated` correctness | 100% |
| Raw-parse agreement vs deterministic ground truth | 100% |
| Latency p50 / p95 / p99 | **67.8 s / 77.0 s / 77.5 s** |

**Honesty contract — read the latency in context.** That run was **CPU-bound on
a dev VM**: an 8-vCPU AMD EPYC 7763 with **AVX2/FMA only (no AVX-512/VNNI)**,
CPU-only (`-ngl 0`). The prism Q2_0 ternary CPU kernels are correctness-first and
not yet SIMD-optimized for that path, so the box sustains **~1 token/s** — which
is why each ≈160-token intent parse takes a little over a minute. These figures
are an honest *floor for this hardware*, not a production target: an
AVX-512/VNNI host or a GPU build is materially faster, and the assistant is
low-QPS and deterministic-first by design (the LLM only augments free-form
entity extraction and never sits on the enforcement hot path). What does *not*
depend on the hardware — and is the load-bearing claim — is that every
deterministic invariant held at 8B scale exactly as it did at 0.5B:
**fallback agreement is 100%**, so turning the real 8B on changed zero verdicts
the deterministic engine already computes.

## Where we fall short

- **The 8B is validated, but only CPU-bound latency is measured so far.** We now
  run the contract (valid JSON, flagged generation, verified verdicts, fallback
  agreement) against the *real* 8B and all of it holds — see the table above.
  What we have *not* yet measured is production-grade latency: the only 8B run we
  can publish is the CPU-only dev-VM one at ~68 s p50, because that is the
  hardware we have. The numbers on an AVX-512/VNNI or GPU host will be far lower;
  we'd rather publish the honest CPU floor than estimate a number we didn't run.
- **The pinned Q2_0 build needs custom kernels.** The 2-bit Q2_0 bake (#155)
  buys affordability, but the ternary kernels aren't in upstream llama.cpp /
  Ollama yet, so it runs on a prism-branch `llama-server` — not a stock binary.
  The dependency is now *pinned and build-verified*: `Dockerfile.llamacpp`
  fixes `PrismML-Eng/llama.cpp@9b98ac8` (on the `prism` branch), and that exact
  commit compiles a `llama-server` that loads the 8B Q2_0 GGUF and serves valid
  JSON (the run above). We document the constraint in the Modelfile header and
  [`deploy/ollama/README.md`](../../deploy/ollama/README.md) rather than implying
  a one-line `ollama pull` works today.
- **Intent parsing is deterministic-first by design.** The NL→query parser is a
  deterministic tokenizer that classifies intent, time windows and policy
  versions; it now spans a wider grammar (blocked-traffic, change-summary,
  policy-version-compare and posture-failure questions in addition to policy
  verdicts), and the LLM augments free-form entity extraction. It is robust and
  auditable, but it still understands a bounded grammar, not arbitrary phrasing.
- **The verifier is the safety net, and it's conservative.** It will reject a
  proposed delta it can't prove safe, which means some legitimate changes need a
  human. We consider that the correct bias; it is still friction.

## Competitive note

The "AI SOC analyst" pitch is everywhere now. SNG's defensible position is the
**verifier** and the **grounding**: answers cite a compiled rule, carry
`ai_generated: false` when they're deterministic, and degrade to a working
deterministic path when the model is gone. That's a narrower claim than
"autonomous AI security" — and a much more honest one.

Next: the buyer's post — cost, compliance, and the consolidated competitive
critique.
