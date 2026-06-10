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
  "matched_rules": ["policy-graph:d582fe06-0ad8-4cc8-8cb5-bce1c97a3dd2@v1"],
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

## The model itself (and the deterministic fallback)

The default model is the self-hosted **Ternary-Bonsai-8B**
([PR #102](https://github.com/kennguy3n/visible-fishbone/pull/102) /
[fishbone-access #35](https://github.com/kennguy3n/fishbone-access/pull/35)), with
compact-model prompt adaptation and a hardened JSON-extraction path. Critically,
when `AI_LLM_ENDPOINT` is unset (as on this VM), the assistant runs
**template-only / deterministic** mode:

- NL policy query → deterministic policy evaluation (shown above), no LLM needed.
- Troubleshoot / suggest-policy → return `503` rather than fabricate an answer.

So the screenshots and payloads here are the *fallback* path working correctly —
which is the path that must never break, because it's what runs when the model is
down.

## Where we fall short

- **No live 8B inference on this rig.** We exercised the deterministic and
  fallback paths, not live model generation — that needs the model served
  (Ollama). The generative-quality story is therefore methodology + design, not a
  measured generation benchmark here.
- **Intent parsing is heuristic.** The NL→query parser is a deterministic
  tokenizer, not an LLM — robust and auditable, but it understands a bounded
  grammar, not arbitrary phrasing.
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
