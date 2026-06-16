# Ship AI you can trust: verify before you suggest

> **Build series, Post 9 of 10 — AI safety.** Reader: both, because "we added
> AI" is easy and "we added AI you can trust" is the actual product. The
> decision: *how do you let AI act on a security platform without it becoming the
> least trustworthy thing in the building?*

Bolting an LLM onto a security console is a weekend's work and a long-term
liability. The hard decision — the one that separates a demo from a product — is
*what stops the AI from being wrong in a way that matters?* SNG's answer is a
single principle: **the AI never gets the last word; a deterministic verifier
does.**

## The build: propose → verify → (maybe) apply

The policy-recommendation engine (`internal/service/policyrec`) reads observed
traffic and proposes graph deltas — "these identities keep reaching this app;
here is the `allow` edge that would codify it." The decisive design move is that
**every proposal is run through the same compiler/verifier as a hand-drawn edge
(Post 3) before it can be applied.** A suggestion that would introduce a
contradiction is rejected by the verifier exactly as a human's contradictory edge
would be. The AI cannot ship something the type system forbids, because the type
system checks it either way.

It is also honest about its inputs. On a deployment without the telemetry hot
tier configured, the engine returns **`503 unavailable`**
([`policyrec-acme-generate-response.json`](../artifacts/payloads/policyrec-acme-generate-response.json))
rather than hallucinating suggestions from no data, and
`GET .../policy/recommendations` returns an empty list. No data, no guess.

Two more trust mechanisms:

- **Coach-first AI-app DLP** (`sng-dlp`): when a user is about to leak PII into an
  AI app, the default action is to *coach*, with a human review queue, not to
  silently block — and the OCR/ML hooks can only ever *escalate* a verdict, never
  weaken one. The human stays in the loop where judgement matters.
- **A shared inference pool** (`internal/service/ai`): one pooled model serves the
  whole fleet (~3,696× less memory than per-tenant, Post 8), with fair queueing up
  to a concurrency cap and a **degrade-to-template fallback** when the pool is
  saturated — so AI load can never take the platform down; it falls back to the
  deterministic path.

## The business call: trust is the feature, not the model

The scenario: **Lena** is offered an AI that suggests policy changes. Her
question is not "is it smart?" but "what happens when it is wrong?" If the answer
is "it applies the change and you find out later," she will never enable it. SNG's
answer — "it proposes, the same verifier that guards your hand-edits checks it,
and it tells you `503` rather than guess when it has no data" — is what makes Lena
turn it on. For the buyer, the trust mechanism *is* the product; the model is just
the part that drafts the suggestion.

The shared pool has a P&L dimension too (it is what makes fleet-wide AI
affordable, Post 8), but the reason it is safe to share is the
degrade-to-template fallback: the platform's correctness never depends on the
model being available.

## How the incumbents approached it

- The incumbents are all shipping AI assistants — **Palo Alto** (Precision
  AI / Copilot), **Zscaler** (AI analytics and risk scoring), **Netskope** and
  **Cato** (AI-driven discovery and policy assistance). They are genuinely
  capable and trained on far larger telemetry than SNG has.
- The common pattern is *assistive*: the AI surfaces insight or drafts a change,
  and a human applies it. That is sound.

SNG's distinctive call is making the safety **mechanical rather than procedural**:
not "a human reviews the AI's suggestion" (which depends on the human being
careful) but "the deterministic verifier rejects an unsafe suggestion before a
human ever sees it" — plus the honest `503` instead of a low-confidence guess.
The incumbents have more data; SNG's bet is that *verifiability* matters more than
model size for a buyer who cannot afford to be wrong.

## Build it yourself

1. **Make a deterministic verifier the gate, not the human.** Route AI output
   through the same validation as human input, so the AI can never ship what the
   type system forbids.
2. **Refuse to guess.** When the inputs are missing, return an honest
   unavailable, not a low-confidence fabrication.
3. **Coach, queue, and escalate — don't silently act.** Keep a human in the loop
   for judgement calls, and make automated hooks monotonic (escalate-only).
4. **Share the model, but degrade to a deterministic fallback** so AI
   availability is never on the platform's critical path.

## Where this approach falls short

- **The engine needs a telemetry hot tier to do anything.** Without it, the
  recommendation engine is honestly inert (`503`) — useful as integrity, useless
  as a feature, until that tier is provisioned. That is a real deployment
  prerequisite.
- **Less data than the incumbents.** Traffic-derived suggestions are only as good
  as the traffic observed; a single SME's telemetry is thin next to a global
  cloud's. Verifiability mitigates the risk but does not manufacture insight.
- **Verifier-checked is not the same as correct.** The verifier guarantees a
  suggestion is *consistent*, not that it reflects the operator's actual intent.
  A consistent-but-unwanted edge is still possible; the human review step exists
  for exactly that residue.
