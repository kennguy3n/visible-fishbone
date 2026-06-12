# Retire the VPN: zero-trust access to private apps (S4)

> **Post 4 of 8.** Persona: **Devraj**, SME IT. Outcome: least-privilege access
> to private apps, with device posture in the decision — not a flat VPN that
> trusts anything that completed a handshake.

## The VPN problem

A VPN authenticates *once*, at the tunnel edge, and then the user is "inside."
Zero-trust inverts that: every access decision re-evaluates identity, device,
app, and posture. SNG's `sng-ztna` crate is the broker that makes that decision.

## Walking it in the console

Device posture is a first-class column. Here are Acme's enrolled endpoints across
macOS, Windows, and Linux, each with a platform, enrollment status, posture
verdict, and last-seen:

![Devices — posture](../artifacts/screenshots/s4-devices-posture.png)

The ZTNA rules themselves live in the same policy graph from Post 1 — access to
`private-apps` is a typed node with device/identity/posture conditions, not a
separate appliance config.

## The real decision behind it

From the efficacy matrix (Post 3), the `ztna` row is the proof: **20 cases**, all
correct, driving the **real** `ZtnaService::evaluate` (the corpus grew this cycle
to cover the new user-subject, session-revocation, and expanded-posture gates).
Its notes spell out exactly what gets denied:

> Denies unknown app/device/identity, stale posture, insufficient posture, stale
> MFA, missing entitlement, and **cross-tenant requests**; admits authorized
> engineers on compliant devices.

We can also show a live access verdict. The AI assistant (Post 6) re-derives the
policy decision deterministically against the compiled bundle. Asking *"Can user
finance access app private-apps from a managed device?"* returns, verbatim from
[`s6-acme-nl-policy-query-response.json`](../artifacts/payloads/s6-acme-nl-policy-query-response.json):

```json
{
  "verdict": "inspect",
  "evaluation_mode": "compiled-bundle",
  "matched_rules": ["policy-graph:b70aebd7-...@v2"],
  "ai_generated": false,
  "explanation": "Verdict \"inspect\" ... user-subject rules were not evaluated
    — user identity is not represented in the synthesized access envelope, so
    this verdict reflects only app/device and default-action matching."
}
```

That `explanation` is the honesty contract in the product itself: the engine
*tells you* it only matched on app/device/default-action because *this particular*
synthesized envelope had no real user identity. It doesn't pretend to a
user-identity verdict it can't actually make.

**What changed this cycle:** full **user-subject evaluation** is now shipped
([#201](https://github.com/kennguy3n/visible-fishbone/pull/201)). When the access
envelope carries a real IdP-populated identity, `evaluate_policy` threads it
first-class through the edge and re-eval path and matches group-entitlement and
user-tag rules — and when the envelope is *supposed* to carry one but doesn't, it
returns an explicit `IdentityAbsent` **deny** rather than silently degrading to a
device-only verdict. It ships behind `ztna.user_subject_eval_enabled`
(default-OFF), which is why the default-path payload above still shows the
device-only explanation: that is the gate being *off*, captured honestly, not a
missing capability.

## How it works under the hood

- **Multi-factor decision.** `evaluate` takes the access envelope (identity,
  device, app, posture, MFA freshness) and walks the compiled ZTNA rules. Any
  failing dimension denies; the verdict is `allow` / `inspect` / `deny`.
- **Posture is an input, not an afterthought.** A device that's enrolled but
  fails a posture check (disk-encryption off, stale signal) doesn't get the same
  verdict as a healthy one — the Devices screenshot above is the data feeding
  that decision.
- **Tenant isolation in the broker.** Cross-tenant access requests are denied at
  the broker, consistent with the Postgres-RLS story from Post 2 — isolation is
  enforced at every layer, not just the database.

## Where we fall short

The three caveats this post used to carry have all moved — they're now shipped,
default-OFF features rather than roadmap items. The honest framing is **wired vs.
default-ON**, and the residual gap is breadth of integrations, not capability:

- **User-subject evaluation ships, but it's default-OFF and IdP-fed.** Full
  identity evaluation now exists ([#201](https://github.com/kennguy3n/visible-fishbone/pull/201))
  and is exercised in the efficacy corpus, but it only produces a user-identity
  verdict when a real identity is in the envelope — which means it depends on the
  IdP directory-sync integration (#177, also default-OFF). The capability is
  real; the *breadth* of IdP connectors is still scaffolding, not a finished IGA
  suite (Post 2).
- **Posture breadth expanded — now EDR/patch/cert, with hard gates.** Beyond the
  weighted core score (disk-encryption 25, OS-patch 25, anti-malware 20, firewall
  15, screen-lock 15), an app can now declare independent **hard gates**:
  `require_edr` (sensor must report healthy), `min_patch_days`, and
  `max_av_definition_age_hours`. A device with a perfect score is still denied if
  its EDR was killed, its patches lapsed, or its AV signatures went stale. It's a
  credible posture engine now — still not a full UEM that gathers *every* signal
  a dedicated agent vendor does.
- **Continuous in-session re-evaluation ships (default-OFF).** The `ReevalLoop`
  ([#183](https://github.com/kennguy3n/visible-fishbone/pull/183)) re-scores live
  sessions when the control plane pushes a posture or revocation change and cuts
  off a session the moment a pushed signal trips a gate — the adaptive-trust
  behaviour this post previously called a roadmap item. Gated behind
  `ztna.reeval_enabled` so an upgrade is behaviourally inert until an operator
  opts in.

## Competitive note

VPN-retirement / ZTNA is the most crowded part of SASE — Zscaler Private Access,
Palo Alto Prisma Access, Cloudflare Access, Netskope Private Access all play
here. SNG's honest differentiator is *not* breadth of identity integrations
(where the incumbents are far ahead); it's that the access decision is a
projection of the *same* typed policy graph that drives NGFW/SWG/DNS, so there's
no second policy model to keep in sync. The cost of that elegance is the identity
depth gap above.

Next: keeping regulated data from leaving — DLP, CASB, and browser isolation.
