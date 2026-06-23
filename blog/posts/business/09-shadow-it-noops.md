# Shadow-IT discovery without the noise

> **Business series, Post 2 of 5.** Buyer: **Sam**, the one-person IT lead at a
> 120-person company. Job-to-be-done: *"show me the SaaS apps my staff use that I
> don't know about — and tell me what to do, not just dump a list."* Capability:
> CASB NoOps. Evidence:
> [`casb-classifications-acme.json`](../../artifacts/payloads/casb-classifications-acme.json),
> [`casb-noops-actions-acme.json`](../../artifacts/payloads/casb-noops-actions-acme.json);
> screenshot [`new-casb-noops-shadow-it.png`](../../artifacts/screenshots/new-casb-noops-shadow-it.png).

Every shadow-IT tool Sam has tried produces the same thing: a 400-row spreadsheet
of "discovered apps," sorted by traffic volume, that he doesn't have time to act
on. Discovery without a recommendation is just more noise. SNG's CASB is built to
end with a *decision*, not a list.

## What Sam sees

![CASB shadow-IT with NoOps recommendations](../../artifacts/screenshots/new-casb-noops-shadow-it.png)

Each discovered app comes with a **risk score**, a **sanction status**, and —
critically — a **recommended action with a confidence level**. Read across:
Microsoft 365 (risk 10, sanctioned → *Monitor*, 100%); WeTransfer (risk 70,
unsanctioned → *Block*, 85%); ChatGPT (risk 60 → *Inspect via SWG*, 35%);
Pastebin (risk 75 → *Block*, 30%). Sam doesn't have to be a security analyst to
know what to do next — the platform already triaged it. When ChatGPT or similar
generative-AI apps are sanctioned, the SWG's **AI governance** stage can apply
per-app rules (allow, monitor, block, or redirect to RBI) on the same ext-authz
path.

## The recommendations are the product engine's, not a demo script

This is the honesty point. Those verdicts are produced by the production
`AppNoOpsEngine` running its real `Reconcile()` over the seeded inventory — the
captured output is in
[`casb-classifications-acme.json`](../../artifacts/payloads/casb-classifications-acme.json)
and [`casb-noops-actions-acme.json`](../../artifacts/payloads/casb-noops-actions-acme.json).
Nothing on that screen is hand-authored to look good.

## NoOps means recommend-first, then act when it's safe

The default posture is **recommend, don't enforce** — the engine surfaces what it
*would* do and waits. High-confidence, high-risk apps (an unsanctioned file-share
at 85%) are the easy approvals; the low-confidence rows stay advisory until Sam
or the platform's auto-enforce gate is sure. That gate (the engineering series'
Post 8) only promotes a recommendation to enforcement after a monitoring period
proves it wouldn't cause false blocks. Sam gets the upside of automation without
the risk of a tool that silently blocks a business-critical app on day one.

## And it scales the cheap way

Shadow-IT reconcile is one of the tiered background jobs (Post 1): on a busy
tenant it refreshes every cycle, on a dormant trial it refreshes rarely. So Sam's
active fleet stays current without the platform burning cost scanning trials
nobody uses.

## Where it falls short

- **Recommendations need confidence to act.** The low-confidence rows (30–35%)
  are deliberately *not* auto-actioned. That's the safe default, but it means the
  long tail of ambiguous apps still needs a human glance.
- **Discovery is as good as the traffic it sees.** Inline discovery sees what
  flows through the gateway; the SaaS-API connectors add API-side
  visibility for the apps that support it, but a fully off-network app is still
  invisible.
- **Catalog breadth is still catching up** to a dedicated CASB like Netskope. The
  decision-quality (risk + recommendation + confidence) is the differentiator,
  not raw app-count.
