// Package policytemplates turns an SME's industry + country choice
// into a working baseline of security policy, expressed as
// Policy-Graph intent (internal/service/policy.Graph).
//
// Motivation
// ----------
// A small/medium enterprise onboarding onto ShieldNet Gateway should
// not have to hand-author a policy graph to get sensible protection.
// Instead they pick two coordinates they already know about
// themselves — their INDUSTRY (healthcare, finance, retail,
// professional-services, …) and their COUNTRY / compliance regime
// (EU/GDPR, UK, AU, CA, US, …) — and this package renders a complete,
// deny-by-default baseline that covers three planes:
//
//  1. Safe-browsing / category filtering — DNS + SWG rules that block
//     or monitor URL categories from the dotted-category vocabulary
//     shared by the DNS, firewall L7 and SWG planes
//     (crates/sng-swg/src/categorizer.rs). High-risk categories
//     (malware, phishing, hacking, anonymizers) are blocked for every
//     tenant; industry-sensitive categories (gambling, adult, …) are
//     blocked or monitored per the industry profile.
//
//  2. DLP sensitivity — DLP-domain rules that key on the PII detectors
//     that matter in the tenant's jurisdiction (e.g. ni_uk + uk_nhs for
//     the UK, ssn_us + credit_card for the US), using the detector vocabulary
//     already shipped in internal/service/dlp and validated against the
//     Rust classifier (crates/sng-dlp).
//
//  3. Baseline firewall posture — NGFW rules that allow the essential
//     egress services and deny the lateral-movement / management ports
//     that have no business traversing the gateway, tightened for
//     regulated industries.
//
// Everything renders into ONE policy.Graph so the result is a
// first-class, signable, compilable policy — it rides the same
// CompileTarget routing, validation and bundle pipeline as an
// operator-authored graph.
//
// Surface
// -------
//   - ListTemplates / GetTemplate — browse the catalog.
//   - Resolve(Selection) — pure render of the composed graph (preview,
//     no persistence). Deterministic: the same selection always yields
//     byte-identical graph bytes.
//   - Apply(tenant, Selection) — idempotently persist the tenant's
//     chosen baseline and the rendered graph (migration 062). Re-applying
//     the same selection is a no-op; changing the selection (or a catalog
//     bump) re-renders and updates in place.
//
// Deferred wiring
// ---------------
// Apply records the rendered Policy-Graph intent and the per-tenant
// applied-template state; it deliberately does NOT push the graph into
// the live PolicyRepository / rollout pipeline. Installing a rendered
// baseline as a tenant's active policy graph (and wiring the service +
// repository into cmd/sng-control) is a documented follow-up — see the
// PR body. This keeps the package self-contained and side-effect-free
// at the policy-enforcement boundary until an operator opts in.
package policytemplates
