// Lane B2 (Connectivity + policy authoring/rollout) message catalog and a
// scoped react-intl provider.
//
// Why a lane-local catalog: the frozen WS0 catalog in `@/lib/i18n/messages`
// only covers app chrome and is off-limits to feature lanes. This module owns
// every user-facing string for the seven Lane B2 screens, keyed by stable
// dotted ids, with English as the source-of-truth and react-intl fallback
// (`defaultLocale="en"`). The per-locale `OVERRIDES` map is the drop-in slot
// for translations; any key a translated catalog omits renders the English
// string rather than the raw key — the same incremental-adoption contract the
// WS0 catalog documents.
//
// Why a nested provider: `LaneB2Intl` reads the active locale from the parent
// app IntlProvider (via react-intl's `IntlContext`) and re-provides it merged
// with this catalog. When there is no parent provider — e.g. PolicyRollout's
// unit test renders the screen in isolation — it falls back to English and
// still supplies a working `intl`, so screens can use `useIntl()` /
// `<FormattedMessage>` unconditionally.

import {
  useCallback,
  useContext,
  useMemo,
  type ComponentProps,
  type ReactNode,
} from "react";
import {
  FormattedMessage,
  IntlContext,
  IntlProvider,
  useIntl,
} from "react-intl";
import { LOCALES, type Locale } from "@/lib/i18n/locales";
import "./lane-b2.css";

const DEFAULT_LOCALE: Locale = "en";

// English source-of-truth catalog. Plain strings here are safe for
// `formatMessage`; messages that carry ICU `<b>` tags are consumed only via
// `<FormattedMessage>` with a matching `b` render function.
const en = {
  // --- shared -----------------------------------------------------------
  "common.cancel": "Cancel",
  "common.back": "Back",
  "common.next": "Next",
  "common.discard": "Discard changes",
  "common.remove": "Remove",
  "common.undo": "Undo",
  "common.none": "None",

  // --- Sites ------------------------------------------------------------
  "sites.title": "Sites",
  "sites.subtitle":
    "Connect each office, data centre and cloud edge, then manage the security template that protects it.",
  "sites.new": "New site",
  "sites.help.title": "What is a site?",
  "sites.help.body":
    "A site is any location you connect to ShieldNet — a branch office, a regional hub, or a cloud edge. Each one starts from a security template you can fine-tune later.",
  "sites.col.name": "Name",
  "sites.col.slug": "Slug",
  "sites.col.template": "Template",
  "sites.col.created": "Created",
  "sites.col.actions": "Actions",
  "sites.delete": "Delete",
  "sites.delete.aria": "Delete site {name}",
  "sites.delete.title": "Delete this site?",
  "sites.delete.cta": "Delete site",
  "sites.delete.confirm":
    "Deleting “{name}” stops protecting the devices and tunnels that rely on it, and can’t be undone.",
  "sites.delete.error": "We couldn’t delete this site. Please try again.",
  "sites.empty.title": "Connect your first site",
  "sites.empty.body":
    "Sites are the offices, data centres and cloud edges ShieldNet protects. Add one to start enforcing policy on its traffic.",
  "sites.wizard.title": "New site · step {step} of 2",
  "sites.wizard.step1.legend": "Choose a deployment template",
  "sites.wizard.step1.help":
    "The template sets sensible defaults for this location. You can adjust individual rules afterwards.",
  "sites.wizard.create": "Create site",
  "sites.wizard.creating": "Provisioning…",
  "sites.wizard.name.label": "Site name",
  "sites.wizard.name.placeholder": "HQ — San Francisco",
  "sites.wizard.name.hint": "A recognizable name your team will see across the console.",
  "sites.wizard.slug.label": "Slug",
  "sites.wizard.slug.optional": "optional",
  "sites.wizard.slug.placeholder": "hq-sf",
  "sites.wizard.slug.hint": "A short, URL-safe id. Leave blank and we’ll generate one for you.",
  "sites.wizard.template.summary": "Template",
  "sites.wizard.error": "We couldn’t create this site. Check the details and try again.",
  "sites.template.branch": "Branch office",
  "sites.template.hub": "Regional hub",
  "sites.template.cloud_only": "Cloud edge",
  "sites.template.home_office": "Home office",
  "sites.template.branch.blurb":
    "Branch office with on-prem LAN, local breakout and a resilient tunnel pair.",
  "sites.template.hub.blurb":
    "Regional aggregation hub terminating site-to-site tunnels and east–west policy.",
  "sites.template.cloud_only.blurb":
    "Agentless cloud edge — secure web gateway and zero-trust access only, no on-site hardware.",
  "sites.template.home_office.blurb":
    "Single-user remote worker site provisioned straight from the device agent.",

  // --- Points of presence ----------------------------------------------
  "pops.title": "Points of presence",
  "pops.subtitle":
    "ShieldNet’s global edge network — the regional gateways that route and inspect your traffic.",
  "pops.help.title": "What is a point of presence?",
  "pops.help.body":
    "A point of presence (PoP) is one of ShieldNet’s regional edge locations. Traffic from your sites and users connects to the nearest healthy PoP for inspection and routing.",
  "pops.col.region": "Region",
  "pops.col.provider": "Provider",
  "pops.col.anycast": "Anycast IP",
  "pops.col.tier": "Capacity tier",
  "pops.col.status": "Status",
  "pops.col.health": "Health",
  "pops.col.load": "Load",
  "pops.empty.title": "No points of presence yet",
  "pops.empty.body":
    "Edge points of presence appear here once they’re provisioned for your network.",
  "pops.health.checking": "Checking…",
  "pops.health.unknown": "Unknown",
  "pops.load.value": "{cpu}% CPU · {conn} connections",
  "pops.load.none": "—",

  // --- Browser protection ----------------------------------------------
  "browser.title": "Browser protection",
  "browser.subtitle":
    "Control risky web activity with managed-browser isolation and download and clipboard rules.",
  "browser.new": "New policy",
  "browser.help.title": "How browser protection works",
  "browser.help.body":
    "Browser policies decide what people can do on the web — isolate risky sites in a safe container and control downloads and copy/paste. Rules apply in order; the first match wins.",
  "browser.col.name": "Name",
  "browser.col.scope": "Applies to",
  "browser.col.action": "Action",
  "browser.col.rules": "Rules",
  "browser.col.status": "Status",
  "browser.col.actions": "Actions",
  "browser.delete": "Delete",
  "browser.delete.aria": "Delete browser policy {name}",
  "browser.delete.title": "Delete this browser policy?",
  "browser.delete.cta": "Delete policy",
  "browser.delete.confirm":
    "Deleting “{name}” means the activity it controls falls back to your default policy.",
  "browser.delete.error": "We couldn’t delete this policy. Please try again.",
  "browser.empty.title": "Add your first browser policy",
  "browser.empty.body":
    "Browser policies isolate risky sites and control downloads and clipboard use. Create one to start protecting web activity.",
  "browser.modal.title": "New browser policy",
  "browser.modal.name.label": "Policy name",
  "browser.modal.name.placeholder": "Isolate uncategorized sites",
  "browser.modal.action.label": "Action",
  "browser.modal.scope.label": "Applies to",
  "browser.modal.create": "Create policy",
  "browser.modal.creating": "Creating…",
  "browser.modal.error": "We couldn’t create this policy. Check the details and try again.",

  // --- Troubleshoot -----------------------------------------------------
  "ts.title": "Troubleshooting",
  "ts.subtitle":
    "Run guided checks on your connection, then search the knowledge base for fixes.",
  "ts.run": "Run diagnostics",
  "ts.running": "Running checks…",
  "ts.checks.title": "Diagnostic checks",
  "ts.checks.help.title": "What gets checked?",
  "ts.checks.help.body":
    "Diagnostics evaluate tunnel health, policy compilation, connector reachability and the posture pipeline, then explain anything that needs attention.",
  "ts.checks.intro":
    "Run diagnostics to evaluate tunnel health, policy compilation, connector reachability and posture-pipeline status. We’ll explain anything that needs attention and how to fix it.",
  "ts.checks.allclear.title": "All clear",
  "ts.checks.allclear.body":
    "Every diagnostic passed — no connectivity or policy issues were found.",
  "ts.checks.error":
    "We couldn’t finish the diagnostics. Check your connection and run them again.",
  "ts.col.check": "Check",
  "ts.col.status": "Status",
  "ts.col.message": "What we found",
  "ts.col.when": "When",
  "ts.kb.title": "Knowledge base",
  "ts.kb.empty.title": "No articles yet",
  "ts.kb.empty.body":
    "Troubleshooting articles and remediation guides appear here as they’re published.",

  // --- shared policy editing -------------------------------------------
  "verb.allow": "Allow",
  "verb.deny": "Deny",
  "verb.inspect": "Inspect",
  "verb.decrypt": "Decrypt",
  "verb.log": "Log",
  "verb.steer": "Steer",
  "verb.isolate": "Isolate",
  "verb.block": "Block",
  "verb.bypass": "Bypass",
  "verb.suggest_only": "Suggest only",

  // --- Network policies -------------------------------------------------
  "net.title": "Network policies",
  "net.subtitle":
    "A guided, plain-language editor for your firewall, web, DNS, access and SD-WAN rules.",
  "net.compile": "Compile bundles",
  "net.compiling": "Compiling…",
  "net.compile.ok.title": "Bundles compiled",
  "net.compile.ok.body": "Enforcers will pick up the new policy shortly.",
  "net.compile.err.title": "Couldn’t compile bundles",
  "net.help.title": "Test before you apply",
  "net.help.body":
    "Rules run top to bottom and the first match wins. After any edit, run a dry-run — which replays recent traffic — before you can apply. A change that would add policy errors stays blocked.",
  "net.domain.ngfw": "Firewall",
  "net.domain.swg": "Web gateway",
  "net.domain.dns": "DNS security",
  "net.domain.ztna": "Zero-trust access",
  "net.domain.sdwan": "SD-WAN",
  "net.domain.ngfw.blurb":
    "Layer 3–7 firewall rules, application identification and intrusion-prevention profiles.",
  "net.domain.swg.blurb":
    "Secure web gateway: URL filtering, TLS inspection and content rules.",
  "net.domain.dns.blurb":
    "DNS-layer security: sinkholing, category blocking and encrypted-DNS control.",
  "net.domain.ztna.blurb":
    "Identity-aware, per-application access with device-posture checks.",
  "net.domain.sdwan.blurb":
    "Path selection, link-quality targets and traffic-steering policy.",
  "net.noGraph.empty.title": "No policy graph for this tenant",
  "net.noGraph.empty.body":
    "Set up this tenant’s policy in the Policy editor first, then return here to manage firewall, web, DNS, access and SD-WAN rules.",
  "net.card.title": "{domain} rules",
  "net.empty.title": "No {domain} rules yet",
  "net.empty.body": "This tenant has no {domain} rules. Add one below to get started.",
  "net.rule.position": "Rule {n}",
  "net.rule.source": "Source",
  "net.rule.source.placeholder": "Anyone — identity, group or address",
  "net.rule.action": "Action",
  "net.rule.dest": "Destination",
  "net.rule.dest.placeholder": "Anywhere — app, web category or domain",
  "net.rule.desc": "Description",
  "net.rule.desc.placeholder": "Why this rule exists (optional)",
  "net.rule.moveUp": "Move rule {n} up",
  "net.rule.moveDown": "Move rule {n} down",
  "net.rule.remove": "Remove rule {n}",
  "net.add": "Add {domain} rule",
  "net.default.label": "When no rule matches",
  "net.gate.untested":
    "Run a dry-run to preview the impact before this change can be applied.",
  "net.gate.ready": "Dry-run passed — this change is safe to apply.",
  "net.gate.blocked":
    "This change would introduce policy errors. Resolve them before applying.",
  "net.test": "Test this change",
  "net.testing": "Replaying traffic…",
  "net.apply": "Apply changes",
  "net.applying": "Saving…",
  "net.apply.ok.title": "Network policy updated",
  "net.apply.ok.body": "Your changes are live.",
  "net.apply.err.title": "Couldn’t save policy",
  "net.impact.title": "Impact of this change",
  "net.impact.replaying": "Replaying recent traffic…",
  "net.impact.stale": "This preview is for an earlier draft — re-test to refresh it.",
  "net.impact.safe":
    "Replaying the last {total, plural, one {# request} other {# requests}}, <b>nothing changes</b> — this edit looks safe to apply.",
  "net.impact.changed":
    "Replaying the last {total, plural, one {# request} other {# requests}}, <b>{changed, plural, one {# verdict changes} other {# verdicts change}}</b>.",
  "net.impact.affected":
    "{devices, plural, =0 {No devices affected} one {# device affected} other {# devices affected}}.",
  "net.impact.sites":
    "{sites, plural, one {# site affected} other {# sites affected}}.",
  "net.impact.transition": "{from} → {to}: <b>{count}</b>",
  "net.impact.errors": "Policy errors: {prev} → <b>{next}</b>",

  // --- Policy editor ----------------------------------------------------
  "policy.title": "Policy editor",
  "policy.subtitle": "See, edit and safely test your tenant’s security policy.",
  "policy.version": "version {version}",
  "policy.compile": "Compile bundles",
  "policy.compiling": "Compiling…",
  "policy.compile.ok.title": "Bundles compiled",
  "policy.compile.ok.body": "Enforcers will pick up the new policy shortly.",
  "policy.compile.err.title": "Couldn’t compile bundles",
  "policy.mode.label": "Editor mode",
  "policy.mode.simple": "Simple",
  "policy.mode.advanced": "Advanced",
  "policy.mode.help.title": "Simple vs Advanced",
  "policy.mode.help.body":
    "Simple shows your rules as a plain “who can do what, to where” list you can reorder and trim. Advanced exposes the raw policy graph, its JSON and the full change simulator.",
  "policy.tab.graph": "Graph",
  "policy.tab.json": "JSON",
  "policy.tab.simulate": "Change simulation",
  "policy.advanced.noGraph":
    "No policy graph exists for this tenant yet. Use the JSON tab to author one.",
  "policy.graph.title": "Policy graph",
  "policy.graph.empty":
    "This graph has no nodes to draw. Switch to the JSON tab to inspect the raw document.",
  "policy.json.title": "Raw policy document",
  "policy.json.save": "Save graph",
  "policy.json.saving": "Saving…",
  "policy.json.reset": "Reset",
  "policy.json.invalid": "This isn’t valid JSON yet — check for a missing comma or bracket.",
  "policy.json.saveFailed.title": "Save failed",
  "policy.sim.proposed": "Proposed graph",
  "policy.sim.run": "Run simulation",
  "policy.sim.running": "Replaying…",
  "policy.sim.invalid":
    "The proposed graph isn’t valid JSON yet — check for a missing comma or bracket.",
  "policy.sim.report": "Impact report",
  "policy.sim.intro":
    "Replays recent traffic through the proposed graph and reports how many verdicts would change. No simulation has run yet.",
  "policy.sim.evaluated": "Evaluated",
  "policy.sim.changed": "Changed",
  "policy.sim.affected": "Affected devices",
  "policy.sim.transitions": "Verdict transitions",
  "policy.sim.noTransitions": "No verdict changes in the replay window.",
  "policy.sim.col.from": "From",
  "policy.sim.col.to": "To",
  "policy.sim.col.count": "Requests",
  "policy.simple.title": "Rules — who can do what, to where",
  "policy.simple.help.title": "Editing rules",
  "policy.simple.help.body":
    "Rules run top to bottom and the first match wins. Drag the handle — or focus it and press the Up and Down arrow keys — to reorder. Mark a rule for removal to preview deleting it, then test the change before you save.",
  "policy.simple.empty.title": "No rules yet",
  "policy.simple.empty.body":
    "This tenant’s policy has no rules. Switch to Advanced to author the policy graph, then return to manage rules in plain English.",
  "policy.col.source": "Source",
  "policy.col.action": "Action",
  "policy.col.dest": "Destination",
  "policy.col.domain": "Area",
  "policy.row.remove": "Remove rule {n}",
  "policy.row.undo": "Keep rule {n}",
  "policy.row.reorder":
    "Reorder rule {n}. Press the Up or Down arrow key to move it.",
  "policy.legend.active": "Active",
  "policy.legend.reordered": "Reordered (draft)",
  "policy.legend.removed": "Will be removed",
  "policy.dragHint": "Drag, or focus and press arrow keys, to reorder",
  "policy.describe.anyone": "Anyone",
  "policy.describe.anything": "anything",
  "policy.describe.allDomain": "All {domain} traffic",
  "policy.test": "Test this change",
  "policy.testing": "Replaying traffic…",
  "policy.save": "Apply changes",
  "policy.saving": "Saving…",
  "policy.save.ok.title": "Policy updated",
  "policy.save.ok.body": "Your changes are live.",
  "policy.save.err.title": "Couldn’t save policy",
  "policy.gate.untested":
    "Run a dry-run to preview the impact before this change can be applied.",
  "policy.gate.ready": "Dry-run passed — this change is safe to apply.",
  "policy.gate.blocked":
    "This change would introduce policy errors. Resolve them before applying.",
  "policy.impact.title": "Impact of this change",
  "policy.impact.safe":
    "Replaying the last {total, plural, one {# request} other {# requests}}, <b>nothing changes</b> — this edit looks safe to apply.",
  "policy.impact.changed":
    "Replaying the last {total, plural, one {# request} other {# requests}}, <b>{changed, plural, one {# verdict changes} other {# verdicts change}}</b>.",
  "policy.impact.affected":
    "{devices, plural, =0 {No devices affected} one {# device affected} other {# devices affected}}.",
  "policy.impact.replaying": "Replaying recent traffic…",
  "policy.impact.removed":
    "{removed, plural, one {# rule removed} other {# rules removed}}",
  "policy.impact.reordered": "Rules reordered",
  "policy.impact.forRequests":
    "{count, plural, one {for # request} other {for # requests}}",

  // --- Cross-tenant roll-out -------------------------------------------
  "rollout.title": "Cross-tenant roll-out",
  "rollout.subtitle":
    "Apply one security baseline to many tenants at once — preview each tenant’s change before you commit.",
  "rollout.step1.title": "1 · Choose the baseline",
  "rollout.step1.help.title": "What is a baseline?",
  "rollout.step1.help.body":
    "A baseline is a ready-made security policy for an industry and country. ShieldNet maps it to each tenant’s rules so you don’t start from scratch.",
  "rollout.industry": "Industry",
  "rollout.industry.placeholder": "Select an industry…",
  "rollout.country": "Country / data residency",
  "rollout.country.placeholder": "Select a country…",
  "rollout.regime": "Compliance regime",
  "rollout.step2.title": "2 · Select target tenants",
  "rollout.selectAll": "Select all",
  "rollout.clearAll": "Clear all",
  "rollout.loadingTenants": "Loading tenants…",
  "rollout.noTenants": "No tenants are available to roll out to.",
  "rollout.selectedCount":
    "{count, plural, one {# tenant selected} other {# tenants selected}}",
  "rollout.step3.title": "3 · Preview & execute",
  "rollout.previewBtn": "Preview diff",
  "rollout.applyBtn": "Apply to {count, plural, one {# tenant} other {# tenants}}",
  "rollout.previewFirst.tip": "Preview the diff before applying.",
  "rollout.previewFirst": "Preview the per-tenant diff before applying.",
  "rollout.preview.heading": "Preview — {industry} · {country} ({regime})",
  "rollout.result.heading":
    "Result — {applied} applied · {unchanged} unchanged · {failed} failed",
  "rollout.result.heading.cancelled":
    "Result — {applied} applied · {unchanged} unchanged · {failed} failed · {cancelled} cancelled",
  "rollout.col.tenant": "Tenant",
  "rollout.col.change": "Change",
  "rollout.col.currentBaseline": "Current baseline",
  "rollout.col.result": "Result",
  "rollout.col.detail": "Detail",
  "rollout.current.none": "None",
  "rollout.detail.failed": "{error} · rolled back",
  "rollout.detail.failed.norollback": "{error}",
  "rollout.detail.failed.default": "Apply failed",
  "rollout.detail.cancelled": "{error} · not attempted",
  "rollout.detail.cancelled.default": "Cancelled · not attempted",
  "rollout.action.create": "Create",
  "rollout.action.update": "Update",
  "rollout.action.noop": "No change",
  "rollout.status.applied": "Applied",
  "rollout.status.unchanged": "Unchanged",
  "rollout.status.failed": "Failed",
  "rollout.status.cancelled": "Cancelled",
  "rollout.toast.preview.err": "Preview failed",
  "rollout.toast.cancelled.title": "Roll-out cancelled",
  "rollout.toast.cancelled.body": "{applied} applied · {cancelled} not attempted",
  "rollout.toast.failures.title": "Roll-out completed with failures",
  "rollout.toast.failures.body": "{applied} applied · {failed} failed (rolled back)",
  "rollout.toast.complete.title": "Roll-out complete",
  "rollout.toast.complete.body": "{applied} applied · {unchanged} unchanged",
  "rollout.toast.err": "Roll-out failed",
} as const;

export type LaneB2Key = keyof typeof en;

// Catalog keys whose values embed ICU rich-text (`<b>`) tags. They render
// correctly only through `<FormattedMessage values={{ ...richBold }}>`; routing
// one through the plain-string `useT()` formatter would print literal `<b>`
// markup. The `extends LaneB2Key` constraint keeps this list honest — a typo or
// a key that leaves the catalog is a compile error.
type EnsureKey<T extends LaneB2Key> = T;
export type RichLaneB2Key = EnsureKey<
  | "net.impact.safe"
  | "net.impact.changed"
  | "net.impact.transition"
  | "net.impact.errors"
  | "policy.impact.safe"
  | "policy.impact.changed"
>;

/** Catalog keys safe to format to a plain string through `useT()`. */
export type PlainLaneB2Key = Exclude<LaneB2Key, RichLaneB2Key>;

type Catalog = Record<LaneB2Key, string>;

// Translations land here as they're produced; any key a locale omits falls
// back to the English source above. Structured per-locale so the full set of
// 12 supported locales is a drop-in.
const OVERRIDES: Partial<Record<Locale, Partial<Catalog>>> = {};

export function laneB2MessagesFor(locale: Locale): Record<string, string> {
  return { ...en, ...(OVERRIDES[locale] ?? {}) };
}

function asLocale(loc: string | undefined): Locale {
  return (LOCALES as readonly string[]).includes(loc ?? "")
    ? (loc as Locale)
    : DEFAULT_LOCALE;
}

/**
 * Provides this lane's catalog, inheriting the active locale from the app's
 * IntlProvider when present and falling back to English in isolation (tests).
 *
 * The `.lane-b2` wrapper scopes this lane's accessibility overrides (see
 * `lane-b2.css`) without touching the frozen foundation. It only re-points a
 * handful of design tokens within the lane, so it adds no layout box of its
 * own beyond a plain block element.
 */
export function LaneB2Intl({ children }: { children: ReactNode }) {
  const parent = useContext(IntlContext) as
    | { locale?: string; messages?: Record<string, string> }
    | null;
  const locale = asLocale(parent?.locale);
  // Merge over the parent catalog (not replace it) so a shared primitive that
  // resolves a global message id keeps working inside the lane, and memoise so
  // the `messages` prop is referentially stable across renders — otherwise
  // IntlProvider rebuilds its formatter cache every render.
  const messages = useMemo(
    () => ({ ...(parent?.messages ?? {}), ...laneB2MessagesFor(locale) }),
    [parent?.messages, locale],
  );
  return (
    <IntlProvider locale={locale} defaultLocale={DEFAULT_LOCALE} messages={messages}>
      <div className="lane-b2">{children}</div>
    </IntlProvider>
  );
}

/**
 * Typed `formatMessage` for plain (tag-free) catalog strings. The key type is
 * narrowed to `PlainLaneB2Key`, so passing a rich (`<b>`-bearing) key is a
 * compile error — those must go through `<FormattedMessage values={richBold}>`.
 */
export function useT() {
  const intl = useIntl();
  return useCallback(
    (id: PlainLaneB2Key, values?: Record<string, string | number>): string =>
      intl.formatMessage({ id }, values),
    [intl],
  );
}

/** Bold render function for ICU `<b>` chunks in rich messages. */
export const richBold = { b: (chunks: ReactNode) => <b>{chunks}</b> };

/**
 * Renders a rich (`<b>`-bearing) catalog message. The `id` is constrained to
 * `RichLaneB2Key` — so a plain key, a typo, or a key that has left the catalog
 * is a compile error — and the `b` chunk renderer is injected automatically, so
 * every rich string is bolded consistently without each call site re-spreading
 * `richBold`. This is the rich-text counterpart to `useT()`, which only formats
 * the plain (tag-free) keys.
 */
export function RichMessage({
  id,
  values,
}: {
  id: RichLaneB2Key;
  // `b` is reserved for the injected bold renderer (`richBold`), so it's typed
  // `never` to make passing a `b` value a compile error rather than letting the
  // spread below silently drop it.
  values?: ComponentProps<typeof FormattedMessage>["values"] & { b?: never };
}) {
  return <FormattedMessage id={id} values={{ ...values, ...richBold }} />;
}
