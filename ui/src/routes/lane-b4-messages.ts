// Lane B4 (identity / governance / audit) message catalog.
//
// This lane ships its own react-intl catalog rather than editing the frozen
// foundation catalog (`@/lib/i18n/messages`). `LaneB4Provider` mounts these
// messages in a nested <IntlProvider> scoped to the lane's screens — none of
// the shared primitives the lane renders read react-intl, so the nested
// provider is conflict-free.
//
// English (`en`) is the source of truth and the fallback: `laneMessagesFor`
// merges the requested locale over `en`, so a missing key always resolves to
// English text rather than a raw key. All copy uses typographic apostrophes
// (’) and quotes (“ ”) so ICU MessageFormat never mistakes a straight quote
// for an escape character.

import type { Locale } from "@/lib/i18n/locales";

import { zhHans } from "./lane-b4-locales/zh-Hans";
import { zhHant } from "./lane-b4-locales/zh-Hant";
import { ms } from "./lane-b4-locales/ms";
import { id } from "./lane-b4-locales/id";
import { th } from "./lane-b4-locales/th";
import { vi } from "./lane-b4-locales/vi";
import { ja } from "./lane-b4-locales/ja";
import { ko } from "./lane-b4-locales/ko";
import { ar } from "./lane-b4-locales/ar";
import { de } from "./lane-b4-locales/de";
import { fr } from "./lane-b4-locales/fr";

export const en = {
  // --- Shared actions / states -------------------------------------------
  "b4.action.cancel": "Cancel",
  "b4.action.done": "Done",
  "b4.action.retry": "Try again",
  "b4.action.copy": "Copy",
  "b4.action.copied": "Copied",
  "b4.denied.title": "You don’t have access to this",
  "b4.denied.desc":
    "Your role doesn’t include permission to view this page. Ask an administrator to grant access, then reload.",

  // --- Identity provider (Idp) -------------------------------------------
  "idp.title": "Identity provider & single sign-on",
  "idp.subtitle":
    "See how your team signs in to this tenant, and connect your company’s identity provider for one-click single sign-on (SSO).",
  "idp.help.title": "What is single sign-on?",
  "idp.help.body":
    "Single sign-on (SSO) lets your team reach ShieldNet with the company accounts they already have — no extra passwords to manage. ShieldNet uses OIDC, the open standard behind Okta, Microsoft Entra ID, Google Workspace and others.",
  "idp.mode.card": "How your team signs in",
  "idp.mode.oidc": "Single sign-on (SSO) — live",
  "idp.mode.jwt": "Developer token sign-in",
  "idp.field.issuer": "Identity provider URL",
  "idp.field.clientId": "Application (client) ID",
  "idp.field.scopes": "Requested scopes",
  "idp.jwt.help":
    "This tenant uses developer token sign-in, meant for testing. To switch on company single sign-on, set the authentication mode to OIDC and add your provider’s URL and client ID in runtime configuration. ShieldNet then uses the secure Authorization Code flow with PKCE.",
  "idp.discovery.card": "Connection check",
  "idp.discovery.loading": "Checking your identity provider…",
  "idp.discovery.errorTitle": "We couldn’t reach your identity provider",
  "idp.discovery.errorDesc":
    "ShieldNet tried to read your provider’s configuration but the request didn’t complete. Check the provider URL is correct and reachable, then reload.",
  "idp.discovery.authorization": "Sign-in endpoint",
  "idp.discovery.token": "Token endpoint",
  "idp.discovery.jwks": "Signing keys (JWKS)",
  "idp.discovery.userinfo": "User-info endpoint",
  "idp.empty.title": "No identity provider connected",
  "idp.empty.desc":
    "Connect your company’s identity provider — Okta, Microsoft Entra ID, Google Workspace and more — so your team can sign in with the accounts they already have.",
  "idp.empty.action": "Open guided setup",

  // --- SCIM provisioning -------------------------------------------------
  "scim.title": "Automatic user provisioning (SCIM)",
  "scim.subtitle":
    "Let your identity provider create, update and deactivate ShieldNet users automatically, so access always matches your company directory.",
  "scim.help.title": "What is SCIM?",
  "scim.help.body":
    "SCIM (System for Cross-domain Identity Management) is the open standard identity providers use to push user and group changes into apps like ShieldNet. With it, joining, role changes and offboarding all happen automatically.",
  "scim.connection.card": "Connection details",
  "scim.field.baseUrl": "SCIM base URL",
  "scim.field.auth": "Authentication",
  "scim.field.auth.value": "Bearer token (issued per identity provider)",
  "scim.field.apiBase": "API base URL",
  "scim.connection.help":
    "Paste the SCIM base URL and a provisioning bearer token into your identity provider (Okta, Microsoft Entra ID and others). ShieldNet validates every request and keeps this tenant’s users in step with your directory.",
  "scim.copyBaseUrl": "Copy SCIM base URL",
  "scim.resources.card": "What gets synced",
  "scim.col.resource": "Directory object",
  "scim.col.path": "Endpoint",
  "scim.col.operations": "Supported changes",
  "scim.resource.users": "Users",
  "scim.resource.groups": "Groups",
  "scim.ops.users": "Create, update, deactivate",
  "scim.ops.groups": "Create, update, remove",

  // --- RBAC roles --------------------------------------------------------
  "rbac.title": "Roles & permissions",
  "rbac.subtitle":
    "Bundle permissions into roles, then assign them to teammates and service accounts. Everyone gets exactly the access they need — nothing more.",
  "rbac.help.title": "How roles work",
  "rbac.help.body":
    "A role is a named set of permissions. Assign it to people or automation so access stays consistent and easy to review. Grant the least access that still lets the job get done.",
  "rbac.new": "New role",
  "rbac.col.role": "Role",
  "rbac.col.scope": "Applies to",
  "rbac.col.permissions": "Permissions",
  "rbac.empty.title": "No roles yet",
  "rbac.empty.desc":
    "Create your first role to grant scoped, least-privilege access to your team and automation.",
  "rbac.empty.action": "Create a role",
  "rbac.modal.title": "Create a role",
  "rbac.field.name": "Role name",
  "rbac.field.name.placeholder": "e.g. Security analyst",
  "rbac.field.name.help": "Use a name your team will recognise.",
  "rbac.field.scope": "Applies to",
  "rbac.field.scope.help": "Choose how widely this role’s permissions apply.",
  "rbac.field.permissions": "Permissions",
  "rbac.permsSelected": "{count} selected",
  "rbac.error.nameRequired": "Enter a role name.",
  "rbac.error.permsRequired": "Select at least one permission.",
  "rbac.error.create":
    "We couldn’t create the role. Check the details and try again.",
  "rbac.creating": "Creating…",
  "rbac.create": "Create role",
  "rbac.scope.platform": "Entire platform",
  "rbac.scope.msp": "Managed service provider",
  "rbac.scope.tenant": "This tenant",
  "rbac.scope.site": "A single site",
  "perm.tenant.read": "View tenant settings",
  "perm.tenant.write": "Manage tenant settings",
  "perm.policy.read": "View security policies",
  "perm.policy.write": "Edit security policies",
  "perm.device.read": "View devices",
  "perm.device.write": "Manage devices",
  "perm.alert.read": "View alerts",
  "perm.alert.write": "Act on alerts",
  "perm.compliance.read": "View compliance reports",
  "perm.billing.read": "View billing",

  // --- API keys ----------------------------------------------------------
  "apiKeys.title": "API keys",
  "apiKeys.subtitle":
    "Issue keys so your scripts and services can reach ShieldNet securely. Treat every key like a password — share it only with the system that needs it.",
  "apiKeys.help.title": "Keeping keys safe",
  "apiKeys.help.body":
    "A key is shown in full only once, when you create it. Store it in a secrets manager, give each system its own key, and revoke any key that might be exposed — then issue a replacement.",
  "apiKeys.new": "New API key",
  "apiKeys.col.name": "Name",
  "apiKeys.col.subject": "Used by",
  "apiKeys.col.status": "Status",
  "apiKeys.col.expires": "Expires",
  "apiKeys.col.lastUsed": "Last used",
  "apiKeys.never": "Never",
  "apiKeys.revoke": "Revoke",
  "apiKeys.revoking": "Revoking…",
  "apiKeys.empty.title": "No API keys yet",
  "apiKeys.empty.desc":
    "Create a key so a script, CI pipeline or service can authenticate to ShieldNet without a person signing in.",
  "apiKeys.empty.action": "Create an API key",
  "apiKeys.create.title": "Create an API key",
  "apiKeys.field.name": "Name",
  "apiKeys.field.name.placeholder": "e.g. CI deploy bot",
  "apiKeys.field.name.help": "A label so you can recognise this key later.",
  "apiKeys.field.subject": "Used by",
  "apiKeys.field.subject.placeholder": "e.g. bot:ci",
  "apiKeys.field.subject.help":
    "The service or identity that will present this key.",
  "apiKeys.error.nameRequired": "Enter a name for this key.",
  "apiKeys.error.subjectRequired":
    "Enter the service or identity that will use this key.",
  "apiKeys.error.create":
    "We couldn’t create the key. Check the details and try again.",
  "apiKeys.create.cta": "Create key",
  "apiKeys.creating": "Creating…",
  "apiKeys.reveal.title": "Copy your new key now",
  "apiKeys.reveal.warning":
    "This is the only time we’ll show this key in full. Store it somewhere safe — you won’t be able to see it again.",
  "apiKeys.reveal.label": "API key value",
  "apiKeys.reveal.copy": "Copy key",
  "apiKeys.revoke.title": "Revoke this API key?",
  "apiKeys.revoke.body":
    "Anything using “{name}” will immediately lose access. This can’t be undone — but you can issue a new key any time.",
  "apiKeys.revoke.cta": "Revoke key",
  "apiKeys.revoke.okTitle": "Key revoked",
  "apiKeys.revoke.okBody":
    "Anything using this key can no longer reach ShieldNet. You can issue a new key any time.",
  "apiKeys.revoke.failTitle": "We couldn’t revoke that key",
  "apiKeys.revoke.failBody":
    "The key is still active. Please check your connection and try again.",

  // --- App registry ------------------------------------------------------
  "appReg.title": "App registry",
  "appReg.subtitle":
    "See how ShieldNet handles each app your team uses — the global catalog, refined by your tenant’s own overrides.",
  "appReg.help.title": "How apps are handled",
  "appReg.help.body":
    "ShieldNet gives every app a handling class, from fully trusted (sent straight through) to blocked. You can override the global default for any app to match your policy.",
  "appReg.stat.apps": "Apps",
  "appReg.stat.overrides": "Your overrides",
  "appReg.stat.inspected": "Inspected",
  "appReg.stat.blocked": "Blocked",
  "appReg.col.application": "Application",
  "appReg.col.category": "Category",
  "appReg.col.class": "How it’s handled",
  "appReg.col.source": "Set by",
  "appReg.col.reason": "Override reason",
  "appReg.empty.title": "No apps classified yet",
  "appReg.empty.desc":
    "Once your team’s traffic flows through ShieldNet, the apps they use appear here with how each one is handled.",
  "appReg.class.trusted_direct": "Trusted — direct",
  "appReg.class.trusted_media_bypass": "Trusted — media bypass",
  "appReg.class.inspect_lite": "Lightly inspected",
  "appReg.class.inspect_full": "Fully inspected",
  "appReg.class.tunnel_private": "Private tunnel",
  "appReg.class.block": "Blocked",
  "appReg.source.global": "Global catalog",
  "appReg.source.override": "Your override",

  // --- Compliance --------------------------------------------------------
  "compliance.title": "Compliance",
  "compliance.subtitle":
    "Check how this tenant measures up against common security frameworks, and export signed evidence packs for your auditors.",
  "compliance.help.title": "About compliance reports",
  "compliance.help.body":
    "Each report scores your current configuration against a framework’s controls and bundles the proof into a signed evidence pack you can hand straight to an auditor.",
  "compliance.generate": "Generate report",
  "compliance.empty.title": "No compliance reports yet",
  "compliance.empty.desc":
    "Generate a report to score this tenant against a framework like SOC 2 or ISO 27001, with downloadable evidence.",
  "compliance.empty.action": "Generate your first report",
  "compliance.card.percent": "{pct}%",
  "compliance.card.score": "{score} of {max}",
  "compliance.card.generated": "Generated {when} · {controls} controls",
  "compliance.download.cta": "Download evidence pack",
  "compliance.download.preparing": "Preparing…",
  "compliance.download.ok": "Your evidence pack is downloading.",
  "compliance.download.failTitle": "Download didn’t finish",
  "compliance.download.failBody":
    "We couldn’t prepare the evidence pack. Please try again.",
  "compliance.modal.title": "Generate a compliance report",
  "compliance.field.framework": "Framework",
  "compliance.field.scopes": "Evidence to include",
  "compliance.error.scopes": "Select at least one area to include.",
  "compliance.error.generate":
    "We couldn’t generate the report. Check the details and try again.",
  "compliance.generate.ok": "Your compliance report is ready.",
  "compliance.generate.cta": "Generate report",
  "compliance.generating": "Generating…",
  "compliance.scope.dlp": "Data-loss prevention",
  "compliance.scope.browser": "Browser protection",
  "compliance.scope.casb": "Cloud-app security (CASB)",
  "compliance.scope.policy": "Security policy",
  "compliance.scope.access_control": "Access control",
  "compliance.framework.soc2": "SOC 2",
  "compliance.framework.iso27001": "ISO 27001",
  "compliance.framework.hipaa": "HIPAA",
  "compliance.framework.pci_dss": "PCI DSS",
  "compliance.framework.gdpr": "GDPR",

  // --- Audit log ---------------------------------------------------------
  "audit.title": "Audit log",
  "audit.subtitle":
    "A tamper-evident record of every administrative change in this tenant — who did what, and when.",
  "audit.help.title": "Why you can trust this log",
  "audit.help.body":
    "Entries are append-only and tamper-evident: each one is chained to the entry before it, so any change would show. The log can’t be edited or deleted from the console.",
  "audit.filter.action.label": "Action",
  "audit.filter.action.placeholder": "e.g. tenant.update",
  "audit.filter.resource.label": "Resource type",
  "audit.filter.resource.placeholder": "e.g. role",
  "audit.filter.clear": "Clear filters",
  "audit.col.when": "When",
  "audit.col.actor": "Who",
  "audit.col.action": "Action",
  "audit.col.resource": "Resource",
  "audit.col.resourceId": "Resource ID",
  "audit.actor.system": "System",
  "audit.empty.title": "No administrative activity yet",
  "audit.empty.desc":
    "Every administrative change in this tenant will be recorded here as it happens.",
  "audit.empty.filtered.title": "No matching audit entries",
  "audit.empty.filtered.desc":
    "No activity matches these filters. Clear them to see every administrative change.",

  // --- Alerts ------------------------------------------------------------
  "alerts.title": "Alerts",
  "alerts.subtitle":
    "Unusual activity ShieldNet spotted in your traffic, grouped into incidents with a recommended next step.",
  "alerts.help.title": "How alerts work",
  "alerts.help.body":
    "ShieldNet learns what’s normal for your traffic, then flags anything that stands out — a higher deviation score means it’s further from normal. Related findings are grouped into a single incident automatically.",
  "alerts.chart.title": "How far each finding is from normal, over time",
  "alerts.chart.summary":
    "{count} findings plotted by deviation score over time; {beyond} sit beyond the ±3 alert threshold.",
  "alerts.chart.yLabel": "Deviation score",
  "alerts.chart.empty.title": "No unusual activity detected",
  "alerts.chart.empty.desc":
    "When ShieldNet spots something out of the ordinary, it appears here.",
  "alerts.filter.severity": "Filter by severity",
  "alerts.filter.state": "Filter by status",
  "alerts.filter.all": "All",
  "alerts.baselines": "{count} baseline models trained",
  "alerts.incident.unavailable":
    "We couldn’t group these into incidents right now — they’re listed individually below.",
  "alerts.incident.title": "Incident · {count} related alerts",
  "alerts.other.title": "Other alerts",
  "alerts.list.title": "Alerts",
  "alerts.other.allGrouped": "Every matching alert is part of an incident above.",
  "alerts.empty.title": "No matching alerts",
  "alerts.empty.desc":
    "Nothing matches the current filters. Try widening the severity or status.",
  "alerts.card.fallbackSummary": "Unusual activity on {dimension}.",
  "alerts.card.affected": "Affected",
  "alerts.card.metric":
    "Now {observed} · normal {baseline} ± {stddev} · deviation {z}",
  "alerts.card.recommended": "Recommended",
  "alerts.rec.critical":
    "Investigate now and consider auto-remediation — this is far outside your normal range.",
  "alerts.rec.warning":
    "Review the affected resource, then acknowledge once you’ve looked into it.",
  "alerts.rec.info":
    "For your awareness. Usually no action is needed — resolve it to clear the queue.",
  "alerts.action.acknowledge": "Acknowledge",
  "alerts.action.resolve": "Resolve",
  "alerts.action.investigate": "Investigate",
  "alerts.action.investigate.hint": "Open troubleshooting tools",
  "alerts.action.remediate": "Auto-remediate",
  "alerts.action.remediate.hint": "Trigger an automated response playbook",
  "alerts.toast.ackTitle": "Acknowledged",
  "alerts.toast.ackBody": "We’ve marked this alert as acknowledged.",
  "alerts.toast.resolveTitle": "Resolved",
  "alerts.toast.resolveBody": "We’ve marked this alert as resolved.",
  "alerts.toast.failTitle": "That didn’t go through",
  "alerts.toast.failBody": "We couldn’t update the alert. Please try again.",
  "alerts.severity.info": "Info",
  "alerts.severity.warning": "Warning",
  "alerts.severity.critical": "Critical",
  "alerts.state.open": "Open",
  "alerts.state.acknowledged": "Acknowledged",
  "alerts.state.resolved": "Resolved",
  "alerts.state.suppressed": "Suppressed",
} as const;

export type LaneKey = keyof typeof en;

/** A partial catalog for a translated locale; any missing key falls back to en. */
export type LaneCatalog = Partial<Record<LaneKey, string>>;

const CATALOGS: Record<Locale, LaneCatalog> = {
  en,
  "zh-Hans": zhHans,
  "zh-Hant": zhHant,
  ms,
  id,
  th,
  vi,
  ja,
  ko,
  ar,
  de,
  fr,
};

/** Messages for a locale, with English filled in for any untranslated key. */
export function laneMessagesFor(locale: Locale): Record<LaneKey, string> {
  return { ...en, ...CATALOGS[locale] };
}
