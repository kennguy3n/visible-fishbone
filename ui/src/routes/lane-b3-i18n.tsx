// Lane B3 (data-protection + device posture) message catalog.
//
// These four screens — DLP, DLP review queue, CASB and Devices — own their
// user-facing strings here rather than in the frozen global catalog
// (`src/lib/i18n/messages.ts`). `LaneB3Intl` nests a react-intl provider that
// reuses the app's active locale (from `useLocale()`) and feeds it this
// catalog, merged over English so any not-yet-translated key falls back to the
// English source instead of showing a raw id. English is the source of truth;
// `lane-b3-i18n.test.ts` asserts every locale defines every key.

import { IntlProvider, useIntl } from "react-intl";
import type { ReactNode } from "react";
import { useLocale } from "@/lib/i18n/locale-context";
import type { Locale } from "@/lib/i18n/locales";

export type B3Key =
  // shared within the lane
  | "b3.retry"
  | "b3.confidence"
  | "b3.actions"
  // ----- DLP -----
  | "dlp.title"
  | "dlp.subtitle"
  | "dlp.templates.title"
  | "dlp.templates.help.title"
  | "dlp.templates.help.body"
  | "dlp.templates.taxonomy"
  | "dlp.templates.apply"
  | "dlp.templates.applying"
  | "dlp.templates.empty.title"
  | "dlp.templates.empty.desc"
  | "dlp.templates.applied.title"
  | "dlp.templates.applied.body"
  | "dlp.templates.failed.title"
  | "dlp.templates.failed.body"
  | "dlp.sandbox.title"
  | "dlp.sandbox.help.title"
  | "dlp.sandbox.help.body"
  | "dlp.sandbox.desc"
  | "dlp.sandbox.placeholder"
  | "dlp.sandbox.label"
  | "dlp.sandbox.run"
  | "dlp.sandbox.running"
  | "dlp.sandbox.result.clean"
  | "dlp.sandbox.result.flagged"
  | "dlp.sandbox.matches"
  | "dlp.sandbox.col.detector"
  | "dlp.sandbox.col.match"
  | "dlp.sandbox.col.confidence"
  | "dlp.action.block"
  | "dlp.action.audit"
  | "dlp.action.redact"
  | "dlp.action.warn"
  | "dlp.policies.title"
  | "dlp.policies.empty.title"
  | "dlp.policies.empty.desc"
  | "dlp.policies.col.name"
  | "dlp.policies.col.detectors"
  | "dlp.policies.col.action"
  | "dlp.policies.col.enabled"
  | "dlp.policies.col.created"
  | "dlp.policies.detectors"
  | "dlp.policies.enabled"
  | "dlp.policies.disabled"
  // ----- DLP review queue -----
  | "drq.title"
  | "drq.subtitle"
  | "drq.help.title"
  | "drq.help.body"
  | "drq.digest.title"
  | "drq.digest.subtitle"
  | "drq.digest.window.label"
  | "drq.digest.total"
  | "drq.digest.pending"
  | "drq.digest.apps"
  | "drq.digest.since"
  | "drq.digest.bySeverity"
  | "drq.digest.byState"
  | "drq.digest.byApp"
  | "drq.queue.title"
  | "drq.queue.hint"
  | "drq.queue.capped"
  | "drq.filter.label"
  | "drq.filter.all"
  | "drq.empty.pending.title"
  | "drq.empty.pending.desc"
  | "drq.empty.other.title"
  | "drq.empty.other.desc"
  | "drq.col.destination"
  | "drq.col.signal"
  | "drq.col.severity"
  | "drq.col.confidence"
  | "drq.col.findings"
  | "drq.col.state"
  | "drq.col.created"
  | "drq.col.decision"
  | "drq.suspectedAi"
  | "drq.sev.low"
  | "drq.sev.medium"
  | "drq.sev.high"
  | "drq.sev.critical"
  | "drq.state.pending"
  | "drq.state.approved"
  | "drq.state.blocked"
  | "drq.state.dismissed"
  | "drq.action.approve"
  | "drq.action.block"
  | "drq.action.dismiss"
  | "drq.action.details"
  | "drq.toast.approved"
  | "drq.toast.blocked"
  | "drq.toast.dismissed"
  | "drq.toast.recorded"
  | "drq.toast.failed.title"
  | "drq.toast.failed.body"
  | "drq.detail.title"
  | "drq.detail.close"
  | "drq.detail.shortcuts"
  | "drq.field.state"
  | "drq.field.destination"
  | "drq.field.signal"
  | "drq.field.severity"
  | "drq.field.confidence"
  | "drq.field.created"
  | "drq.field.decided"
  | "drq.field.decidedBy"
  | "drq.findings.title"
  | "drq.findings.empty"
  | "drq.findings.kind"
  | "drq.findings.detector"
  | "drq.findings.count"
  | "drq.findings.maxConfidence"
  | "drq.findings.severity"
  | "drq.signal.aiAppExfiltration"
  | "drq.signal.bulkDownload"
  | "drq.finding.pii"
  | "drq.finding.secret"
  | "drq.finding.confidential"
  // ----- CASB -----
  | "casb.title"
  | "casb.subtitle"
  | "casb.addConnector"
  | "casb.apps.title"
  | "casb.apps.help.title"
  | "casb.apps.help.body"
  | "casb.apps.empty.title"
  | "casb.apps.empty.desc"
  | "casb.risk.help.title"
  | "casb.risk.help.body"
  | "casb.col.app"
  | "casb.col.vendor"
  | "casb.col.category"
  | "casb.col.risk"
  | "casb.col.sanction"
  | "casb.col.recommendation"
  | "casb.col.users"
  | "casb.col.devices"
  | "casb.col.lastSeen"
  | "casb.sanction.unsanctioned"
  | "casb.sanction.tolerated"
  | "casb.sanction.sanctioned"
  | "casb.verdict.none"
  | "casb.enforcement.none"
  | "casb.enforcement.throttle"
  | "casb.enforcement.protect"
  | "casb.enforcement.route"
  | "casb.enforcement.enforce"
  | "casb.verdict.applied"
  | "casb.verdict.recommended"
  | "casb.verdict.detail"
  | "casb.connectors.title"
  | "casb.connectors.help.title"
  | "casb.connectors.help.body"
  | "casb.connectors.empty.title"
  | "casb.connectors.empty.desc"
  | "casb.col.connName"
  | "casb.col.connType"
  | "casb.col.connStatus"
  | "casb.col.lastSync"
  | "casb.sync"
  | "casb.syncing"
  | "casb.sync.done.title"
  | "casb.sync.done.body"
  | "casb.sync.failed.title"
  | "casb.sync.failed.body"
  | "casb.create.title"
  | "casb.create.name"
  | "casb.create.name.help"
  | "casb.create.namePlaceholder"
  | "casb.create.type"
  | "casb.create.cancel"
  | "casb.create.submit"
  | "casb.create.submitting"
  | "casb.create.error"
  | "casb.create.success.title"
  | "casb.create.success.body"
  // ----- Devices -----
  | "dev.title"
  | "dev.subtitle"
  | "dev.export"
  | "dev.exporting"
  | "dev.revoke"
  | "dev.claim"
  | "dev.col.selectAll"
  | "dev.col.selectRow"
  | "dev.col.name"
  | "dev.col.platform"
  | "dev.col.status"
  | "dev.col.posture"
  | "dev.col.access"
  | "dev.col.lastSeen"
  | "dev.platform.windows"
  | "dev.platform.macos"
  | "dev.platform.linux"
  | "dev.platform.ios"
  | "dev.platform.android"
  | "dev.posture.healthy"
  | "dev.posture.atrisk"
  | "dev.posture.compromised"
  | "dev.posture.unknown"
  | "dev.posture.help.title"
  | "dev.posture.help.body"
  | "dev.access.allowed"
  | "dev.access.limited"
  | "dev.access.blocked"
  | "dev.access.unknown"
  | "dev.empty.title"
  | "dev.empty.desc"
  | "dev.revoke.confirm.title"
  | "dev.revoke.confirm.body"
  | "dev.revoke.confirm.cancel"
  | "dev.revoke.confirm.submit"
  | "dev.revoke.revoking"
  | "dev.revoke.success.title"
  | "dev.revoke.success.body"
  | "dev.revoke.failed.title"
  | "dev.revoke.failed.body"
  | "dev.claim.title"
  | "dev.claim.intro"
  | "dev.claim.ttl"
  | "dev.claim.ttl.help"
  | "dev.claim.cancel"
  | "dev.claim.generate"
  | "dev.claim.generating"
  | "dev.claim.done"
  | "dev.claim.token.title"
  | "dev.claim.token.warn"
  | "dev.claim.token.copy"
  | "dev.claim.token.copied"
  | "dev.claim.token.expires"
  | "dev.claim.failed.title"
  | "dev.claim.failed.body";

export type B3Catalog = Record<B3Key, string>;

const en: B3Catalog = {
  "b3.retry": "Try again",
  "b3.confidence": "Confidence {pct}",
  "b3.actions": "Actions",

  "dlp.title": "Data loss prevention",
  "dlp.subtitle":
    "Build the rules that spot sensitive data — card numbers, health records, secrets — and decide what happens when someone tries to send it.",
  "dlp.templates.title": "Start from a template",
  "dlp.templates.help.title": "What is a template?",
  "dlp.templates.help.body":
    "A template is a ready-made set of detectors for one kind of sensitive data, such as payment cards or health records. Apply one and we create the matching policies for you — no need to build detectors by hand.",
  "dlp.templates.taxonomy": "Covers {name}",
  "dlp.templates.apply": "Apply template",
  "dlp.templates.applying": "Applying…",
  "dlp.templates.empty.title": "No templates available yet",
  "dlp.templates.empty.desc":
    "Ready-made detector sets will appear here as soon as they're published for your tenant.",
  "dlp.templates.applied.title": "Template applied",
  "dlp.templates.applied.body":
    "We created policies from “{name}”. You'll find them in the list below.",
  "dlp.templates.failed.title": "Couldn't apply that template",
  "dlp.templates.failed.body": "Nothing was changed. Please try again.",
  "dlp.sandbox.title": "Test your detectors",
  "dlp.sandbox.help.title": "Is this safe to paste?",
  "dlp.sandbox.help.body":
    "Yes. Sample text is checked in memory only to show what your detectors would catch. It is never saved or sent anywhere.",
  "dlp.sandbox.desc":
    "Paste a sample message to see what your detectors would catch. Nothing you paste here is stored.",
  "dlp.sandbox.placeholder":
    "Paste sample text — for example a line with a credit-card or Social Security number…",
  "dlp.sandbox.label": "Sample text to test",
  "dlp.sandbox.run": "Check this text",
  "dlp.sandbox.running": "Checking…",
  "dlp.sandbox.result.clean": "No sensitive data found",
  "dlp.sandbox.result.flagged": "{action} · {count, plural, one {# match} other {# matches}}",
  "dlp.sandbox.matches": "{count, plural, one {# match} other {# matches}}",
  "dlp.sandbox.col.detector": "Detector",
  "dlp.sandbox.col.match": "Match",
  "dlp.sandbox.col.confidence": "Confidence",
  "dlp.action.block": "Would block",
  "dlp.action.audit": "Would log",
  "dlp.action.redact": "Would redact",
  "dlp.action.warn": "Would warn",
  "dlp.policies.title": "Your policies",
  "dlp.policies.empty.title": "No policies yet",
  "dlp.policies.empty.desc":
    "Apply a template above and we'll turn it into ready-to-use policies in seconds.",
  "dlp.policies.col.name": "Policy",
  "dlp.policies.col.detectors": "Detectors",
  "dlp.policies.col.action": "When matched",
  "dlp.policies.col.enabled": "Status",
  "dlp.policies.col.created": "Created",
  "dlp.policies.detectors": "{count, plural, one {# detector} other {# detectors}}",
  "dlp.policies.enabled": "On",
  "dlp.policies.disabled": "Off",

  "drq.title": "Review queue",
  "drq.subtitle":
    "When the endpoint spots a risky upload to an AI or cloud app, it coaches the person but doesn't block. Each one waits here for you to decide.",
  "drq.help.title": "Why review these?",
  "drq.help.body":
    "The AI-app upload signal coaches first — it warns the person but lets the file through. Approve the ones that are fine, block real leaks, and dismiss the noise. We only keep a redacted summary, never the actual content.",
  "drq.digest.title": "At a glance",
  "drq.digest.subtitle":
    "A read-only summary of flagged uploads in the range you pick. Make decisions in the queue below.",
  "drq.digest.window.label": "Time range",
  "drq.digest.total": "Flagged uploads",
  "drq.digest.pending": "Waiting on you",
  "drq.digest.apps": "Apps involved",
  "drq.digest.since": "Since",
  "drq.digest.bySeverity": "By severity",
  "drq.digest.byState": "By status",
  "drq.digest.byApp": "Waiting, by app",
  "drq.queue.title": "Queue",
  "drq.queue.hint":
    "Tip: use Tab to step through each upload's Approve, Block and Dismiss buttons — no mouse needed. Open any row for the full details.",
  "drq.queue.capped":
    "Showing the {limit} most recent. Filter by status to work through the rest of the backlog.",
  "drq.filter.label": "Filter by status",
  "drq.filter.all": "All",
  "drq.empty.pending.title": "You're all caught up",
  "drq.empty.pending.desc":
    "Nothing is waiting on review. New flagged uploads will show up here automatically.",
  "drq.empty.other.title": "Nothing matches this filter",
  "drq.empty.other.desc": "Try another status to see decided uploads.",
  "drq.col.destination": "Destination app",
  "drq.col.signal": "Why it was flagged",
  "drq.col.severity": "Severity",
  "drq.col.confidence": "Confidence",
  "drq.col.findings": "What we found",
  "drq.col.state": "Status",
  "drq.col.created": "Flagged",
  "drq.col.decision": "Decision",
  "drq.suspectedAi": "Suspected AI app",
  "drq.sev.low": "Low",
  "drq.sev.medium": "Medium",
  "drq.sev.high": "High",
  "drq.sev.critical": "Critical",
  "drq.state.pending": "Waiting",
  "drq.state.approved": "Approved",
  "drq.state.blocked": "Blocked",
  "drq.state.dismissed": "Dismissed",
  "drq.action.approve": "Approve",
  "drq.action.block": "Block",
  "drq.action.dismiss": "Dismiss",
  "drq.action.details": "Details",
  "drq.toast.approved": "Approved",
  "drq.toast.blocked": "Blocked",
  "drq.toast.dismissed": "Dismissed",
  "drq.toast.recorded": "Your decision has been saved.",
  "drq.toast.failed.title": "That didn't go through",
  "drq.toast.failed.body": "Your decision wasn't saved. Please try again.",
  "drq.detail.title": "Upload details",
  "drq.detail.close": "Close",
  "drq.detail.shortcuts":
    "Keyboard: press A to approve, B to block, or D to dismiss.",
  "drq.field.state": "Status",
  "drq.field.destination": "Destination app",
  "drq.field.signal": "Why it was flagged",
  "drq.field.severity": "Severity",
  "drq.field.confidence": "Confidence",
  "drq.field.created": "Flagged",
  "drq.field.decided": "Decided",
  "drq.field.decidedBy": "Decided by",
  "drq.findings.title": "What we found (redacted summary)",
  "drq.findings.empty": "No details were recorded for this upload.",
  "drq.findings.kind": "Type",
  "drq.findings.detector": "Detector",
  "drq.findings.count": "Count",
  "drq.findings.maxConfidence": "Top confidence",
  "drq.findings.severity": "Severity",
  "drq.signal.aiAppExfiltration": "Sent to an AI app",
  "drq.signal.bulkDownload": "Large bulk download",
  "drq.finding.pii": "Personal data",
  "drq.finding.secret": "Secrets",
  "drq.finding.confidential": "Confidential",

  "casb.title": "Cloud app control",
  "casb.subtitle":
    "See which SaaS apps your team uses, how risky each one is, and decide what to allow.",
  "casb.addConnector": "Add a connector",
  "casb.apps.title": "Apps in use",
  "casb.apps.help.title": "What is shadow IT?",
  "casb.apps.help.body":
    "Shadow IT means apps your team uses that haven't been formally approved. We find them from network traffic and connectors so you can approve the safe ones and block the risky ones.",
  "casb.apps.empty.title": "No apps discovered yet",
  "casb.apps.empty.desc":
    "Connect a cloud source and we'll start listing the SaaS apps your team uses.",
  "casb.risk.help.title": "What does the risk score mean?",
  "casb.risk.help.body":
    "A 0–100 estimate of how risky an app is, based on how it handles data, its compliance posture and how it's used here. Higher means riskier.",
  "casb.col.app": "Application",
  "casb.col.vendor": "Vendor",
  "casb.col.category": "Category",
  "casb.col.risk": "Risk",
  "casb.col.sanction": "Status",
  "casb.col.recommendation": "Recommended action",
  "casb.col.users": "Licensed users",
  "casb.col.devices": "Active devices",
  "casb.col.lastSeen": "Last seen",
  "casb.sanction.unsanctioned": "Not approved",
  "casb.sanction.tolerated": "Tolerated",
  "casb.sanction.sanctioned": "Approved",
  "casb.verdict.none": "Not yet reviewed",
  "casb.enforcement.none": "Monitor",
  "casb.enforcement.throttle": "Slow down",
  "casb.enforcement.protect": "Inspect uploads",
  "casb.enforcement.route": "Route privately",
  "casb.enforcement.enforce": "Block",
  "casb.verdict.applied": "Auto-applied",
  "casb.verdict.recommended": "Recommended",
  "casb.verdict.detail": "{state} · {confidence}% confident",
  "casb.connectors.title": "Connectors",
  "casb.connectors.help.title": "What is a connector?",
  "casb.connectors.help.body":
    "A connector links ShieldNet to one of your cloud providers so we can inspect uploads, shares and downloads as they happen.",
  "casb.connectors.empty.title": "No connectors yet",
  "casb.connectors.empty.desc":
    "Add a connector to inspect uploads, shares and downloads in your cloud apps in real time.",
  "casb.col.connName": "Name",
  "casb.col.connType": "Type",
  "casb.col.connStatus": "Status",
  "casb.col.lastSync": "Last sync",
  "casb.sync": "Sync now",
  "casb.syncing": "Syncing…",
  "casb.sync.done.title": "Sync started",
  "casb.sync.done.body": "We're refreshing this connector's inventory.",
  "casb.sync.failed.title": "Couldn't start the sync",
  "casb.sync.failed.body": "Please try again in a moment.",
  "casb.create.title": "New connector",
  "casb.create.name": "Name",
  "casb.create.name.help": "A short label so you'll recognise it later.",
  "casb.create.namePlaceholder": "e.g. Company Google Workspace",
  "casb.create.type": "Type",
  "casb.create.cancel": "Cancel",
  "casb.create.submit": "Create connector",
  "casb.create.submitting": "Creating…",
  "casb.create.error":
    "We couldn't create the connector. Please check the details and try again.",
  "casb.create.success.title": "Connector added",
  "casb.create.success.body": "We'll start inventorying its apps shortly.",

  "dev.title": "Devices",
  "dev.subtitle":
    "Every enrolled laptop, phone and tablet — its health and whether it can reach your apps.",
  "dev.export": "Export CSV",
  "dev.exporting": "Exporting…",
  "dev.revoke": "Revoke access ({count})",
  "dev.claim": "Enroll a device",
  "dev.col.selectAll": "Select all devices",
  "dev.col.selectRow": "Select {name}",
  "dev.col.name": "Device",
  "dev.col.platform": "Platform",
  "dev.col.status": "Status",
  "dev.col.posture": "Health",
  "dev.col.access": "Access",
  "dev.col.lastSeen": "Last seen",
  "dev.platform.windows": "Windows",
  "dev.platform.macos": "macOS",
  "dev.platform.linux": "Linux",
  "dev.platform.ios": "iOS",
  "dev.platform.android": "Android",
  "dev.posture.healthy": "Healthy",
  "dev.posture.atrisk": "Needs attention",
  "dev.posture.compromised": "Compromised",
  "dev.posture.unknown": "Not reported",
  "dev.posture.help.title": "What do these health states mean?",
  "dev.posture.help.body":
    "Healthy devices meet your security checks and keep full access. Needs attention means a check (like disk encryption) is off, so access is limited. Compromised means the device looks jailbroken or rooted, so access is blocked until it's fixed.",
  "dev.access.allowed": "Can reach apps",
  "dev.access.limited": "Limited access",
  "dev.access.blocked": "Access blocked",
  "dev.access.unknown": "Pending check",
  "dev.empty.title": "No devices enrolled yet",
  "dev.empty.desc":
    "Enroll your first device to start managing access and checking its health.",
  "dev.revoke.confirm.title":
    "Revoke access for {count, plural, one {# device} other {# devices}}?",
  "dev.revoke.confirm.body":
    "They'll be signed out and must enroll again before they can reach your apps. This can't be undone.",
  "dev.revoke.confirm.cancel": "Keep access",
  "dev.revoke.confirm.submit": "Revoke access",
  "dev.revoke.revoking": "Revoking…",
  "dev.revoke.success.title": "Access revoked",
  "dev.revoke.success.body":
    "{count, plural, one {# device} other {# devices}} can no longer reach your apps.",
  "dev.revoke.failed.title": "Couldn't revoke access",
  "dev.revoke.failed.body": "No changes were made. Please try again.",
  "dev.claim.title": "Enroll a device",
  "dev.claim.intro":
    "Generate a one-time token, then enter it in the ShieldNet agent on the new device to enroll it.",
  "dev.claim.ttl": "Valid for (seconds)",
  "dev.claim.ttl.help": "After this many seconds the token expires and can't be used.",
  "dev.claim.cancel": "Cancel",
  "dev.claim.generate": "Generate token",
  "dev.claim.generating": "Generating…",
  "dev.claim.done": "Done",
  "dev.claim.token.title": "Your one-time token",
  "dev.claim.token.warn":
    "Copy it now — for security we show it only once. Paste it into the device's ShieldNet agent.",
  "dev.claim.token.copy": "Copy token",
  "dev.claim.token.copied": "Copied",
  "dev.claim.token.expires": "Expires {datetime}",
  "dev.claim.failed.title": "Couldn't create a token",
  "dev.claim.failed.body": "Please try again in a moment.",
};

// Translated catalogs are merged over English, so a missing key safely falls
// back to the English source (also passed as `defaultMessage` by `useB3`).
// `lane-b3-i18n.test.ts` enforces full coverage as the quality gate.
// eslint-disable-next-line react-refresh/only-export-components
export const B3_MESSAGES: Record<Locale, B3Catalog> = {
  en,
  "zh-Hans": en,
  "zh-Hant": en,
  ms: en,
  id: en,
  th: en,
  vi: en,
  ja: en,
  ko: en,
  ar: en,
  de: en,
  fr: en,
};

export { en as B3_EN };

export function LaneB3Intl({ children }: { children: ReactNode }) {
  const { locale } = useLocale();
  // Merge the locale catalog over English so any not-yet-translated key renders
  // the English source rather than a raw message id.
  const messages = { ...en, ...B3_MESSAGES[locale] };
  return (
    <IntlProvider
      locale={locale}
      defaultLocale="en"
      messages={messages}
      onError={(err) => {
        // English fallback is intentional; stay quiet for missing translations.
        if (err.code === "MISSING_TRANSLATION") return;
        console.error(err);
      }}
    >
      {children}
    </IntlProvider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useB3() {
  const intl = useIntl();
  return (id: B3Key, values?: Record<string, string | number>) =>
    intl.formatMessage({ id, defaultMessage: en[id] }, values);
}
