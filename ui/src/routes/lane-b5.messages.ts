// Lane B5 (Integrations / Webhooks / Terraform / Playbooks / Assistant /
// Metering) message catalog. English source copy lives here as
// `defaultMessage`; react-intl renders it directly (the shared i18n catalog
// covers chrome only and adopts feature-screen keys incrementally — see
// lib/i18n/messages.ts). Keeping every user-facing string here means no
// hard-coded copy in the screens and a single place to translate this lane.
//
// Brand voice: plain language, reassuring, jargon-free — say what happened,
// why it matters, and what to do next.

import { defineMessages } from "react-intl";

export const integrationsMsg = defineMessages({
  title: { id: "laneB5.integrations.title", defaultMessage: "Integrations" },
  subtitle: {
    id: "laneB5.integrations.subtitle",
    defaultMessage:
      "Connect ShieldNet to the SIEM, ticketing, and notification tools your team already uses. Matching security events are forwarded automatically.",
  },
  add: { id: "laneB5.integrations.add", defaultMessage: "Connect a tool" },
  colName: { id: "laneB5.integrations.col.name", defaultMessage: "Name" },
  colType: { id: "laneB5.integrations.col.type", defaultMessage: "Type" },
  colStatus: { id: "laneB5.integrations.col.status", defaultMessage: "Status" },
  colLastTest: { id: "laneB5.integrations.col.lastTest", defaultMessage: "Last test" },
  colActions: { id: "laneB5.integrations.col.actions", defaultMessage: "Actions" },
  test: { id: "laneB5.integrations.test", defaultMessage: "Test" },
  testing: { id: "laneB5.integrations.testing", defaultMessage: "Testing…" },
  remove: { id: "laneB5.integrations.remove", defaultMessage: "Remove" },
  neverTested: { id: "laneB5.integrations.neverTested", defaultMessage: "Not tested yet" },
  emptyTitle: {
    id: "laneB5.integrations.empty.title",
    defaultMessage: "No tools connected yet",
  },
  emptyBody: {
    id: "laneB5.integrations.empty.body",
    defaultMessage:
      "Connect your first integration to forward security events to tools like Splunk, Jira, or ServiceNow — no manual exports needed.",
  },
  deleteTitle: {
    id: "laneB5.integrations.delete.title",
    defaultMessage: "Remove this integration?",
  },
  deleteBody: {
    id: "laneB5.integrations.delete.body",
    defaultMessage:
      "ShieldNet will stop forwarding events to “{name}”. You can reconnect it later, but events sent while it''s disconnected won''t be retried. Nothing is changed inside {name} itself.",
  },
  deleteConfirm: {
    id: "laneB5.integrations.delete.confirm",
    defaultMessage: "Remove integration",
  },
  removing: { id: "laneB5.integrations.removing", defaultMessage: "Removing…" },
  createTitle: { id: "laneB5.integrations.create.title", defaultMessage: "Connect a tool" },
  nameLabel: { id: "laneB5.integrations.create.name.label", defaultMessage: "Name" },
  nameHelp: {
    id: "laneB5.integrations.create.name.help",
    defaultMessage: "A label you''ll recognise later, such as “SOC Splunk”.",
  },
  namePlaceholder: {
    id: "laneB5.integrations.create.name.placeholder",
    defaultMessage: "SOC Splunk",
  },
  typeLabel: { id: "laneB5.integrations.create.type.label", defaultMessage: "Tool type" },
  typeHelp: {
    id: "laneB5.integrations.create.type.help",
    defaultMessage: "Choose where ShieldNet should send events.",
  },
  create: { id: "laneB5.integrations.create.submit", defaultMessage: "Connect" },
  creating: { id: "laneB5.integrations.create.busy", defaultMessage: "Connecting…" },
  createError: {
    id: "laneB5.integrations.create.error",
    defaultMessage: "We couldn''t connect that tool. Check the details and try again.",
  },
  cancel: { id: "laneB5.integrations.cancel", defaultMessage: "Cancel" },
  typeSyslog: { id: "laneB5.integrations.type.syslog", defaultMessage: "Syslog" },
  typeSiem: { id: "laneB5.integrations.type.siem_webhook", defaultMessage: "SIEM webhook" },
  typeJira: { id: "laneB5.integrations.type.jira", defaultMessage: "Jira" },
  typeServicenow: {
    id: "laneB5.integrations.type.servicenow",
    defaultMessage: "ServiceNow",
  },
});

export const webhooksMsg = defineMessages({
  title: { id: "laneB5.webhooks.title", defaultMessage: "Webhooks" },
  subtitle: {
    id: "laneB5.webhooks.subtitle",
    defaultMessage:
      "Send signed, real-time event notifications to HTTPS endpoints you control.",
  },
  add: { id: "laneB5.webhooks.add", defaultMessage: "Add endpoint" },
  colUrl: { id: "laneB5.webhooks.col.url", defaultMessage: "Endpoint" },
  colEvents: { id: "laneB5.webhooks.col.events", defaultMessage: "Events" },
  colStatus: { id: "laneB5.webhooks.col.status", defaultMessage: "Status" },
  colCreated: { id: "laneB5.webhooks.col.created", defaultMessage: "Added" },
  colActions: { id: "laneB5.webhooks.col.actions", defaultMessage: "Actions" },
  remove: { id: "laneB5.webhooks.remove", defaultMessage: "Remove" },
  removing: { id: "laneB5.webhooks.removing", defaultMessage: "Removing…" },
  emptyTitle: { id: "laneB5.webhooks.empty.title", defaultMessage: "No webhook endpoints yet" },
  emptyBody: {
    id: "laneB5.webhooks.empty.body",
    defaultMessage:
      "Add an endpoint to receive real-time, HMAC-signed event notifications at a URL you control.",
  },
  deleteTitle: { id: "laneB5.webhooks.delete.title", defaultMessage: "Remove this webhook?" },
  deleteBody: {
    id: "laneB5.webhooks.delete.body",
    defaultMessage:
      "ShieldNet will stop sending events to this endpoint. Deliveries already sent aren''t affected. You can add the endpoint again at any time.",
  },
  deleteConfirm: { id: "laneB5.webhooks.delete.confirm", defaultMessage: "Remove webhook" },
  createTitle: { id: "laneB5.webhooks.create.title", defaultMessage: "Add webhook endpoint" },
  urlLabel: { id: "laneB5.webhooks.url.label", defaultMessage: "Endpoint URL" },
  urlHelp: {
    id: "laneB5.webhooks.url.help",
    defaultMessage: "A public HTTPS URL that can accept POST requests.",
  },
  urlPlaceholder: {
    id: "laneB5.webhooks.url.placeholder",
    defaultMessage: "https://soc.example.com/hooks/shieldnet",
  },
  eventsLegend: { id: "laneB5.webhooks.events.legend", defaultMessage: "Events to send" },
  eventsHelp: {
    id: "laneB5.webhooks.events.help",
    defaultMessage: "Pick which events trigger a delivery. Choose at least one.",
  },
  create: { id: "laneB5.webhooks.create.submit", defaultMessage: "Create endpoint" },
  creating: { id: "laneB5.webhooks.create.busy", defaultMessage: "Creating…" },
  createError: {
    id: "laneB5.webhooks.create.error",
    defaultMessage:
      "We couldn''t create that webhook. Check the URL and selected events, then try again.",
  },
  secretTitle: { id: "laneB5.webhooks.secret.title", defaultMessage: "Save your signing secret" },
  secretBody: {
    id: "laneB5.webhooks.secret.body",
    defaultMessage:
      "Use this secret to verify the HMAC signature on every delivery. It''s shown only once — store it somewhere safe, because you won''t be able to see it again.",
  },
  copy: { id: "laneB5.webhooks.secret.copy", defaultMessage: "Copy secret" },
  copied: { id: "laneB5.webhooks.secret.copied", defaultMessage: "Copied" },
  done: { id: "laneB5.webhooks.secret.done", defaultMessage: "Done" },
  cancel: { id: "laneB5.webhooks.cancel", defaultMessage: "Cancel" },
});

export const terraformMsg = defineMessages({
  title: { id: "laneB5.terraform.title", defaultMessage: "Configuration as code" },
  subtitle: {
    id: "laneB5.terraform.subtitle",
    defaultMessage:
      "Export this tenant''s settings as a JSON document, re-import it, or check for drift between what''s live and a saved copy.",
  },
  exportTitle: { id: "laneB5.terraform.export.title", defaultMessage: "Current configuration" },
  exportHelp: {
    id: "laneB5.terraform.export.help",
    defaultMessage: "A read-only snapshot of this tenant''s live configuration.",
  },
  download: { id: "laneB5.terraform.download", defaultMessage: "Download JSON" },
  loading: { id: "laneB5.terraform.loading", defaultMessage: "Loading…" },
  exportAria: {
    id: "laneB5.terraform.export.aria",
    defaultMessage: "Current configuration as JSON",
  },
  importTitle: { id: "laneB5.terraform.import.title", defaultMessage: "Import or check drift" },
  importHelp: {
    id: "laneB5.terraform.import.help",
    defaultMessage: "Paste a previously exported configuration document below.",
  },
  importAria: {
    id: "laneB5.terraform.import.aria",
    defaultMessage: "Configuration document to import",
  },
  importPlaceholder: {
    id: "laneB5.terraform.import.placeholder",
    defaultMessage: "Paste the exported JSON configuration document here…",
  },
  runImport: { id: "laneB5.terraform.import.run", defaultMessage: "Import" },
  importing: { id: "laneB5.terraform.import.busy", defaultMessage: "Importing…" },
  runDrift: { id: "laneB5.terraform.drift.run", defaultMessage: "Check for drift" },
  comparing: { id: "laneB5.terraform.drift.busy", defaultMessage: "Comparing…" },
  jsonError: {
    id: "laneB5.terraform.error.json",
    defaultMessage:
      "That doesn''t look like valid JSON. Paste the full exported document, then try again.",
  },
  importSuccess: {
    id: "laneB5.terraform.import.success",
    defaultMessage: "Configuration imported. Your live settings now match the document.",
  },
  importError: {
    id: "laneB5.terraform.import.error",
    defaultMessage: "We couldn''t import that document. Check it and try again.",
  },
  driftError: {
    id: "laneB5.terraform.drift.error",
    defaultMessage: "We couldn''t compare that document. Check it and try again.",
  },
  driftNone: { id: "laneB5.terraform.drift.none", defaultMessage: "In sync — no drift detected" },
  driftSome: {
    id: "laneB5.terraform.drift.some",
    defaultMessage:
      "{count, plural, one {# resource differs from the live config} other {# resources differ from the live config}}",
  },
});

export const playbooksMsg = defineMessages({
  title: { id: "laneB5.playbooks.title", defaultMessage: "Playbooks" },
  subtitle: {
    id: "laneB5.playbooks.subtitle",
    defaultMessage:
      "Automate incident response with runbooks that trigger on events — with human approval before anything runs.",
  },
  add: { id: "laneB5.playbooks.add", defaultMessage: "New playbook" },
  approvalsTitle: { id: "laneB5.playbooks.approvals.title", defaultMessage: "Approvals waiting" },
  approvalsEmptyTitle: {
    id: "laneB5.playbooks.approvals.empty.title",
    defaultMessage: "Nothing waiting for approval",
  },
  approvalsEmptyBody: {
    id: "laneB5.playbooks.approvals.empty.body",
    defaultMessage:
      "When a playbook run needs sign-off, it''ll appear here for you to approve or decline.",
  },
  approvalHeading: {
    id: "laneB5.playbooks.approval.heading",
    defaultMessage: "Playbook {id}",
  },
  approvalRequestedBy: {
    id: "laneB5.playbooks.approval.requestedBy",
    defaultMessage: "Requested by {who} · {when}",
  },
  approvalPending: {
    id: "laneB5.playbooks.approval.pending",
    defaultMessage: "Awaiting approval",
  },
  approve: { id: "laneB5.playbooks.approve", defaultMessage: "Approve & run" },
  reject: { id: "laneB5.playbooks.reject", defaultMessage: "Decline" },
  playbooksTitle: { id: "laneB5.playbooks.list.title", defaultMessage: "Playbooks" },
  pbColName: { id: "laneB5.playbooks.list.col.name", defaultMessage: "Name" },
  pbColTrigger: { id: "laneB5.playbooks.list.col.trigger", defaultMessage: "Runs when" },
  pbColEnabled: { id: "laneB5.playbooks.list.col.enabled", defaultMessage: "Status" },
  pbEmptyTitle: { id: "laneB5.playbooks.list.empty.title", defaultMessage: "No playbooks yet" },
  pbEmptyBody: {
    id: "laneB5.playbooks.list.empty.body",
    defaultMessage:
      "Create a playbook to respond to incidents automatically — for example, isolate a device the moment a critical alert fires.",
  },
  execTitle: { id: "laneB5.playbooks.exec.title", defaultMessage: "Recent runs" },
  exColPlaybook: { id: "laneB5.playbooks.exec.col.playbook", defaultMessage: "Playbook" },
  exColStatus: { id: "laneB5.playbooks.exec.col.status", defaultMessage: "Status" },
  exColStarted: { id: "laneB5.playbooks.exec.col.started", defaultMessage: "Started" },
  exColFinished: { id: "laneB5.playbooks.exec.col.finished", defaultMessage: "Finished" },
  execEmptyTitle: { id: "laneB5.playbooks.exec.empty.title", defaultMessage: "No runs yet" },
  execEmptyBody: {
    id: "laneB5.playbooks.exec.empty.body",
    defaultMessage: "Once a playbook runs, its outcome shows up here.",
  },
  createTitle: { id: "laneB5.playbooks.create.title", defaultMessage: "New playbook" },
  nameLabel: { id: "laneB5.playbooks.create.name.label", defaultMessage: "Name" },
  namePlaceholder: {
    id: "laneB5.playbooks.create.name.placeholder",
    defaultMessage: "Isolate compromised device",
  },
  triggerLabel: { id: "laneB5.playbooks.create.trigger.label", defaultMessage: "Runs when" },
  triggerHelp: {
    id: "laneB5.playbooks.create.trigger.help",
    defaultMessage: "The condition that triggers this playbook.",
  },
  stepsLabel: { id: "laneB5.playbooks.create.steps.label", defaultMessage: "Steps (JSON)" },
  stepsHelp: {
    id: "laneB5.playbooks.create.steps.help",
    defaultMessage: "An ordered list of actions to run. Must be valid JSON.",
  },
  create: { id: "laneB5.playbooks.create.submit", defaultMessage: "Create playbook" },
  creating: { id: "laneB5.playbooks.create.busy", defaultMessage: "Creating…" },
  stepsError: {
    id: "laneB5.playbooks.error.steps",
    defaultMessage: "Steps must be valid JSON. Check the brackets and quotes, then try again.",
  },
  createError: {
    id: "laneB5.playbooks.create.error",
    defaultMessage: "We couldn''t create that playbook. Review the fields and try again.",
  },
  enabled: { id: "laneB5.playbooks.enabled", defaultMessage: "Enabled" },
  disabled: { id: "laneB5.playbooks.disabled", defaultMessage: "Disabled" },
  cancel: { id: "laneB5.playbooks.cancel", defaultMessage: "Cancel" },
  deciding: { id: "laneB5.playbooks.deciding", defaultMessage: "Working…" },
});

export const assistantMsg = defineMessages({
  title: { id: "laneB5.assistant.title", defaultMessage: "AI assistant" },
  subtitle: {
    id: "laneB5.assistant.subtitle",
    defaultMessage:
      "Ask in plain language — troubleshoot connectivity or check what your policy allows. Answers are grounded in this tenant''s data.",
  },
  tabTroubleshoot: { id: "laneB5.assistant.tab.troubleshoot", defaultMessage: "Troubleshoot" },
  tabPolicy: { id: "laneB5.assistant.tab.policy", defaultMessage: "Policy questions" },
  emptyTroubleshoot: {
    id: "laneB5.assistant.empty.troubleshoot",
    defaultMessage: "What can I help you troubleshoot?",
  },
  emptyPolicy: {
    id: "laneB5.assistant.empty.policy",
    defaultMessage: "Ask a question about your policy",
  },
  tryAsking: { id: "laneB5.assistant.tryAsking", defaultMessage: "Try asking" },
  composerPlaceholder: {
    id: "laneB5.assistant.composer.placeholder",
    defaultMessage: "Type your question…",
  },
  composerBusy: { id: "laneB5.assistant.composer.busy", defaultMessage: "Thinking…" },
  send: { id: "laneB5.assistant.composer.send", defaultMessage: "Send" },
  composerHelp: {
    id: "laneB5.assistant.composer.help",
    defaultMessage: "Press Enter to send.",
  },
  you: { id: "laneB5.assistant.msg.you", defaultMessage: "You" },
  assistant: { id: "laneB5.assistant.msg.assistant", defaultMessage: "Assistant" },
  logAria: { id: "laneB5.assistant.log.aria", defaultMessage: "Conversation" },
  verdict: { id: "laneB5.assistant.verdict", defaultMessage: "Verdict" },
  matchedRules: {
    id: "laneB5.assistant.matchedRules",
    defaultMessage: "Matched rules: {rules}",
  },
  references: { id: "laneB5.assistant.references", defaultMessage: "References: {docs}" },
  noSuggestions: {
    id: "laneB5.assistant.noSuggestions",
    defaultMessage: "No suggestions returned for that question.",
  },
  confidence: {
    id: "laneB5.assistant.meta.confidence",
    defaultMessage: "{pct}% confidence",
  },
  heuristic: { id: "laneB5.assistant.meta.heuristic", defaultMessage: "heuristic" },
  deterministic: { id: "laneB5.assistant.meta.deterministic", defaultMessage: "deterministic" },
  errorMeta: { id: "laneB5.assistant.meta.error", defaultMessage: "Couldn''t answer" },
  errorGeneric: {
    id: "laneB5.assistant.error.generic",
    defaultMessage: "Something went wrong reaching the assistant. Please try again.",
  },
  exTrouble1: {
    id: "laneB5.assistant.ex.trouble1",
    defaultMessage: "Why can''t a device reach an internal app?",
  },
  exTrouble2: {
    id: "laneB5.assistant.ex.trouble2",
    defaultMessage: "Why does this tunnel keep dropping?",
  },
  exTrouble3: {
    id: "laneB5.assistant.ex.trouble3",
    defaultMessage: "A user reports slow web browsing — where do I start?",
  },
  exPolicy1: {
    id: "laneB5.assistant.ex.policy1",
    defaultMessage: "Can contractors reach the finance app?",
  },
  exPolicy2: {
    id: "laneB5.assistant.ex.policy2",
    defaultMessage: "Is social media blocked for the sales team?",
  },
  exPolicy3: {
    id: "laneB5.assistant.ex.policy3",
    defaultMessage: "Which groups can use personal cloud storage?",
  },
});

export const meteringMsg = defineMessages({
  title: { id: "laneB5.metering.title", defaultMessage: "Metering & cost" },
  subtitle: {
    id: "laneB5.metering.subtitle",
    defaultMessage:
      "See how much you''re using against your budgets, what it''s projected to cost, and where the spend goes.",
  },
  editBudgets: { id: "laneB5.metering.editBudgets", defaultMessage: "Edit budgets" },
  projectedLabel: {
    id: "laneB5.metering.summary.projected.label",
    defaultMessage: "Projected monthly cost",
  },
  projectedHint: {
    id: "laneB5.metering.summary.projected.hint",
    defaultMessage: "{amount} so far this period",
  },
  healthLabel: { id: "laneB5.metering.summary.health.label", defaultMessage: "Budget health" },
  healthAllOk: {
    id: "laneB5.metering.summary.health.allOk",
    defaultMessage: "All within budget",
  },
  healthOverSoft: {
    id: "laneB5.metering.summary.health.overSoft",
    defaultMessage:
      "{count, plural, one {# meter over soft limit} other {# meters over soft limit}}",
  },
  healthOverHard: {
    id: "laneB5.metering.summary.health.overHard",
    defaultMessage:
      "{count, plural, one {# meter over hard limit} other {# meters over hard limit}}",
  },
  healthHint: {
    id: "laneB5.metering.summary.health.hint",
    defaultMessage: "{count, plural, one {# metered item} other {# metered items}}",
  },
  marginLabel: { id: "laneB5.metering.summary.margin.label", defaultMessage: "Margin" },
  marginHint: { id: "laneB5.metering.summary.margin.hint", defaultMessage: "{amount} / month" },
  topDriverLabel: {
    id: "laneB5.metering.summary.topDriver.label",
    defaultMessage: "Top cost driver",
  },
  topDriverHint: {
    id: "laneB5.metering.summary.topDriver.hint",
    defaultMessage: "{pct} of {amount}",
  },
  topDriverNone: {
    id: "laneB5.metering.summary.topDriver.none",
    defaultMessage: "No cost recorded yet",
  },
  tableTitle: { id: "laneB5.metering.table.title", defaultMessage: "Usage by meter" },
  tableSubtitle: {
    id: "laneB5.metering.table.subtitle",
    defaultMessage:
      "What you''ve used this period, the projected run-rate, and the cost for each meter.",
  },
  colMeter: { id: "laneB5.metering.table.col.meter", defaultMessage: "Meter" },
  colPeriod: { id: "laneB5.metering.table.col.period", defaultMessage: "Period" },
  colUsed: { id: "laneB5.metering.table.col.used", defaultMessage: "Used" },
  colSoft: { id: "laneB5.metering.table.col.soft", defaultMessage: "Soft limit" },
  colHard: { id: "laneB5.metering.table.col.hard", defaultMessage: "Hard limit" },
  colProjected: { id: "laneB5.metering.table.col.projected", defaultMessage: "Projected" },
  colCost: { id: "laneB5.metering.table.col.cost", defaultMessage: "Cost" },
  colBudget: { id: "laneB5.metering.table.col.budget", defaultMessage: "Budget used" },
  colStatus: { id: "laneB5.metering.table.col.status", defaultMessage: "Status" },
  tableEmptyTitle: {
    id: "laneB5.metering.table.empty.title",
    defaultMessage: "No usage yet this period",
  },
  tableEmptyBody: {
    id: "laneB5.metering.table.empty.body",
    defaultMessage: "Usage appears here as this tenant''s traffic is processed.",
  },
  budgetUnbounded: {
    id: "laneB5.metering.budgetbar.unbounded",
    defaultMessage: "No limit set",
  },
  statusOk: { id: "laneB5.metering.status.ok", defaultMessage: "On track" },
  statusWarning: { id: "laneB5.metering.status.warning", defaultMessage: "Near limit" },
  statusExceeded: { id: "laneB5.metering.status.exceeded", defaultMessage: "Over limit" },
  trendTitle: { id: "laneB5.metering.trend.title", defaultMessage: "Usage trend" },
  trendSubtitle: {
    id: "laneB5.metering.trend.subtitle",
    defaultMessage: "Completed-month totals per meter. Select a meter to show or hide its line.",
  },
  windowLabel: { id: "laneB5.metering.trend.window.label", defaultMessage: "Window" },
  windowOption: {
    id: "laneB5.metering.trend.window.option",
    defaultMessage: "{count} months",
  },
  trendEmptyTitle: { id: "laneB5.metering.trend.empty.title", defaultMessage: "No history yet" },
  trendEmptyBody: {
    id: "laneB5.metering.trend.empty.body",
    defaultMessage: "Trends appear after your first completed billing period.",
  },
  infraTitle: {
    id: "laneB5.metering.infra.title",
    defaultMessage: "Where infrastructure cost goes",
  },
  infraSubtitle: {
    id: "laneB5.metering.infra.subtitle",
    defaultMessage: "Projected monthly infrastructure spend by backend service.",
  },
  infraEmptyTitle: {
    id: "laneB5.metering.infra.empty.title",
    defaultMessage: "No infrastructure cost yet",
  },
  infraEmptyBody: {
    id: "laneB5.metering.infra.empty.body",
    defaultMessage:
      "This appears once the tenant accrues telemetry storage and write volume.",
  },
  infraTotal: { id: "laneB5.metering.infra.total", defaultMessage: "Total / month" },
  infraRows: { id: "laneB5.metering.infra.rows", defaultMessage: "{rows} rows projected" },
  infraResident: { id: "laneB5.metering.infra.resident", defaultMessage: "{gb} GB resident" },
  infraUnattributed: {
    id: "laneB5.metering.infra.unattributed",
    defaultMessage: "Not billed per tenant",
  },
  footnote: {
    id: "laneB5.metering.footnote",
    defaultMessage:
      "All amounts are USD estimates for cost and margin analysis — not invoices. Storage figures (NATS, S3) are point-in-time; ClickHouse is a projected monthly write volume.",
  },
  fleetTitle: { id: "laneB5.metering.fleet.title", defaultMessage: "Fleet cost & margin" },
  fleetSubtitle: {
    id: "laneB5.metering.fleet.subtitle",
    defaultMessage: "{count} tenants — platform-wide cost report.",
  },
  fleetEmptyTitle: { id: "laneB5.metering.fleet.empty.title", defaultMessage: "No tenants yet" },
  fleetEmptyBody: {
    id: "laneB5.metering.fleet.empty.body",
    defaultMessage: "Per-tenant cost and margin appear here once tenants are reporting.",
  },
  fleetColTenant: { id: "laneB5.metering.fleet.col.tenant", defaultMessage: "Tenant" },
  fleetColTier: { id: "laneB5.metering.fleet.col.tier", defaultMessage: "Tier" },
  fleetColCost: { id: "laneB5.metering.fleet.col.cost", defaultMessage: "Projected cost" },
  fleetColRevenue: { id: "laneB5.metering.fleet.col.revenue", defaultMessage: "Revenue" },
  fleetColMargin: { id: "laneB5.metering.fleet.col.margin", defaultMessage: "Margin" },
  fleetColMarginPct: { id: "laneB5.metering.fleet.col.marginPct", defaultMessage: "Margin %" },
  fleetSortMargin: {
    id: "laneB5.metering.fleet.sortMargin",
    defaultMessage: "Sort by margin {dir}",
  },
  sortAscending: { id: "laneB5.metering.sort.asc", defaultMessage: "ascending" },
  sortDescending: { id: "laneB5.metering.sort.desc", defaultMessage: "descending" },
  fleetTotal: { id: "laneB5.metering.fleet.total", defaultMessage: "Total" },
  budgetTitle: { id: "laneB5.metering.budget.title", defaultMessage: "Edit budgets" },
  budgetIntro: {
    id: "laneB5.metering.budget.intro",
    defaultMessage:
      "Set a soft and hard limit per meter. Soft limits warn you; hard limits stop usage. Leave a field blank (or 0) for no limit.",
  },
  budgetColMeter: { id: "laneB5.metering.budget.col.meter", defaultMessage: "Meter" },
  budgetColPeriod: { id: "laneB5.metering.budget.col.period", defaultMessage: "Period" },
  budgetColSoft: { id: "laneB5.metering.budget.col.soft", defaultMessage: "Soft limit" },
  budgetColHard: { id: "laneB5.metering.budget.col.hard", defaultMessage: "Hard limit" },
  budgetSave: { id: "laneB5.metering.budget.save", defaultMessage: "Save budgets" },
  budgetSaving: { id: "laneB5.metering.budget.saving", defaultMessage: "Saving…" },
  budgetCancel: { id: "laneB5.metering.budget.cancel", defaultMessage: "Cancel" },
  budgetSoftHardError: {
    id: "laneB5.metering.budget.error.softHard",
    defaultMessage: "Soft limit can''t be higher than the hard limit.",
  },
  budgetSaveError: {
    id: "laneB5.metering.budget.error.generic",
    defaultMessage: "We couldn''t save your budgets. Please try again.",
  },
  budgetSoftAria: {
    id: "laneB5.metering.budget.aria.soft",
    defaultMessage: "{meter} soft limit",
  },
  budgetHardAria: {
    id: "laneB5.metering.budget.aria.hard",
    defaultMessage: "{meter} hard limit",
  },
  cancel: { id: "laneB5.metering.cancel", defaultMessage: "Cancel" },
});

// Display names for the meter enum. Kept as messages so the lane catalog owns
// every visible string; product names (ClickHouse, S3, NATS) stay literal.
export const meterMsg = defineMessages({
  llm_tokens_used: { id: "laneB5.meter.llm_tokens_used", defaultMessage: "LLM tokens" },
  llm_calls: { id: "laneB5.meter.llm_calls", defaultMessage: "LLM calls" },
  url_cat_lookups: { id: "laneB5.meter.url_cat_lookups", defaultMessage: "URL categorisation" },
  malware_scans: { id: "laneB5.meter.malware_scans", defaultMessage: "Malware scans" },
  clickhouse_rows_written: {
    id: "laneB5.meter.clickhouse_rows_written",
    defaultMessage: "ClickHouse rows",
  },
  s3_bytes_archived: { id: "laneB5.meter.s3_bytes_archived", defaultMessage: "S3 bytes archived" },
  bandwidth_proxied_bytes: {
    id: "laneB5.meter.bandwidth_proxied_bytes",
    defaultMessage: "Bandwidth proxied",
  },
  policy_evaluations: {
    id: "laneB5.meter.policy_evaluations",
    defaultMessage: "Policy evaluations",
  },
});
