// Lane B6 (MSP / multi-tenant management) message catalog.
//
// The shared central catalog (`src/lib/i18n/messages.ts`) is frozen WS0 and
// covers app chrome only; per its own note, "feature screens adopt keys
// incrementally". This module owns the user-facing strings for the seven
// MSP / multi-tenant screens, declared with `defineMessages` so every string
// has a stable id and an English source (`defaultMessage`). react-intl renders
// the `defaultMessage` for the default locale and falls back to it for any
// locale that has not yet translated these keys — so there are no hard-coded
// strings in the screens themselves.
import { defineMessages } from "react-intl";

export const M = defineMessages({
  // --- shared / common ------------------------------------------------------
  cancel: { id: "laneB6.common.cancel", defaultMessage: "Cancel" },
  create: { id: "laneB6.common.create", defaultMessage: "Create" },
  creating: { id: "laneB6.common.creating", defaultMessage: "Creating…" },
  save: { id: "laneB6.common.save", defaultMessage: "Save" },
  retryHint: {
    id: "laneB6.common.retryHint",
    defaultMessage: "Check your connection and try again.",
  },
  permTitle: {
    id: "laneB6.common.permTitle",
    defaultMessage: "You don’t have access to this",
  },
  permBody: {
    id: "laneB6.common.permBody",
    defaultMessage:
      "Your account isn’t permitted to view this data. Ask an administrator to grant you the matching MSP role, then reload.",
  },
  permReload: { id: "laneB6.common.permReload", defaultMessage: "Reload" },

  // --- scope banners --------------------------------------------------------
  scopeTenantLabel: {
    id: "laneB6.scope.tenant.label",
    defaultMessage: "Working in tenant",
  },
  scopeTenantSub: {
    id: "laneB6.scope.tenant.sub",
    defaultMessage:
      "Changes on this screen apply only to this customer. Switch tenants from the selector in the top bar.",
  },
  scopeNoTenantTitle: {
    id: "laneB6.scope.noTenant.title",
    defaultMessage: "Pick a tenant to continue",
  },
  scopeNoTenantBody: {
    id: "laneB6.scope.noTenant.body",
    defaultMessage:
      "These settings are configured one customer at a time. Choose a tenant from the selector in the top bar to begin.",
  },
  scopeMspLabel: {
    id: "laneB6.scope.msp.label",
    defaultMessage: "Acting on behalf of",
  },
  scopeMspCohort: {
    id: "laneB6.scope.msp.cohort",
    defaultMessage:
      "{count, plural, =0 {No tenants in this cohort yet} one {# tenant in this cohort} other {# tenants in this cohort}}",
  },
  scopeMspSub: {
    id: "laneB6.scope.msp.sub",
    defaultMessage:
      "Bulk actions below run across every tenant this provider owns. Switch providers with the selector above.",
  },

  // --- Tenants --------------------------------------------------------------
  tenantsTitle: { id: "laneB6.tenants.title", defaultMessage: "Tenants" },
  tenantsSubtitle: {
    id: "laneB6.tenants.subtitle",
    defaultMessage: "Customer organizations managed by this control plane.",
  },
  tenantsNew: { id: "laneB6.tenants.new", defaultMessage: "New tenant" },
  colName: { id: "laneB6.tenants.col.name", defaultMessage: "Name" },
  colSlug: { id: "laneB6.tenants.col.slug", defaultMessage: "Slug" },
  colStatus: { id: "laneB6.tenants.col.status", defaultMessage: "Status" },
  colTier: { id: "laneB6.tenants.col.tier", defaultMessage: "Plan" },
  colRegion: { id: "laneB6.tenants.col.region", defaultMessage: "Region" },
  colManagedBy: {
    id: "laneB6.tenants.col.managedBy",
    defaultMessage: "Managed by",
  },
  colCreated: { id: "laneB6.tenants.col.created", defaultMessage: "Created" },
  colActions: { id: "laneB6.tenants.col.actions", defaultMessage: "Actions" },
  tenantManaged: {
    id: "laneB6.tenants.managed",
    defaultMessage: "MSP-managed",
  },
  tenantDirect: { id: "laneB6.tenants.direct", defaultMessage: "Direct" },
  makeActive: {
    id: "laneB6.tenants.makeActive",
    defaultMessage: "Switch to this tenant",
  },
  makeActiveTitle: {
    id: "laneB6.tenants.makeActiveTitle",
    defaultMessage: "Make this the active tenant for the console",
  },
  suspend: { id: "laneB6.tenants.suspend", defaultMessage: "Suspend" },
  resume: { id: "laneB6.tenants.resume", defaultMessage: "Active" },
  delete: { id: "laneB6.tenants.delete", defaultMessage: "Delete" },
  tenantsEmptyTitle: {
    id: "laneB6.tenants.empty.title",
    defaultMessage: "No tenants yet",
  },
  tenantsEmptyBody: {
    id: "laneB6.tenants.empty.body",
    defaultMessage:
      "Tenants are the customer organizations you secure. Create your first one to start provisioning sites, policies and devices.",
  },
  activeTenantTag: {
    id: "laneB6.tenants.activeTag",
    defaultMessage: "You’re here",
  },
  // create tenant modal
  createTenantTitle: {
    id: "laneB6.tenants.create.title",
    defaultMessage: "Create tenant",
  },
  fieldName: { id: "laneB6.field.name", defaultMessage: "Name" },
  fieldSlug: { id: "laneB6.field.slug", defaultMessage: "Slug" },
  fieldSlugOptional: {
    id: "laneB6.field.slug.optional",
    defaultMessage: "Slug (optional)",
  },
  fieldSlugHelp: {
    id: "laneB6.field.slug.help",
    defaultMessage:
      "A short, URL-friendly identifier. Leave blank to generate one from the name.",
  },
  fieldRegionOptional: {
    id: "laneB6.field.region.optional",
    defaultMessage: "Region (optional)",
  },
  fieldRegionHelp: {
    id: "laneB6.field.region.help",
    defaultMessage:
      "Where this tenant’s data is hosted. Defaults to the platform’s primary region.",
  },
  fieldTier: { id: "laneB6.field.tier", defaultMessage: "Plan" },
  createTenantError: {
    id: "laneB6.tenants.create.error",
    defaultMessage:
      "We couldn’t create the tenant. Check the name and slug are unique, then try again.",
  },
  createdToastTitle: {
    id: "laneB6.tenants.created.title",
    defaultMessage: "Tenant created",
  },
  createdToastBody: {
    id: "laneB6.tenants.created.body",
    defaultMessage: "{name} is ready. Provision its first site to get going.",
  },
  // suspend / delete confirms
  suspendConfirmTitle: {
    id: "laneB6.tenants.suspend.title",
    defaultMessage: "Suspend {name}?",
  },
  suspendConfirmBody: {
    id: "laneB6.tenants.suspend.body",
    defaultMessage:
      "Users lose access until you resume the tenant. Sites and policies are kept, nothing is deleted.",
  },
  suspendConfirmCta: {
    id: "laneB6.tenants.suspend.cta",
    defaultMessage: "Suspend tenant",
  },
  deleteConfirmTitle: {
    id: "laneB6.tenants.delete.title",
    defaultMessage: "Delete {name}?",
  },
  deleteConfirmBody: {
    id: "laneB6.tenants.delete.body",
    defaultMessage:
      "This permanently removes the tenant and everything in it — sites, policies and devices. This can’t be undone.",
  },
  deleteConfirmCta: {
    id: "laneB6.tenants.delete.cta",
    defaultMessage: "Delete permanently",
  },
  suspendedToast: {
    id: "laneB6.tenants.suspended.toast",
    defaultMessage: "{name} is suspended. Resume it anytime to restore access.",
  },
  suspendErrorTitle: {
    id: "laneB6.tenants.suspend.error.title",
    defaultMessage: "Couldn’t suspend tenant",
  },
  suspendErrorBody: {
    id: "laneB6.tenants.suspend.error.body",
    defaultMessage: "Something went wrong suspending {name}. Please try again.",
  },
  deletedToast: {
    id: "laneB6.tenants.deleted.toast",
    defaultMessage: "{name} was deleted.",
  },
  deleteErrorTitle: {
    id: "laneB6.tenants.delete.error.title",
    defaultMessage: "Couldn’t delete tenant",
  },
  deleteErrorBody: {
    id: "laneB6.tenants.delete.error.body",
    defaultMessage: "Something went wrong deleting {name}. Please try again.",
  },
  typeToConfirm: {
    id: "laneB6.confirm.type",
    defaultMessage: "Type {name} to confirm",
  },

  // --- MspPicker ------------------------------------------------------------
  pickerLabel: {
    id: "laneB6.picker.label",
    defaultMessage: "Managed service provider",
  },
  pickerHelp: {
    id: "laneB6.picker.help",
    defaultMessage:
      "The partner whose tenant cohort you’re managing. Every bulk action applies to this provider’s tenants.",
  },
  pickerLoading: {
    id: "laneB6.picker.loading",
    defaultMessage: "Loading providers…",
  },
  pickerEmpty: {
    id: "laneB6.picker.empty",
    defaultMessage: "No providers available",
  },
  pickerEmptyHint: {
    id: "laneB6.picker.emptyHint",
    defaultMessage:
      "Register a managed service provider on the MSP hierarchy screen first.",
  },

  // --- MspHierarchy ---------------------------------------------------------
  hierTitle: { id: "laneB6.hier.title", defaultMessage: "MSP hierarchy" },
  hierSubtitle: {
    id: "laneB6.hier.subtitle",
    defaultMessage:
      "Managed service providers and the customer tenants they administer.",
  },
  hierNew: { id: "laneB6.hier.new", defaultMessage: "Register MSP" },
  hierProviders: { id: "laneB6.hier.providers", defaultMessage: "Providers" },
  hierProvidersSub: {
    id: "laneB6.hier.providersSub",
    defaultMessage: "Select a provider to see the tenants it manages.",
  },
  hierBindings: {
    id: "laneB6.hier.bindings",
    defaultMessage: "Managed tenants",
  },
  hierEmptyTitle: {
    id: "laneB6.hier.empty.title",
    defaultMessage: "No providers registered",
  },
  hierEmptyBody: {
    id: "laneB6.hier.empty.body",
    defaultMessage:
      "Register a managed service provider to delegate management of a group of tenants to a partner.",
  },
  hierPickPrompt: {
    id: "laneB6.hier.pickPrompt",
    defaultMessage: "Select a provider",
  },
  hierPickBody: {
    id: "laneB6.hier.pickBody",
    defaultMessage:
      "Choose a provider on the left to view the customer tenants in its cohort.",
  },
  hierTenantsEmptyTitle: {
    id: "laneB6.hier.tenants.empty.title",
    defaultMessage: "No tenants assigned",
  },
  hierTenantsEmptyBody: {
    id: "laneB6.hier.tenants.empty.body",
    defaultMessage:
      "This provider doesn’t manage any tenants yet. Assign tenants to it to populate this cohort.",
  },
  hierStatusLabel: {
    id: "laneB6.hier.statusLabel",
    defaultMessage: "Set status for {name}",
  },
  hierDeleteTitle: {
    id: "laneB6.hier.delete.title",
    defaultMessage: "Delete {name}?",
  },
  hierDeleteBody: {
    id: "laneB6.hier.delete.body",
    defaultMessage:
      "This soft-deletes the provider and unassigns every tenant in its cohort. The tenants themselves are kept. This can’t be undone.",
  },
  hierDeleteCta: {
    id: "laneB6.hier.delete.cta",
    defaultMessage: "Delete provider",
  },
  hierRelOwner: { id: "laneB6.hier.rel.owner", defaultMessage: "Owner" },
  hierRelCoManager: {
    id: "laneB6.hier.rel.coManager",
    defaultMessage: "Co-manager",
  },
  hierCreateTitle: {
    id: "laneB6.hier.create.title",
    defaultMessage: "Register a managed service provider",
  },
  hierCreateError: {
    id: "laneB6.hier.create.error",
    defaultMessage:
      "We couldn’t register the provider. Check the name and slug are unique, then try again.",
  },
  hierTenantId: {
    id: "laneB6.hier.tenantId",
    defaultMessage: "Tenant ID",
  },
  hierStatusToast: {
    id: "laneB6.hier.statusToast",
    defaultMessage: "Provider status updated",
  },
  hierActionError: {
    id: "laneB6.hier.actionError",
    defaultMessage: "That action didn’t go through. Please try again.",
  },
  hierDeletedToast: {
    id: "laneB6.hier.deletedToast",
    defaultMessage: "{name} was removed",
  },
  hierCreatedToast: {
    id: "laneB6.hier.createdToast",
    defaultMessage: "{name} registered",
  },

  // --- MspBranding ----------------------------------------------------------
  brandTitle: { id: "laneB6.brand.title", defaultMessage: "Tenant branding" },
  brandSubtitle: {
    id: "laneB6.brand.subtitle",
    defaultMessage:
      "Give each customer a white-labelled self-service portal — their logo, colours and support details.",
  },
  brandConfig: {
    id: "laneB6.brand.config",
    defaultMessage: "Portal appearance",
  },
  brandPreview: {
    id: "laneB6.brand.preview",
    defaultMessage: "Live preview",
  },
  brandPreviewSub: {
    id: "laneB6.brand.previewSub",
    defaultMessage: "How this customer’s portal will look to their users.",
  },
  brandLogo: { id: "laneB6.brand.logo", defaultMessage: "Logo URL" },
  brandLogoHelp: {
    id: "laneB6.brand.logoHelp",
    defaultMessage:
      "A link to the customer’s logo image. Shown in the portal header.",
  },
  brandPrimary: {
    id: "laneB6.brand.primary",
    defaultMessage: "Primary colour",
  },
  brandSecondary: {
    id: "laneB6.brand.secondary",
    defaultMessage: "Accent colour",
  },
  brandDomain: {
    id: "laneB6.brand.domain",
    defaultMessage: "Custom domain",
  },
  brandSupport: {
    id: "laneB6.brand.support",
    defaultMessage: "Support email",
  },
  brandSave: {
    id: "laneB6.brand.save",
    defaultMessage: "Save branding",
  },
  brandSaving: { id: "laneB6.brand.saving", defaultMessage: "Saving…" },
  brandReset: {
    id: "laneB6.brand.reset",
    defaultMessage: "Reset to default",
  },
  brandSavedTitle: {
    id: "laneB6.brand.saved.title",
    defaultMessage: "Branding saved",
  },
  brandSavedBody: {
    id: "laneB6.brand.saved.body",
    defaultMessage: "This customer’s portal now uses the new appearance.",
  },
  brandResetTitle: {
    id: "laneB6.brand.reset.title",
    defaultMessage: "Branding reset",
  },
  brandResetBody: {
    id: "laneB6.brand.reset.body",
    defaultMessage: "The portal is back to the default ShieldNet appearance.",
  },
  brandError: {
    id: "laneB6.brand.error",
    defaultMessage: "We couldn’t save the branding. Please try again.",
  },
  brandResetConfirmTitle: {
    id: "laneB6.brand.resetConfirm.title",
    defaultMessage: "Reset branding to default?",
  },
  brandResetConfirmBody: {
    id: "laneB6.brand.resetConfirm.body",
    defaultMessage:
      "This clears the custom logo, colours and domain for this tenant and restores the default ShieldNet portal.",
  },
  brandPreviewLogoAlt: {
    id: "laneB6.brand.previewLogoAlt",
    defaultMessage: "Customer portal logo",
  },
  brandPreviewAction: {
    id: "laneB6.brand.previewAction",
    defaultMessage: "Primary action",
  },
  brandPreviewServedAt: {
    id: "laneB6.brand.previewServedAt",
    defaultMessage: "Served at {domain}",
  },
  brandPreviewDefaultDomain: {
    id: "laneB6.brand.previewDefaultDomain",
    defaultMessage: "Default platform domain",
  },
  brandPreviewSupport: {
    id: "laneB6.brand.previewSupport",
    defaultMessage: "Support: {email}",
  },

  // --- MspBulkOps -----------------------------------------------------------
  bulkTitle: {
    id: "laneB6.bulk.title",
    defaultMessage: "Bulk operations",
  },
  bulkSubtitle: {
    id: "laneB6.bulk.subtitle",
    defaultMessage:
      "Roll out provisioning and policy changes across a provider’s whole tenant cohort in one pass.",
  },
  bulkOnboardCard: {
    id: "laneB6.bulk.onboard.card",
    defaultMessage: "Onboard the whole cohort",
  },
  bulkOnboardIntro: {
    id: "laneB6.bulk.onboard.intro",
    defaultMessage:
      "Run the full onboarding sequence for every tenant this provider owns: provision a site, optionally apply a baseline policy, and issue enrolment tokens.",
  },
  bulkSiteName: {
    id: "laneB6.bulk.siteName",
    defaultMessage: "Site name (one per tenant)",
  },
  bulkSiteTemplate: {
    id: "laneB6.bulk.siteTemplate",
    defaultMessage: "Site template",
  },
  bulkTokens: {
    id: "laneB6.bulk.tokens",
    defaultMessage: "Enrolment tokens per tenant",
  },
  bulkBaselinePolicy: {
    id: "laneB6.bulk.baselinePolicy",
    defaultMessage: "Baseline policy",
  },
  bulkApplyPolicyLabel: {
    id: "laneB6.bulk.applyPolicyLabel",
    defaultMessage: "Apply a policy template to every tenant",
  },
  bulkPolicyJson: {
    id: "laneB6.bulk.policyJson",
    defaultMessage: "Policy template (JSON — same shape as the policy graph)",
  },
  bulkRun: {
    id: "laneB6.bulk.run",
    defaultMessage: "Review & onboard cohort",
  },
  bulkRunning: {
    id: "laneB6.bulk.running",
    defaultMessage: "Onboarding cohort…",
  },
  bulkTokensNote: {
    id: "laneB6.bulk.tokensNote",
    defaultMessage:
      "Enrolment tokens are issued once and never shown here — distribute them from each tenant’s device page.",
  },
  bulkErrSiteName: {
    id: "laneB6.bulk.err.siteName",
    defaultMessage: "Enter a site name to provision for each tenant.",
  },
  bulkErrTokens: {
    id: "laneB6.bulk.err.tokens",
    defaultMessage: "Tokens per tenant must be a whole number of at least 1.",
  },
  bulkErrJson: {
    id: "laneB6.bulk.err.json",
    defaultMessage:
      "The policy template isn’t valid JSON. Check for a missing comma or bracket.",
  },
  // confirm dialog
  bulkConfirmTitle: {
    id: "laneB6.bulk.confirm.title",
    defaultMessage: "Onboard {count, plural, one {# tenant} other {# tenants}}?",
  },
  bulkConfirmIntro: {
    id: "laneB6.bulk.confirm.intro",
    defaultMessage:
      "This runs across every tenant owned by {msp}. Here’s exactly what will happen:",
  },
  bulkConfirmSite: {
    id: "laneB6.bulk.confirm.site",
    defaultMessage: "Provision a “{site}” site ({template}) for each tenant",
  },
  bulkConfirmPolicy: {
    id: "laneB6.bulk.confirm.policy",
    defaultMessage: "Apply the baseline policy template to each tenant",
  },
  bulkConfirmTokens: {
    id: "laneB6.bulk.confirm.tokens",
    defaultMessage: "Issue {count} enrolment tokens to each tenant",
  },
  bulkConfirmCta: {
    id: "laneB6.bulk.confirm.cta",
    defaultMessage: "Onboard cohort",
  },
  bulkConfirmNoTenants: {
    id: "laneB6.bulk.confirm.noTenants",
    defaultMessage:
      "This provider has no tenants yet, so there’s nothing to onboard.",
  },
  // results
  bulkResultsTitle: {
    id: "laneB6.bulk.results.title",
    defaultMessage: "Onboarding results",
  },
  bulkSucceeded: {
    id: "laneB6.bulk.succeeded",
    defaultMessage: "{count} succeeded",
  },
  bulkFailed: {
    id: "laneB6.bulk.failed",
    defaultMessage: "{count} failed",
  },
  bulkRanAt: { id: "laneB6.bulk.ranAt", defaultMessage: "Run {when}" },
  bulkColTenant: {
    id: "laneB6.bulk.col.tenant",
    defaultMessage: "Tenant",
  },
  bulkColSite: { id: "laneB6.bulk.col.site", defaultMessage: "Site" },
  bulkColPolicy: { id: "laneB6.bulk.col.policy", defaultMessage: "Policy" },
  bulkColTokens: { id: "laneB6.bulk.col.tokens", defaultMessage: "Tokens" },
  bulkColStatus: { id: "laneB6.bulk.col.status", defaultMessage: "Outcome" },
  bulkStatusOk: { id: "laneB6.bulk.status.ok", defaultMessage: "Done" },
  bulkStatusErr: {
    id: "laneB6.bulk.status.err",
    defaultMessage:
      "{count, plural, one {# problem} other {# problems}}",
  },
  bulkPolicyVer: {
    id: "laneB6.bulk.policyVer",
    defaultMessage: "Version {v}",
  },
  bulkDoneToast: {
    id: "laneB6.bulk.doneToast",
    defaultMessage: "Cohort onboarded",
  },
  bulkDoneToastBody: {
    id: "laneB6.bulk.doneToastBody",
    defaultMessage:
      "{count, plural, one {# tenant} other {# tenants}} provisioned successfully.",
  },
  bulkPartialToast: {
    id: "laneB6.bulk.partialToast",
    defaultMessage: "Onboarding finished with problems",
  },
  bulkPartialToastBody: {
    id: "laneB6.bulk.partialToastBody",
    defaultMessage:
      "{failed} of {total} tenants had a problem. See the outcomes table for details.",
  },
  bulkPhaseFailToast: {
    id: "laneB6.bulk.phaseFailToast",
    defaultMessage: "Bulk onboarding stopped during {phase}",
  },
  bulkPhaseRemainingOne: {
    id: "laneB6.bulk.phaseRemainingOne",
    defaultMessage: "{reason} The {phase} step wasn’t attempted.",
  },
  bulkPhaseRemainingMany: {
    id: "laneB6.bulk.phaseRemainingMany",
    defaultMessage: "{reason} Steps after {phase} weren’t attempted.",
  },
  phaseSite: {
    id: "laneB6.bulk.phase.site",
    defaultMessage: "site provisioning",
  },
  phasePolicy: {
    id: "laneB6.bulk.phase.policy",
    defaultMessage: "policy template",
  },
  phaseTokens: {
    id: "laneB6.bulk.phase.tokens",
    defaultMessage: "enrolment tokens",
  },
  // individual operations
  bulkIndividual: {
    id: "laneB6.bulk.individual",
    defaultMessage: "Individual operations",
  },
  bulkIndividualSub: {
    id: "laneB6.bulk.individualSub",
    defaultMessage:
      "Run a single step across the cohort instead of the full sequence.",
  },
  bulkProvCard: {
    id: "laneB6.bulk.prov.card",
    defaultMessage: "Provision sites across cohort",
  },
  bulkTokCard: {
    id: "laneB6.bulk.tok.card",
    defaultMessage: "Issue enrolment tokens",
  },
  bulkPolCard: {
    id: "laneB6.bulk.pol.card",
    defaultMessage: "Apply policy template to cohort",
  },
  bulkProvision: {
    id: "laneB6.bulk.provision",
    defaultMessage: "Provision",
  },
  bulkProvisioning: {
    id: "laneB6.bulk.provisioning",
    defaultMessage: "Provisioning…",
  },
  bulkGenerate: { id: "laneB6.bulk.generate", defaultMessage: "Issue tokens" },
  bulkGenerating: {
    id: "laneB6.bulk.generating",
    defaultMessage: "Issuing…",
  },
  bulkApply: {
    id: "laneB6.bulk.apply",
    defaultMessage: "Apply to all tenants",
  },
  bulkApplying: { id: "laneB6.bulk.applying", defaultMessage: "Applying…" },
  bulkDone: { id: "laneB6.bulk.done", defaultMessage: "Done" },
  bulkOpFailed: {
    id: "laneB6.bulk.opFailed",
    defaultMessage: "Failed — try again",
  },
  bulkBadgeSummary: {
    id: "laneB6.bulk.badgeSummary",
    defaultMessage: "{withPolicy, select, true {Provision · Policy · Enrol} other {Provision · Enrol}}",
  },
  bulkRequestFailed: {
    id: "laneB6.bulk.requestFailed",
    defaultMessage: "The request didn’t complete.",
  },
  bulkPolicyConfirmTitle: {
    id: "laneB6.bulk.policyConfirm.title",
    defaultMessage:
      "Apply this policy to {count, plural, one {# tenant} other {# tenants}}?",
  },
  bulkPolicyConfirmBody: {
    id: "laneB6.bulk.policyConfirm.body",
    defaultMessage:
      "This replaces the network policy for every tenant owned by {msp}. Existing rules will be overwritten.",
  },

  // --- MspRbac --------------------------------------------------------------
  rbacTitle: { id: "laneB6.rbac.title", defaultMessage: "MSP roles" },
  rbacSubtitle: {
    id: "laneB6.rbac.subtitle",
    defaultMessage:
      "Partner-scoped roles that grant administrators authority across many tenants at once.",
  },
  rbacNew: { id: "laneB6.rbac.new", defaultMessage: "New MSP role" },
  rbacColRole: { id: "laneB6.rbac.col.role", defaultMessage: "Role" },
  rbacColScope: { id: "laneB6.rbac.col.scope", defaultMessage: "Reach" },
  rbacColPerms: {
    id: "laneB6.rbac.col.perms",
    defaultMessage: "What it can do",
  },
  rbacEmptyTitle: {
    id: "laneB6.rbac.empty.title",
    defaultMessage: "No MSP roles yet",
  },
  rbacEmptyBody: {
    id: "laneB6.rbac.empty.body",
    defaultMessage:
      "Create an MSP- or platform-scoped role to let partner administrators manage tenants without giving them full platform access.",
  },
  rbacScopeMspName: {
    id: "laneB6.rbac.scope.msp",
    defaultMessage: "MSP-wide",
  },
  rbacScopePlatformName: {
    id: "laneB6.rbac.scope.platform",
    defaultMessage: "Platform-wide",
  },
  rbacScopeMspHelp: {
    id: "laneB6.rbac.scope.mspHelp",
    defaultMessage: "Can act across the tenants of a single managed provider.",
  },
  rbacScopePlatformHelp: {
    id: "laneB6.rbac.scope.platformHelp",
    defaultMessage:
      "Can act across every tenant on the platform. Grant sparingly.",
  },
  rbacCreateTitle: {
    id: "laneB6.rbac.create.title",
    defaultMessage: "New MSP role",
  },
  rbacScopeForTenant: {
    id: "laneB6.rbac.scopeForTenant",
    defaultMessage: "This role is managed within {tenant}’s RBAC store.",
  },
  rbacName: { id: "laneB6.rbac.name", defaultMessage: "Role name" },
  rbacScope: { id: "laneB6.rbac.scope", defaultMessage: "Reach" },
  rbacPerms: { id: "laneB6.rbac.perms", defaultMessage: "Permissions" },
  rbacPermsHint: {
    id: "laneB6.rbac.permsHint",
    defaultMessage: "Pick what this role is allowed to do. Select at least one.",
  },
  rbacError: {
    id: "laneB6.rbac.error",
    defaultMessage: "We couldn’t create the role. Please try again.",
  },
  rbacCreatedTitle: {
    id: "laneB6.rbac.created.title",
    defaultMessage: "Role created",
  },
  rbacCreatedBody: {
    id: "laneB6.rbac.created.body",
    defaultMessage: "{name} can now be assigned to partner administrators.",
  },
  // permission friendly labels
  permTenantRead: {
    id: "laneB6.perm.tenant.read",
    defaultMessage: "View tenants",
  },
  permTenantReadDesc: {
    id: "laneB6.perm.tenant.read.desc",
    defaultMessage: "See the list of tenants and their details.",
  },
  permTenantWrite: {
    id: "laneB6.perm.tenant.write",
    defaultMessage: "Edit tenants",
  },
  permTenantWriteDesc: {
    id: "laneB6.perm.tenant.write.desc",
    defaultMessage: "Create, update and suspend tenants.",
  },
  permTenantProvision: {
    id: "laneB6.perm.tenant.provision",
    defaultMessage: "Provision tenants",
  },
  permTenantProvisionDesc: {
    id: "laneB6.perm.tenant.provision.desc",
    defaultMessage: "Set up sites and issue enrolment tokens for tenants.",
  },
  permBrandingWrite: {
    id: "laneB6.perm.branding.write",
    defaultMessage: "Manage branding",
  },
  permBrandingWriteDesc: {
    id: "laneB6.perm.branding.write.desc",
    defaultMessage: "Customise tenant white-label portals.",
  },
  permPolicyTemplateWrite: {
    id: "laneB6.perm.policy.template.write",
    defaultMessage: "Manage policy templates",
  },
  permPolicyTemplateWriteDesc: {
    id: "laneB6.perm.policy.template.write.desc",
    defaultMessage: "Create and apply reusable policy templates.",
  },
  permBillingRead: {
    id: "laneB6.perm.billing.read",
    defaultMessage: "View billing",
  },
  permBillingReadDesc: {
    id: "laneB6.perm.billing.read.desc",
    defaultMessage: "See usage and cost estimates.",
  },
  permRbacWrite: {
    id: "laneB6.perm.rbac.write",
    defaultMessage: "Manage roles",
  },
  permRbacWriteDesc: {
    id: "laneB6.perm.rbac.write.desc",
    defaultMessage: "Create roles and assign them to administrators.",
  },

  // --- MspTemplates ---------------------------------------------------------
  tplTitle: {
    id: "laneB6.tpl.title",
    defaultMessage: "Policy templates",
  },
  tplSubtitle: {
    id: "laneB6.tpl.subtitle",
    defaultMessage:
      "Reusable policy baselines you can apply to a provider’s entire tenant cohort in one click.",
  },
  tplNew: { id: "laneB6.tpl.new", defaultMessage: "New template" },
  tplEmptyTitle: {
    id: "laneB6.tpl.empty.title",
    defaultMessage: "No templates yet",
  },
  tplEmptyBody: {
    id: "laneB6.tpl.empty.body",
    defaultMessage:
      "Templates capture a policy baseline once so you can roll it out to many tenants consistently. Create your first to get started.",
  },
  tplNoDescription: {
    id: "laneB6.tpl.noDescription",
    defaultMessage: "No description yet.",
  },
  tplApply: { id: "laneB6.tpl.apply", defaultMessage: "Apply to cohort" },
  tplApplying: { id: "laneB6.tpl.applying", defaultMessage: "Applying…" },
  tplEdit: { id: "laneB6.tpl.edit", defaultMessage: "Edit" },
  tplDelete: { id: "laneB6.tpl.delete", defaultMessage: "Delete" },
  tplApplied: { id: "laneB6.tpl.applied", defaultMessage: "Applied" },
  tplNodesEdges: {
    id: "laneB6.tpl.nodesEdges",
    defaultMessage:
      "{nodes, plural, one {# node} other {# nodes}} · {edges, plural, one {# edge} other {# edges}}",
  },
  tplCreateTitle: {
    id: "laneB6.tpl.create.title",
    defaultMessage: "New policy template",
  },
  tplEditTitle: {
    id: "laneB6.tpl.edit.title",
    defaultMessage: "Edit template",
  },
  tplName: { id: "laneB6.tpl.name", defaultMessage: "Template name" },
  tplDescription: {
    id: "laneB6.tpl.description",
    defaultMessage: "Description",
  },
  tplDescriptionHelp: {
    id: "laneB6.tpl.descriptionHelp",
    defaultMessage:
      "A short, plain-language summary so teammates know when to use this template.",
  },
  tplGraph: {
    id: "laneB6.tpl.graph",
    defaultMessage: "Policy graph (JSON)",
  },
  tplGraphHelp: {
    id: "laneB6.tpl.graphHelp",
    defaultMessage:
      "The policy definition, in the same shape as the policy editor exports.",
  },
  tplErrJson: {
    id: "laneB6.tpl.err.json",
    defaultMessage:
      "The policy graph isn’t valid JSON. Check for a missing comma or bracket.",
  },
  tplErrName: {
    id: "laneB6.tpl.err.name",
    defaultMessage: "Give the template a name.",
  },
  tplErrQuota: {
    id: "laneB6.tpl.err.quota",
    defaultMessage:
      "There’s no room left to save templates in this browser. Delete one and try again.",
  },
  tplDeleteTitle: {
    id: "laneB6.tpl.delete.title",
    defaultMessage: "Delete {name}?",
  },
  tplDeleteBody: {
    id: "laneB6.tpl.delete.body",
    defaultMessage:
      "This removes the template from this browser. Tenants it was already applied to keep their policy.",
  },
  tplDeleteCta: {
    id: "laneB6.tpl.delete.cta",
    defaultMessage: "Delete template",
  },
  tplAppliedToast: {
    id: "laneB6.tpl.appliedToast",
    defaultMessage: "Template applied",
  },
  tplAppliedToastBody: {
    id: "laneB6.tpl.appliedToastBody",
    defaultMessage: "{name} was rolled out to the cohort.",
  },
  tplApplyError: {
    id: "laneB6.tpl.applyError",
    defaultMessage:
      "We couldn’t apply the template to the cohort. Please try again.",
  },
  tplApplyConfirmTitle: {
    id: "laneB6.tpl.applyConfirm.title",
    defaultMessage: "Apply {name} to the cohort?",
  },
  tplApplyConfirmBody: {
    id: "laneB6.tpl.applyConfirm.body",
    defaultMessage:
      "This replaces the network policy for every tenant owned by {msp}. Existing rules will be overwritten.",
  },
  tplApplyConfirmCta: {
    id: "laneB6.tpl.applyConfirm.cta",
    defaultMessage: "Apply to cohort",
  },
  tplSave: { id: "laneB6.tpl.save", defaultMessage: "Save template" },
});
