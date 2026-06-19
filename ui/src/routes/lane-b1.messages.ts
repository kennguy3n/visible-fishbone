// Lane B1 (Gateway console front door) message catalog.
//
// This is a lane-local catalog that lives alongside the screens it serves
// (Login, OidcCallback, Onboarding, GuidedOnboarding, Dashboard, Settings).
// It is merged on top of the shared chrome catalog by `LaneB1Intl`, so these
// keys resolve through the same react-intl provider the rest of the app uses.
//
// English is the source of truth and the react-intl fallback
// (defaultLocale="en"), so a key missing from a translated catalog renders the
// English string rather than the raw id. Translated catalogs are therefore
// typed `Partial` — completeness is desirable but never required for a correct
// build.

import { DEFAULT_LOCALE, type Locale } from "@/lib/i18n/locales";

export type LaneB1Key =
  // shared
  | "b1.common.back"
  | "b1.common.continue"
  | "b1.common.cancel"
  | "b1.common.retry"
  | "b1.common.next"
  | "b1.stepper.label"
  | "b1.stepper.status.done"
  | "b1.stepper.status.current"
  | "b1.stepper.status.todo"
  // login
  | "b1.login.brand"
  | "b1.login.subtitle"
  | "b1.login.oidc.intro"
  | "b1.login.oidc.cta"
  | "b1.login.jwt.label"
  | "b1.login.jwt.placeholder"
  | "b1.login.jwt.help"
  | "b1.login.jwt.cta"
  | "b1.login.error.empty"
  | "b1.login.error.invalid"
  | "b1.login.error.oidc"
  // oidc callback
  | "b1.oidc.loading"
  | "b1.oidc.error.title"
  | "b1.oidc.error.unusable"
  | "b1.oidc.error.generic"
  | "b1.oidc.back"
  // settings
  | "b1.settings.title"
  | "b1.settings.subtitle"
  | "b1.settings.appearance.title"
  | "b1.settings.appearance.subtitle"
  | "b1.settings.theme.legend"
  | "b1.settings.theme.light"
  | "b1.settings.theme.light.hint"
  | "b1.settings.theme.dark"
  | "b1.settings.theme.dark.hint"
  | "b1.settings.theme.system"
  | "b1.settings.theme.system.hint"
  | "b1.settings.theme.locked"
  | "b1.settings.theme.following"
  | "b1.settings.theme.value.light"
  | "b1.settings.theme.value.dark"
  | "b1.settings.language.title"
  | "b1.settings.language.subtitle"
  // guided onboarding
  | "b1.guided.title"
  | "b1.guided.subtitle"
  | "b1.guided.steps"
  | "b1.guided.step.tenant.title"
  | "b1.guided.step.tenant.desc"
  | "b1.guided.field.businessName"
  | "b1.guided.field.businessName.placeholder"
  | "b1.guided.field.plan"
  | "b1.guided.cta.create"
  | "b1.guided.toast.created.title"
  | "b1.guided.toast.created.body"
  | "b1.guided.toast.createFailed"
  | "b1.guided.step.residency.title"
  | "b1.guided.step.residency.desc"
  | "b1.guided.field.country"
  | "b1.guided.field.country.placeholder"
  | "b1.guided.residency.regime"
  | "b1.guided.step.industry.title"
  | "b1.guided.step.industry.desc"
  | "b1.guided.cta.preview"
  | "b1.guided.cta.previewing"
  | "b1.guided.toast.renderFailed"
  | "b1.guided.step.review.title"
  | "b1.guided.review.summary"
  | "b1.guided.review.composedFrom"
  | "b1.guided.review.fingerprint"
  | "b1.guided.cta.apply"
  | "b1.guided.cta.applying"
  | "b1.guided.toast.applyFailed"
  | "b1.guided.toast.applied.title"
  | "b1.guided.toast.applied.body"
  | "b1.guided.step.done.title"
  | "b1.guided.step.done.desc"
  | "b1.guided.cta.goDashboard"
  | "b1.guided.cta.fullSetup"
  // onboarding
  | "b1.onboard.title"
  | "b1.onboard.subtitle"
  | "b1.onboard.steps"
  | "b1.onboard.tenant.title"
  | "b1.onboard.tenant.intro"
  | "b1.onboard.anim.staff"
  | "b1.onboard.anim.sng"
  | "b1.onboard.anim.internet"
  | "b1.onboard.tenant.existing"
  | "b1.onboard.tenant.createInstead"
  | "b1.onboard.tenant.none"
  | "b1.onboard.newTenant.title"
  | "b1.onboard.field.businessName"
  | "b1.onboard.field.businessName.help"
  | "b1.onboard.field.businessName.placeholder"
  | "b1.onboard.field.slug"
  | "b1.onboard.field.slug.help"
  | "b1.onboard.field.slug.placeholder"
  | "b1.onboard.field.region"
  | "b1.onboard.field.region.help"
  | "b1.onboard.field.region.placeholder"
  | "b1.onboard.field.planTier"
  | "b1.onboard.tier.starter.blurb"
  | "b1.onboard.tier.professional.blurb"
  | "b1.onboard.tier.enterprise.blurb"
  | "b1.onboard.cta.createTenant"
  | "b1.onboard.cta.creating"
  | "b1.onboard.cta.continue"
  | "b1.onboard.toast.tenantCreated.title"
  | "b1.onboard.toast.tenantCreated.body"
  | "b1.onboard.toast.tenantFailed"
  | "b1.onboard.site.title"
  | "b1.onboard.site.existing"
  | "b1.onboard.field.siteName"
  | "b1.onboard.field.siteName.help"
  | "b1.onboard.field.siteName.placeholder"
  | "b1.onboard.field.siteSlug.help"
  | "b1.onboard.field.siteSlug.placeholder"
  | "b1.onboard.field.deployment"
  | "b1.onboard.field.deployment.help"
  | "b1.onboard.template.branch.blurb"
  | "b1.onboard.template.hub.blurb"
  | "b1.onboard.template.cloud_only.blurb"
  | "b1.onboard.template.home_office.blurb"
  | "b1.onboard.cta.createSite"
  | "b1.onboard.cta.creatingSite"
  | "b1.onboard.cta.skip"
  | "b1.onboard.toast.siteCreated.title"
  | "b1.onboard.toast.siteCreated.body"
  | "b1.onboard.toast.siteFailed"
  | "b1.onboard.identity.title"
  | "b1.onboard.identity.help"
  | "b1.onboard.identity.enabled"
  | "b1.onboard.identity.issuer"
  | "b1.onboard.identity.clientId"
  | "b1.onboard.identity.scopes"
  | "b1.onboard.identity.verifying"
  | "b1.onboard.identity.verifyFailed"
  | "b1.onboard.identity.discoveryFailed"
  | "b1.onboard.identity.verified"
  | "b1.onboard.identity.authorization"
  | "b1.onboard.identity.token"
  | "b1.onboard.identity.jwks"
  | "b1.onboard.identity.scimHint"
  | "b1.onboard.identity.devBadge"
  | "b1.onboard.identity.devBody"
  | "b1.onboard.identity.devNote"
  | "b1.onboard.policy.title"
  | "b1.onboard.policy.help"
  | "b1.onboard.policy.none"
  | "b1.onboard.policy.rules"
  | "b1.onboard.cta.applyContinue"
  | "b1.onboard.cta.skipForNow"
  | "b1.onboard.cta.applyingPolicy"
  | "b1.onboard.toast.protectionApplied.title"
  | "b1.onboard.toast.protectionApplied.body"
  | "b1.onboard.toast.policyFailed"
  | "b1.onboard.deploy.title"
  | "b1.onboard.deploy.intro"
  | "b1.onboard.deploy.enrolled"
  | "b1.onboard.cta.generateToken"
  | "b1.onboard.cta.generating"
  | "b1.onboard.deploy.tokenLabel"
  | "b1.onboard.cta.copy"
  | "b1.onboard.cta.copied"
  | "b1.onboard.deploy.expires"
  | "b1.onboard.deploy.instructions"
  | "b1.onboard.deploy.scanHint"
  | "b1.onboard.toast.copied.title"
  | "b1.onboard.toast.copied.body"
  | "b1.onboard.toast.copyFailed.title"
  | "b1.onboard.toast.copyFailed.body"
  | "b1.onboard.toast.tokenFailed"
  | "b1.onboard.deploy.doneTitle"
  | "b1.onboard.deploy.doneSub"
  | "b1.onboard.deploy.link.dashboard"
  | "b1.onboard.deploy.link.alerts"
  | "b1.onboard.deploy.link.policy"
  | "b1.onboard.deploy.link.devices"
  | "b1.onboard.cta.goDashboard"
  // dashboard
  | "b1.dash.title"
  | "b1.dash.subtitle.tenant"
  | "b1.dash.subtitle.default"
  | "b1.dash.banner.title"
  | "b1.dash.banner.sub"
  | "b1.dash.banner.cta"
  | "b1.dash.stat.tenants"
  | "b1.dash.stat.sites"
  | "b1.dash.stat.sites.tier"
  | "b1.dash.stat.devices"
  | "b1.dash.stat.openAlerts"
  | "b1.dash.stat.attention"
  | "b1.dash.stat.clear"
  | "b1.dash.score.title"
  | "b1.dash.score.none"
  | "b1.dash.score.composite"
  | "b1.dash.qa.title"
  | "b1.dash.qa.help"
  | "b1.dash.qa.none"
  | "b1.dash.qa.addSite.title"
  | "b1.dash.qa.addSite.desc"
  | "b1.dash.qa.addSite.cta"
  | "b1.dash.qa.enrolDevice.title"
  | "b1.dash.qa.enrolDevice.desc"
  | "b1.dash.qa.enrolDevice.cta"
  | "b1.dash.qa.critical.title"
  | "b1.dash.qa.critical.desc"
  | "b1.dash.qa.critical.cta"
  | "b1.dash.qa.usage.title"
  | "b1.dash.qa.usage.desc"
  | "b1.dash.qa.usage.cta"
  | "b1.dash.qa.weak.title"
  | "b1.dash.qa.weak.desc"
  | "b1.dash.qa.weak.cta"
  | "b1.dash.qa.review"
  | "b1.dash.cost.title"
  | "b1.dash.cost.help"
  | "b1.dash.cost.perMo"
  | "b1.dash.cost.basis"
  | "b1.dash.cost.enrol"
  | "b1.dash.cost.trend.up"
  | "b1.dash.cost.trend.down"
  | "b1.dash.cost.trend.stable"
  | "b1.dash.coverage.title"
  | "b1.dash.coverage.help"
  | "b1.dash.coverage.none"
  | "b1.dash.coverage.overall"
  | "b1.dash.coverage.policies"
  | "b1.dash.threat.title"
  | "b1.dash.threat.help"
  | "b1.dash.activity.title"
  | "b1.dash.activity.help"
  | "b1.dash.activity.clear.title"
  | "b1.dash.activity.clear.desc"
  | "b1.dash.alerts.title"
  | "b1.dash.alerts.none.title"
  | "b1.dash.alerts.none.desc"
  | "b1.dash.alerts.viewAll"
  | "b1.dash.col.severity"
  | "b1.dash.col.kind"
  | "b1.dash.col.dimension"
  | "b1.dash.col.zscore"
  | "b1.dash.col.state"
  | "b1.dash.col.when";

type Catalog = Record<LaneB1Key, string>;
type PartialCatalog = Partial<Catalog>;

const en: Catalog = {
  "b1.common.back": "Back",
  "b1.common.continue": "Continue",
  "b1.common.cancel": "Cancel",
  "b1.common.retry": "Try again",
  "b1.common.next": "Next",
  "b1.stepper.label": "Setup progress",
  "b1.stepper.status.done": "Completed",
  "b1.stepper.status.current": "Current step",
  "b1.stepper.status.todo": "Upcoming",

  "b1.login.brand": "ShieldNet Gateway",
  "b1.login.subtitle": "Operator console",
  "b1.login.oidc.intro":
    "Sign in with your organization's single sign-on to continue.",
  "b1.login.oidc.cta": "Continue with single sign-on",
  "b1.login.jwt.label": "Developer access token",
  "b1.login.jwt.placeholder": "Paste your token (starts with eyJ…)",
  "b1.login.jwt.help":
    "Paste the operator token your administrator issued. In production this screen uses your organization's single sign-on instead.",
  "b1.login.jwt.cta": "Sign in",
  "b1.login.error.empty": "Enter your access token to continue.",
  "b1.login.error.invalid":
    "That token isn't valid or has expired. Paste a current one to continue.",
  "b1.login.error.oidc": "We couldn't start single sign-on. Please try again.",

  "b1.oidc.loading": "Signing you in…",
  "b1.oidc.error.title": "We couldn't finish signing you in",
  "b1.oidc.error.unusable":
    "Your identity provider returned a sign-in token this console can't read. ShieldNet needs a standard, unexpired token — ask your administrator to check the single sign-on token format and audience.",
  "b1.oidc.error.generic":
    "Something interrupted sign-in before it finished. Please head back and try again.",
  "b1.oidc.back": "Back to sign in",

  "b1.settings.title": "Settings",
  "b1.settings.subtitle": "Preferences for this console, saved on this device.",
  "b1.settings.appearance.title": "Appearance",
  "b1.settings.appearance.subtitle":
    "Choose how the console looks. Your choice is saved on this device.",
  "b1.settings.theme.legend": "Theme",
  "b1.settings.theme.light": "Light",
  "b1.settings.theme.light.hint": "Always use the light theme.",
  "b1.settings.theme.dark": "Dark",
  "b1.settings.theme.dark.hint": "Always use the dark theme.",
  "b1.settings.theme.system": "Match system",
  "b1.settings.theme.system.hint": "Follow your device's appearance setting.",
  "b1.settings.theme.locked": "Theme set to {theme}.",
  "b1.settings.theme.following": "Following your device — currently {theme}.",
  "b1.settings.theme.value.light": "light",
  "b1.settings.theme.value.dark": "dark",
  "b1.settings.language.title": "Language",
  "b1.settings.language.subtitle":
    "Choose the language for this console. Your choice is saved on this device.",

  "b1.guided.title": "Guided setup",
  "b1.guided.subtitle":
    "Create your workspace and turn on its first protection — in five quick steps.",
  "b1.guided.steps": "Tenant|Data location|Industry|First policy|Done",
  "b1.guided.step.tenant.title": "Create the tenant",
  "b1.guided.step.tenant.desc":
    "A tenant is the private workspace that keeps one organization's people, devices and policies separate from everyone else's.",
  "b1.guided.field.businessName": "Business name",
  "b1.guided.field.businessName.placeholder": "Acme Ltd",
  "b1.guided.field.plan": "Plan",
  "b1.guided.cta.create": "Create tenant",
  "b1.guided.toast.created.title": "Tenant created",
  "b1.guided.toast.created.body": "{name} is ready to configure.",
  "b1.guided.toast.createFailed": "We couldn't create the tenant",
  "b1.guided.step.residency.title": "Where does {name} operate?",
  "b1.guided.step.residency.desc":
    "This sets where your data is stored and which compliance rules the first policy applies.",
  "b1.guided.field.country": "Country / data location",
  "b1.guided.field.country.placeholder": "Choose a country…",
  "b1.guided.residency.regime": "Rules applied: <badge>{regime}</badge>",
  "b1.guided.step.industry.title": "What does the business do?",
  "b1.guided.step.industry.desc":
    "Your industry sets sensible defaults for acceptable use and the kinds of sensitive data we watch for.",
  "b1.guided.cta.preview": "Preview protection",
  "b1.guided.cta.previewing": "Preparing…",
  "b1.guided.toast.renderFailed": "We couldn't prepare the baseline",
  "b1.guided.step.review.title": "Review your first protection",
  "b1.guided.review.summary": "{industry} · {country} · <badge>{regime}</badge>",
  "b1.guided.review.composedFrom": "Built from",
  "b1.guided.review.fingerprint": "Policy fingerprint",
  "b1.guided.cta.apply": "Turn on protection",
  "b1.guided.cta.applying": "Turning on…",
  "b1.guided.toast.applyFailed": "We couldn't turn on protection",
  "b1.guided.toast.applied.title": "Protection is on",
  "b1.guided.toast.applied.body": "{name} is now protected.",
  "b1.guided.step.done.title": "You're all set",
  "b1.guided.step.done.desc":
    "{name} has its first protection turned on. Next, add locations, enrol devices, or fine-tune the policy.",
  "b1.guided.cta.goDashboard": "Go to dashboard",
  "b1.guided.cta.fullSetup": "Continue full setup",

  "b1.onboard.title": "Get protected",
  "b1.onboard.subtitle":
    "A short, five-step setup. Leave any time and pick up where you left off.",
  "b1.onboard.steps": "Tenant|Site|Sign-in|Protection|Devices",
  "b1.onboard.tenant.title": "Choose the tenant to set up",
  "b1.onboard.tenant.intro":
    "ShieldNet protects your business's internet traffic — blocking threats, stopping data leaks and keeping remote staff safe — without needing an IT team to run it. Everything in this setup applies to the tenant you pick here.",
  "b1.onboard.anim.staff": "Staff",
  "b1.onboard.anim.sng": "ShieldNet",
  "b1.onboard.anim.internet": "Internet",
  "b1.onboard.tenant.existing": "Existing tenants",
  "b1.onboard.tenant.createInstead": "Create a new tenant instead",
  "b1.onboard.tenant.none":
    "You don't have any tenants yet. Create your first one to begin.",
  "b1.onboard.newTenant.title": "New tenant",
  "b1.onboard.field.businessName": "Business name",
  "b1.onboard.field.businessName.help":
    "The organization this tenant represents, e.g. \"Acme Ltd\". Shown throughout the console.",
  "b1.onboard.field.businessName.placeholder": "e.g. Acme Ltd",
  "b1.onboard.field.slug": "Short name (optional)",
  "b1.onboard.field.slug.help":
    "A short, lowercase identifier used in web addresses and configs. Leave blank and we'll generate one from the name.",
  "b1.onboard.field.slug.placeholder": "acme",
  "b1.onboard.field.region": "Region (optional)",
  "b1.onboard.field.region.help":
    "Where this tenant's data is processed. Leave blank to use the platform default.",
  "b1.onboard.field.region.placeholder": "e.g. eu-west-1",
  "b1.onboard.field.planTier": "Plan",
  "b1.onboard.tier.starter.blurb":
    "Small teams getting started — core protection, sensible defaults.",
  "b1.onboard.tier.professional.blurb":
    "Growing businesses — full policy control and integrations.",
  "b1.onboard.tier.enterprise.blurb":
    "Large or regulated organizations — advanced controls and scale.",
  "b1.onboard.cta.createTenant": "Create tenant",
  "b1.onboard.cta.creating": "Creating…",
  "b1.onboard.cta.continue": "Continue",
  "b1.onboard.toast.tenantCreated.title": "Tenant created",
  "b1.onboard.toast.tenantCreated.body": "{name} is now active.",
  "b1.onboard.toast.tenantFailed": "We couldn't create the tenant",
  "b1.onboard.site.title": "Add your first site",
  "b1.onboard.site.existing":
    "You already have {count, plural, one {# site} other {# sites}}. Add another or continue.",
  "b1.onboard.field.siteName": "Site name",
  "b1.onboard.field.siteName.help":
    "A friendly name for this location, e.g. \"London HQ\" or \"Warehouse\". It's just for you to recognize it.",
  "b1.onboard.field.siteName.placeholder": "e.g. London HQ",
  "b1.onboard.field.siteSlug.help":
    "A short, lowercase identifier used in web addresses and configs. Leave blank and we'll generate one from the name.",
  "b1.onboard.field.siteSlug.placeholder": "london-hq",
  "b1.onboard.field.deployment": "Deployment type",
  "b1.onboard.field.deployment.help":
    "How this location connects. Most offices are a \"Branch\". Choose \"Cloud only\" if there's no physical network to protect.",
  "b1.onboard.template.branch.blurb":
    "A physical office with its own network — on-site staff share one internet connection.",
  "b1.onboard.template.hub.blurb":
    "A central location that other sites connect back through.",
  "b1.onboard.template.cloud_only.blurb":
    "No hardware — protect cloud apps and remote staff only.",
  "b1.onboard.template.home_office.blurb":
    "A single remote worker, set up from their device.",
  "b1.onboard.cta.createSite": "Create site",
  "b1.onboard.cta.creatingSite": "Creating…",
  "b1.onboard.cta.skip": "Skip",
  "b1.onboard.toast.siteCreated.title": "Site created",
  "b1.onboard.toast.siteCreated.body": "{name} is now connected.",
  "b1.onboard.toast.siteFailed": "We couldn't create the site",
  "b1.onboard.identity.title": "Connect your identity provider",
  "b1.onboard.identity.help":
    "ShieldNet hands sign-in to your identity provider (Okta, Microsoft Entra ID, Google Workspace and others) and can sync users and groups automatically. Single sign-on is set up when the console is deployed; here we check it's live.",
  "b1.onboard.identity.enabled": "Single sign-on enabled",
  "b1.onboard.identity.issuer": "Provider address",
  "b1.onboard.identity.clientId": "Client ID",
  "b1.onboard.identity.scopes": "Scopes",
  "b1.onboard.identity.verifying": "Checking your provider…",
  "b1.onboard.identity.verifyFailed":
    "We couldn't reach your identity provider's settings: {detail}. Check the address and that it's reachable from this browser.",
  "b1.onboard.identity.discoveryFailed": "the connection didn't complete",
  "b1.onboard.identity.verified":
    "Connection verified — single sign-on is ready.",
  "b1.onboard.identity.authorization": "Sign-in address",
  "b1.onboard.identity.token": "Token address",
  "b1.onboard.identity.jwks": "Signing keys",
  "b1.onboard.identity.scimHint":
    "To add users and groups automatically, set up <scim>directory sync</scim>. Full sign-in details live on the <idp>identity provider</idp> page.",
  "b1.onboard.identity.devBadge": "Developer sign-in",
  "b1.onboard.identity.devBody":
    "This console is in developer sign-in mode, where it accepts a pasted operator token. To hand sign-in to your identity provider, switch on single sign-on in the deploy-time settings, then re-run this step to check the connection.",
  "b1.onboard.identity.devNote":
    "You can still continue and finish setup — single sign-on can be turned on later without redoing the rest.",
  "b1.onboard.policy.title": "Apply a protection template",
  "b1.onboard.policy.help":
    "These are ready-made data-protection policies. They decide what sensitive information — card numbers, ID numbers, secrets — ShieldNet watches for and blocks. You can fine-tune everything later.",
  "b1.onboard.policy.none":
    "No protection templates are published for this tenant yet. You can skip this step and set up data protection later.",
  "b1.onboard.policy.rules": "{count, plural, one {# rule} other {# rules}}",
  "b1.onboard.cta.applyContinue": "Apply & continue",
  "b1.onboard.cta.skipForNow": "Skip for now",
  "b1.onboard.cta.applyingPolicy": "Applying…",
  "b1.onboard.toast.protectionApplied.title": "Protection applied",
  "b1.onboard.toast.protectionApplied.body":
    "Your data-protection policy is now active.",
  "b1.onboard.toast.policyFailed": "We couldn't apply the template",
  "b1.onboard.deploy.title": "Deploy & enrol your first device",
  "b1.onboard.deploy.intro":
    "A claim token lets a device join this tenant securely. Generate one, then install the ShieldNet agent on the device and paste the token (or scan the QR code) when it asks.",
  "b1.onboard.deploy.enrolled":
    "{count, plural, one {# device} other {# devices}} already enrolled.",
  "b1.onboard.cta.generateToken": "Generate claim token",
  "b1.onboard.cta.generating": "Generating…",
  "b1.onboard.deploy.tokenLabel": "Claim token (shown once)",
  "b1.onboard.cta.copy": "Copy",
  "b1.onboard.cta.copied": "Copied",
  "b1.onboard.deploy.expires":
    "Expires {date}. Generate a fresh token if it lapses.",
  "b1.onboard.deploy.instructions":
    "On the device, install the ShieldNet agent and choose Enrol with token, then paste the value above. Mobile agents can scan the QR code instead.",
  "b1.onboard.deploy.scanHint": "Scan with the mobile agent",
  "b1.onboard.toast.copied.title": "Copied",
  "b1.onboard.toast.copied.body": "Claim token copied to your clipboard.",
  "b1.onboard.toast.copyFailed.title": "Copy failed",
  "b1.onboard.toast.copyFailed.body": "Select the token and copy it manually.",
  "b1.onboard.toast.tokenFailed": "We couldn't generate a token",
  "b1.onboard.deploy.doneTitle": "You're protected",
  "b1.onboard.deploy.doneSub":
    "ShieldNet is now watching this tenant's traffic. Here's where to go next:",
  "b1.onboard.deploy.link.dashboard":
    "<link>Dashboard</link> — your security at a glance.",
  "b1.onboard.deploy.link.alerts":
    "<link>Alerts</link> — threats as they're detected.",
  "b1.onboard.deploy.link.policy":
    "<link>Policy</link> — review and fine-tune what's allowed.",
  "b1.onboard.deploy.link.devices": "<link>Devices</link> — enrol more devices any time.",
  "b1.onboard.cta.goDashboard": "Go to dashboard",

  "b1.dash.title": "Dashboard",
  "b1.dash.subtitle.tenant": "Security for {name}",
  "b1.dash.subtitle.default": "Your security at a glance",
  "b1.dash.banner.title": "Let's get you protected",
  "b1.dash.banner.sub":
    "This tenant has no sites or devices yet. The guided setup turns on protection in about five minutes.",
  "b1.dash.banner.cta": "Get started",
  "b1.dash.stat.tenants": "Tenants",
  "b1.dash.stat.sites": "Sites",
  "b1.dash.stat.sites.tier": "Plan: {tier}",
  "b1.dash.stat.devices": "Devices",
  "b1.dash.stat.openAlerts": "Open alerts",
  "b1.dash.stat.attention": "needs attention",
  "b1.dash.stat.clear": "all clear",
  "b1.dash.score.title": "Security score",
  "b1.dash.score.none":
    "We haven't recorded a health check for this tenant yet.",
  "b1.dash.score.composite":
    "Based on {count, plural, =0 {your operational checks} one {# operational check} other {# operational checks}}.",
  "b1.dash.qa.title": "What to do next",
  "b1.dash.qa.help":
    "The most useful next steps, drawn from your live security — open alerts, weak areas, setup gaps and recommendations.",
  "b1.dash.qa.none": "You're all caught up — nothing needs your attention right now.",
  "b1.dash.qa.addSite.title": "Add your first site",
  "b1.dash.qa.addSite.desc":
    "Connect a location so traffic starts flowing through the gateway.",
  "b1.dash.qa.addSite.cta": "Set up",
  "b1.dash.qa.enrolDevice.title": "Enrol your first device",
  "b1.dash.qa.enrolDevice.desc":
    "Install the agent and claim a device to begin protection.",
  "b1.dash.qa.enrolDevice.cta": "Enrol",
  "b1.dash.qa.critical.title":
    "{count, plural, one {Resolve # critical alert} other {Resolve # critical alerts}}",
  "b1.dash.qa.critical.desc": "Critical anomalies are open and need a look.",
  "b1.dash.qa.critical.cta": "Review",
  "b1.dash.qa.usage.title": "Usage over a hard limit",
  "b1.dash.qa.usage.desc": "{meters} went over its cap.",
  "b1.dash.qa.usage.cta": "Open",
  "b1.dash.qa.weak.title": "Improve {label} ({score}/100)",
  "b1.dash.qa.weak.desc":
    "This area is pulling your security score down.",
  "b1.dash.qa.weak.cta": "Tune",
  "b1.dash.qa.review": "Review",
  "b1.dash.cost.title": "Estimated monthly cost",
  "b1.dash.cost.help":
    "Counts each of your {count, plural, one {# enrolled device} other {# enrolled devices}} as one seat at the ${price}/seat list price (published range $5–12). If a person uses more than one device this over-estimates — connect billing for exact figures.",
  "b1.dash.cost.perMo": "/ mo",
  "b1.dash.cost.basis":
    "{count, plural, one {# device} other {# devices}} × ${price}/seat per month",
  "b1.dash.cost.enrol": "Enrol devices to project a cost.",
  "b1.dash.cost.trend.up": "Usage trending up",
  "b1.dash.cost.trend.down": "Usage trending down",
  "b1.dash.cost.trend.stable": "Usage stable",
  "b1.dash.coverage.title": "Policy coverage",
  "b1.dash.coverage.help":
    "How much of your operations is actively governed by policy. Area scores come from the latest health check; overall coverage comes from the security report.",
  "b1.dash.coverage.none":
    "Coverage appears once a security report or health check exists.",
  "b1.dash.coverage.overall": "Overall coverage",
  "b1.dash.coverage.policies": "· {active}/{total} policies active",
  "b1.dash.threat.title": "Threat activity by region",
  "b1.dash.threat.help":
    "Plots this tenant's region, sized by currently-open threats. Per-origin location isn't available, so this reflects where your protected traffic is served from.",
  "b1.dash.activity.title": "Security activity (last 24 hours)",
  "b1.dash.activity.help":
    "Hourly count of detected anomalies over the last 24 hours, grouped by severity. Drawn from the live alert stream.",
  "b1.dash.activity.clear.title": "All clear",
  "b1.dash.activity.clear.desc": "No anomalies detected in the last 24 hours.",
  "b1.dash.alerts.title": "Recent alerts",
  "b1.dash.alerts.none.title": "No alerts",
  "b1.dash.alerts.none.desc": "Nothing needs your attention right now.",
  "b1.dash.alerts.viewAll": "View all alerts",
  "b1.dash.col.severity": "Severity",
  "b1.dash.col.kind": "Kind",
  "b1.dash.col.dimension": "Area",
  "b1.dash.col.zscore": "Z-score",
  "b1.dash.col.state": "State",
  "b1.dash.col.when": "When",
};

const zhHans: PartialCatalog = {
  "b1.common.back": "返回",
  "b1.common.continue": "继续",
  "b1.common.cancel": "取消",
  "b1.common.retry": "重试",
  "b1.common.next": "下一步",
  "b1.stepper.label": "设置进度",
  "b1.stepper.status.done": "已完成",
  "b1.stepper.status.current": "当前步骤",
  "b1.stepper.status.todo": "待进行",
  "b1.login.subtitle": "运营控制台",
  "b1.login.oidc.intro": "使用贵组织的单点登录继续。",
  "b1.login.oidc.cta": "使用单点登录继续",
  "b1.login.jwt.label": "开发者访问令牌",
  "b1.login.jwt.placeholder": "粘贴您的令牌（以 eyJ… 开头）",
  "b1.login.jwt.help":
    "粘贴管理员为您签发的运营令牌。在生产环境中，此界面将改用贵组织的单点登录。",
  "b1.login.jwt.cta": "登录",
  "b1.login.error.empty": "请输入访问令牌以继续。",
  "b1.login.error.invalid": "该令牌无效或已过期。请粘贴一个有效的令牌以继续。",
  "b1.login.error.oidc": "无法启动单点登录，请重试。",
  "b1.oidc.loading": "正在为您登录…",
  "b1.oidc.error.title": "无法完成登录",
  "b1.oidc.error.unusable":
    "您的身份提供商返回了本控制台无法读取的登录令牌。ShieldNet 需要标准且未过期的令牌——请让管理员检查单点登录的令牌格式和受众。",
  "b1.oidc.error.generic": "登录在完成前被中断。请返回重试。",
  "b1.oidc.back": "返回登录",
  "b1.settings.title": "设置",
  "b1.settings.subtitle": "本控制台的偏好设置，保存在此设备上。",
  "b1.settings.appearance.title": "外观",
  "b1.settings.appearance.subtitle": "选择控制台的外观。您的选择将保存在此设备上。",
  "b1.settings.theme.legend": "主题",
  "b1.settings.theme.light": "浅色",
  "b1.settings.theme.light.hint": "始终使用浅色主题。",
  "b1.settings.theme.dark": "深色",
  "b1.settings.theme.dark.hint": "始终使用深色主题。",
  "b1.settings.theme.system": "跟随系统",
  "b1.settings.theme.system.hint": "跟随设备的外观设置。",
  "b1.settings.theme.locked": "主题已设为{theme}。",
  "b1.settings.theme.following": "正在跟随您的设备——当前为{theme}。",
  "b1.settings.theme.value.light": "浅色",
  "b1.settings.theme.value.dark": "深色",
  "b1.settings.language.title": "语言",
  "b1.settings.language.subtitle": "选择本控制台的语言。您的选择将保存在此设备上。",
  "b1.guided.title": "引导式设置",
  "b1.guided.subtitle": "创建您的租户并开启首项防护——仅需五个快捷步骤。",
  "b1.guided.steps": "租户|数据所在地|行业|首个策略|完成",
  "b1.guided.step.tenant.title": "创建租户",
  "b1.guided.step.tenant.desc":
    "租户是一个私有工作区，将一个组织的人员、设备和策略与其他组织隔离开来。",
  "b1.guided.field.businessName": "企业名称",
  "b1.guided.field.businessName.placeholder": "Acme 有限公司",
  "b1.guided.field.plan": "套餐",
  "b1.guided.cta.create": "创建租户",
  "b1.guided.toast.created.title": "租户已创建",
  "b1.guided.toast.created.body": "{name} 已可配置。",
  "b1.guided.toast.createFailed": "无法创建租户",
  "b1.guided.step.residency.title": "{name} 在哪里运营？",
  "b1.guided.step.residency.desc": "这将决定您的数据存储位置以及首个策略所适用的合规规则。",
  "b1.guided.field.country": "国家/数据所在地",
  "b1.guided.field.country.placeholder": "选择国家…",
  "b1.guided.residency.regime": "适用规则：<badge>{regime}</badge>",
  "b1.guided.step.industry.title": "该企业从事什么业务？",
  "b1.guided.step.industry.desc": "您的行业将为可接受使用以及我们监控的敏感数据类型设定合理默认值。",
  "b1.guided.cta.preview": "预览防护",
  "b1.guided.cta.previewing": "准备中…",
  "b1.guided.toast.renderFailed": "无法准备基线",
  "b1.guided.step.review.title": "查看您的首项防护",
  "b1.guided.review.summary": "{industry} · {country} · <badge>{regime}</badge>",
  "b1.guided.review.composedFrom": "构建自",
  "b1.guided.review.fingerprint": "策略指纹",
  "b1.guided.cta.apply": "开启防护",
  "b1.guided.cta.applying": "正在开启…",
  "b1.guided.toast.applyFailed": "无法开启防护",
  "b1.guided.toast.applied.title": "防护已开启",
  "b1.guided.toast.applied.body": "{name} 现已受到保护。",
  "b1.guided.step.done.title": "全部完成",
  "b1.guided.step.done.desc":
    "{name} 已开启首项防护。接下来可添加地点、注册设备或微调策略。",
  "b1.guided.cta.goDashboard": "前往仪表板",
  "b1.guided.cta.fullSetup": "继续完整设置",
  "b1.onboard.title": "开启防护",
  "b1.onboard.subtitle": "简短的五步设置。可随时离开，稍后从中断处继续。",
  "b1.onboard.steps": "租户|站点|登录|防护|设备",
  "b1.onboard.tenant.title": "选择要设置的租户",
  "b1.onboard.tenant.intro":
    "ShieldNet 保护您企业的互联网流量——拦截威胁、防止数据泄露并保障远程员工安全——无需 IT 团队运维。本设置中的所有内容都将应用于您在此选择的租户。",
  "b1.onboard.anim.staff": "员工",
  "b1.onboard.anim.sng": "ShieldNet",
  "b1.onboard.anim.internet": "互联网",
  "b1.onboard.tenant.existing": "现有租户",
  "b1.onboard.tenant.createInstead": "改为创建新租户",
  "b1.onboard.tenant.none": "您还没有任何租户。创建第一个以开始。",
  "b1.onboard.newTenant.title": "新建租户",
  "b1.onboard.field.businessName": "企业名称",
  "b1.onboard.field.businessName.help":
    "此租户所代表的组织，例如“Acme 有限公司”。将显示在整个控制台中。",
  "b1.onboard.field.businessName.placeholder": "例如 Acme 有限公司",
  "b1.onboard.field.slug": "短名称（可选）",
  "b1.onboard.field.slug.help":
    "用于网址和配置的小写短标识符。留空则我们会根据名称自动生成。",
  "b1.onboard.field.slug.placeholder": "acme",
  "b1.onboard.field.region": "区域（可选）",
  "b1.onboard.field.region.help": "此租户数据的处理位置。留空则使用平台默认值。",
  "b1.onboard.field.region.placeholder": "例如 eu-west-1",
  "b1.onboard.field.planTier": "套餐",
  "b1.onboard.tier.starter.blurb": "适合刚起步的小团队——核心防护，合理默认。",
  "b1.onboard.tier.professional.blurb": "成长型企业——完整策略控制与集成。",
  "b1.onboard.tier.enterprise.blurb": "大型或受监管组织——高级控制与规模化。",
  "b1.onboard.cta.createTenant": "创建租户",
  "b1.onboard.cta.creating": "创建中…",
  "b1.onboard.cta.continue": "继续",
  "b1.onboard.toast.tenantCreated.title": "租户已创建",
  "b1.onboard.toast.tenantCreated.body": "{name} 现已激活。",
  "b1.onboard.toast.tenantFailed": "无法创建租户",
  "b1.onboard.site.title": "添加您的第一个站点",
  "b1.onboard.site.existing": "您已有 {count} 个站点。可再添加或继续。",
  "b1.onboard.field.siteName": "站点名称",
  "b1.onboard.field.siteName.help":
    "此地点的易记名称，例如“伦敦总部”或“仓库”。仅供您识别。",
  "b1.onboard.field.siteName.placeholder": "例如 伦敦总部",
  "b1.onboard.field.siteSlug.help":
    "用于网址和配置的小写短标识符。留空则我们会根据名称自动生成。",
  "b1.onboard.field.siteSlug.placeholder": "london-hq",
  "b1.onboard.field.deployment": "部署类型",
  "b1.onboard.field.deployment.help":
    "此地点的连接方式。大多数办公室选择“分支”。若无需保护的物理网络，请选择“仅云端”。",
  "b1.onboard.template.branch.blurb": "拥有自有网络的实体办公室——现场员工共享一条互联网出口。",
  "b1.onboard.template.hub.blurb": "其他站点回连所经的中心位置。",
  "b1.onboard.template.cloud_only.blurb": "无硬件——仅保护云应用和远程员工。",
  "b1.onboard.template.home_office.blurb": "单个远程员工，从其设备上完成设置。",
  "b1.onboard.cta.createSite": "创建站点",
  "b1.onboard.cta.creatingSite": "创建中…",
  "b1.onboard.cta.skip": "跳过",
  "b1.onboard.toast.siteCreated.title": "站点已创建",
  "b1.onboard.toast.siteCreated.body": "{name} 现已连接。",
  "b1.onboard.toast.siteFailed": "无法创建站点",
  "b1.onboard.identity.title": "连接您的身份提供商",
  "b1.onboard.identity.help":
    "ShieldNet 将登录交给您的身份提供商（Okta、Microsoft Entra ID、Google Workspace 等），并可自动同步用户和组。单点登录在控制台部署时配置；此处我们检查其是否生效。",
  "b1.onboard.identity.enabled": "已启用单点登录",
  "b1.onboard.identity.issuer": "提供商地址",
  "b1.onboard.identity.clientId": "客户端 ID",
  "b1.onboard.identity.scopes": "范围",
  "b1.onboard.identity.verifying": "正在检查您的提供商…",
  "b1.onboard.identity.verifyFailed":
    "无法访问您身份提供商的设置：{detail}。请检查地址以及浏览器能否访问。",
  "b1.onboard.identity.discoveryFailed": "连接未完成",
  "b1.onboard.identity.verified": "连接已验证——单点登录已就绪。",
  "b1.onboard.identity.authorization": "登录地址",
  "b1.onboard.identity.token": "令牌地址",
  "b1.onboard.identity.jwks": "签名密钥",
  "b1.onboard.identity.scimHint":
    "要自动添加用户和组，请配置<scim>目录同步</scim>。完整登录详情见<idp>身份提供商</idp>页面。",
  "b1.onboard.identity.devBadge": "开发者登录",
  "b1.onboard.identity.devBody":
    "本控制台处于开发者登录模式，接受粘贴的运营令牌。要将登录交给您的身份提供商，请在部署设置中开启单点登录，然后重新执行此步骤以检查连接。",
  "b1.onboard.identity.devNote":
    "您仍可继续并完成设置——单点登录可稍后开启，无需重做其余步骤。",
  "b1.onboard.policy.title": "应用防护模板",
  "b1.onboard.policy.help":
    "这些是现成的数据保护策略。它们决定 ShieldNet 监控并拦截哪些敏感信息——卡号、证件号、密钥。之后均可微调。",
  "b1.onboard.policy.none": "此租户尚未发布防护模板。您可跳过此步骤，稍后再设置数据保护。",
  "b1.onboard.policy.rules": "{count} 条规则",
  "b1.onboard.cta.applyContinue": "应用并继续",
  "b1.onboard.cta.skipForNow": "暂时跳过",
  "b1.onboard.cta.applyingPolicy": "应用中…",
  "b1.onboard.toast.protectionApplied.title": "已应用防护",
  "b1.onboard.toast.protectionApplied.body": "您的数据保护策略现已生效。",
  "b1.onboard.toast.policyFailed": "无法应用模板",
  "b1.onboard.deploy.title": "部署并注册您的第一台设备",
  "b1.onboard.deploy.intro":
    "认领令牌可让设备安全加入此租户。生成一个，然后在设备上安装 ShieldNet 代理，并在提示时粘贴令牌（或扫描二维码）。",
  "b1.onboard.deploy.enrolled": "已注册 {count} 台设备。",
  "b1.onboard.cta.generateToken": "生成认领令牌",
  "b1.onboard.cta.generating": "生成中…",
  "b1.onboard.deploy.tokenLabel": "认领令牌（仅显示一次）",
  "b1.onboard.cta.copy": "复制",
  "b1.onboard.cta.copied": "已复制",
  "b1.onboard.deploy.expires": "{date} 过期。若失效请生成新令牌。",
  "b1.onboard.deploy.instructions":
    "在设备上安装 ShieldNet 代理并选择“使用令牌注册”，然后粘贴上方的值。移动代理可改为扫描二维码。",
  "b1.onboard.deploy.scanHint": "用移动代理扫描",
  "b1.onboard.toast.copied.title": "已复制",
  "b1.onboard.toast.copied.body": "认领令牌已复制到剪贴板。",
  "b1.onboard.toast.copyFailed.title": "复制失败",
  "b1.onboard.toast.copyFailed.body": "请选中令牌并手动复制。",
  "b1.onboard.toast.tokenFailed": "无法生成令牌",
  "b1.onboard.deploy.doneTitle": "您已受到保护",
  "b1.onboard.deploy.doneSub": "ShieldNet 现已监控此租户的流量。接下来可前往：",
  "b1.onboard.deploy.link.dashboard": "<link>仪表板</link>——一目了然地查看安全状况。",
  "b1.onboard.deploy.link.alerts": "<link>告警</link>——实时检测到的威胁。",
  "b1.onboard.deploy.link.policy": "<link>策略</link>——查看并微调允许的内容。",
  "b1.onboard.deploy.link.devices": "<link>设备</link>——随时注册更多设备。",
  "b1.onboard.cta.goDashboard": "前往仪表板",
  "b1.dash.title": "仪表板",
  "b1.dash.subtitle.tenant": "{name} 的安全状况",
  "b1.dash.subtitle.default": "一目了然的安全概览",
  "b1.dash.banner.title": "让我们为您开启防护",
  "b1.dash.banner.sub": "此租户尚无站点或设备。引导式设置约五分钟即可开启防护。",
  "b1.dash.banner.cta": "开始",
  "b1.dash.stat.tenants": "租户",
  "b1.dash.stat.sites": "站点",
  "b1.dash.stat.sites.tier": "套餐：{tier}",
  "b1.dash.stat.devices": "设备",
  "b1.dash.stat.openAlerts": "未处理告警",
  "b1.dash.stat.attention": "需要关注",
  "b1.dash.stat.clear": "一切正常",
  "b1.dash.score.title": "安全评分",
  "b1.dash.score.none": "我们尚未记录此租户的健康检查。",
  "b1.dash.score.composite": "基于{count, plural, =0 {您的运营检查} other {#项运营检查}}。",
  "b1.dash.qa.title": "下一步该做什么",
  "b1.dash.qa.help":
    "最有用的后续步骤，来自您的实时安全状况——未处理告警、薄弱环节、设置缺口和建议。",
  "b1.dash.qa.none": "您已全部处理完毕——目前无需关注任何事项。",
  "b1.dash.qa.addSite.title": "添加您的第一个站点",
  "b1.dash.qa.addSite.desc": "连接一个地点，让流量开始经过网关。",
  "b1.dash.qa.addSite.cta": "设置",
  "b1.dash.qa.enrolDevice.title": "注册您的第一台设备",
  "b1.dash.qa.enrolDevice.desc": "安装代理并认领设备以开始防护。",
  "b1.dash.qa.enrolDevice.cta": "注册",
  "b1.dash.qa.critical.title": "处理 {count} 条严重告警",
  "b1.dash.qa.critical.desc": "有严重异常未处理，需要查看。",
  "b1.dash.qa.critical.cta": "查看",
  "b1.dash.qa.usage.title": "用量超出硬性上限",
  "b1.dash.qa.usage.desc": "{meters} 已超出其上限。",
  "b1.dash.qa.usage.cta": "打开",
  "b1.dash.qa.weak.title": "改进 {label}（{score}/100）",
  "b1.dash.qa.weak.desc": "此环节正在拉低您的安全评分。",
  "b1.dash.qa.weak.cta": "调优",
  "b1.dash.qa.review": "查看",
  "b1.dash.cost.title": "预计每月费用",
  "b1.dash.cost.help":
    "将您的 {count} 台已注册设备各计为一个席位，按 ${price}/席位的标价计算（公布区间 $5–12）。若一人使用多台设备则会高估——连接计费以获取精确数字。",
  "b1.dash.cost.perMo": "/ 月",
  "b1.dash.cost.basis": "{count} 台设备 × ${price}/席位/月",
  "b1.dash.cost.enrol": "注册设备以估算费用。",
  "b1.dash.cost.trend.up": "用量上升",
  "b1.dash.cost.trend.down": "用量下降",
  "b1.dash.cost.trend.stable": "用量平稳",
  "b1.dash.coverage.title": "策略覆盖率",
  "b1.dash.coverage.help":
    "您的运营有多少受策略主动管控。各环节评分来自最新健康检查；总体覆盖率来自安全报告。",
  "b1.dash.coverage.none": "覆盖率会在出现安全报告或健康检查后显示。",
  "b1.dash.coverage.overall": "总体覆盖率",
  "b1.dash.coverage.policies": "· {active}/{total} 条策略生效",
  "b1.dash.threat.title": "按地区的威胁活动",
  "b1.dash.threat.help":
    "标出此租户的地区，大小按当前未处理威胁数量。无法获取每个来源的位置，故此反映您受保护流量的服务地。",
  "b1.dash.activity.title": "安全活动（最近 24 小时）",
  "b1.dash.activity.help":
    "最近 24 小时内每小时检测到的异常数量，按严重程度分组。来自实时告警流。",
  "b1.dash.activity.clear.title": "一切正常",
  "b1.dash.activity.clear.desc": "最近 24 小时未检测到异常。",
  "b1.dash.alerts.title": "近期告警",
  "b1.dash.alerts.none.title": "暂无告警",
  "b1.dash.alerts.none.desc": "目前无需关注任何事项。",
  "b1.dash.alerts.viewAll": "查看全部告警",
  "b1.dash.col.severity": "严重程度",
  "b1.dash.col.kind": "类型",
  "b1.dash.col.dimension": "环节",
  "b1.dash.col.zscore": "Z 分数",
  "b1.dash.col.state": "状态",
  "b1.dash.col.when": "时间",
};

const de: PartialCatalog = {
  "b1.common.back": "Zurück",
  "b1.common.continue": "Weiter",
  "b1.common.cancel": "Abbrechen",
  "b1.common.retry": "Erneut versuchen",
  "b1.common.next": "Weiter",
  "b1.stepper.label": "Einrichtungsfortschritt",
  "b1.stepper.status.done": "Abgeschlossen",
  "b1.stepper.status.current": "Aktueller Schritt",
  "b1.stepper.status.todo": "Ausstehend",
  "b1.login.subtitle": "Betreiberkonsole",
  "b1.login.oidc.intro":
    "Melden Sie sich mit dem Single Sign-on Ihrer Organisation an, um fortzufahren.",
  "b1.login.oidc.cta": "Mit Single Sign-on fortfahren",
  "b1.login.jwt.label": "Entwickler-Zugriffstoken",
  "b1.login.jwt.placeholder": "Token einfügen (beginnt mit eyJ…)",
  "b1.login.jwt.help":
    "Fügen Sie das von Ihrem Administrator ausgestellte Betreiber-Token ein. In der Produktion verwendet dieser Bildschirm stattdessen das Single Sign-on Ihrer Organisation.",
  "b1.login.jwt.cta": "Anmelden",
  "b1.login.error.empty": "Geben Sie Ihr Zugriffstoken ein, um fortzufahren.",
  "b1.login.error.invalid":
    "Dieses Token ist ungültig oder abgelaufen. Fügen Sie ein aktuelles ein, um fortzufahren.",
  "b1.login.error.oidc":
    "Single Sign-on konnte nicht gestartet werden. Bitte versuchen Sie es erneut.",

  "b1.oidc.loading": "Sie werden angemeldet…",
  "b1.oidc.error.title": "Anmeldung konnte nicht abgeschlossen werden",
  "b1.oidc.error.unusable":
    "Ihr Identitätsanbieter hat ein Anmelde-Token zurückgegeben, das diese Konsole nicht lesen kann. ShieldNet benötigt ein standardmäßiges, nicht abgelaufenes Token — bitten Sie Ihren Administrator, Tokenformat und Zielgruppe des Single Sign-on zu prüfen.",
  "b1.oidc.error.generic":
    "Die Anmeldung wurde vor dem Abschluss unterbrochen. Bitte gehen Sie zurück und versuchen Sie es erneut.",
  "b1.oidc.back": "Zurück zur Anmeldung",
  "b1.settings.title": "Einstellungen",
  "b1.settings.subtitle":
    "Einstellungen für diese Konsole, auf diesem Gerät gespeichert.",
  "b1.settings.appearance.title": "Darstellung",
  "b1.settings.appearance.subtitle":
    "Wählen Sie das Aussehen der Konsole. Ihre Auswahl wird auf diesem Gerät gespeichert.",
  "b1.settings.theme.legend": "Design",
  "b1.settings.theme.light": "Hell",
  "b1.settings.theme.light.hint": "Immer das helle Design verwenden.",
  "b1.settings.theme.dark": "Dunkel",
  "b1.settings.theme.dark.hint": "Immer das dunkle Design verwenden.",
  "b1.settings.theme.system": "Wie System",
  "b1.settings.theme.system.hint": "Der Darstellungseinstellung Ihres Geräts folgen.",
  "b1.settings.theme.locked": "Design auf {theme} gesetzt.",
  "b1.settings.theme.following": "Folgt Ihrem Gerät — derzeit {theme}.",
  "b1.settings.theme.value.light": "hell",
  "b1.settings.theme.value.dark": "dunkel",
  "b1.settings.language.title": "Sprache",
  "b1.settings.language.subtitle":
    "Wählen Sie die Sprache dieser Konsole. Ihre Auswahl wird auf diesem Gerät gespeichert.",
  "b1.guided.title": "Geführte Einrichtung",
  "b1.guided.subtitle":
    "Erstellen Sie Ihren Mandanten und aktivieren Sie den ersten Schutz — in fünf schnellen Schritten.",
  "b1.guided.steps": "Mandant|Datenstandort|Branche|Erste Richtlinie|Fertig",
  "b1.guided.step.tenant.title": "Mandanten erstellen",
  "b1.guided.step.tenant.desc":
    "Ein Mandant ist der private Arbeitsbereich, der Personen, Geräte und Richtlinien einer Organisation von allen anderen trennt.",
  "b1.guided.field.businessName": "Firmenname",
  "b1.guided.field.businessName.placeholder": "Acme GmbH",
  "b1.guided.field.plan": "Tarif",
  "b1.guided.cta.create": "Mandanten erstellen",
  "b1.guided.toast.created.title": "Mandant erstellt",
  "b1.guided.toast.created.body": "{name} kann jetzt konfiguriert werden.",
  "b1.guided.toast.createFailed": "Mandant konnte nicht erstellt werden",
  "b1.guided.step.residency.title": "Wo ist {name} tätig?",
  "b1.guided.step.residency.desc":
    "Dies legt fest, wo Ihre Daten gespeichert werden und welche Compliance-Regeln die erste Richtlinie anwendet.",
  "b1.guided.field.country": "Land / Datenstandort",
  "b1.guided.field.country.placeholder": "Land wählen…",
  "b1.guided.residency.regime": "Angewandte Regeln: <badge>{regime}</badge>",
  "b1.guided.step.industry.title": "Womit befasst sich das Unternehmen?",
  "b1.guided.step.industry.desc":
    "Ihre Branche legt sinnvolle Standardwerte für die zulässige Nutzung und die überwachten sensiblen Daten fest.",
  "b1.guided.cta.preview": "Schutz in der Vorschau",
  "b1.guided.cta.previewing": "Wird vorbereitet…",
  "b1.guided.toast.renderFailed": "Baseline konnte nicht vorbereitet werden",
  "b1.guided.step.review.title": "Ersten Schutz prüfen",
  "b1.guided.review.summary": "{industry} · {country} · <badge>{regime}</badge>",
  "b1.guided.review.composedFrom": "Erstellt aus",
  "b1.guided.review.fingerprint": "Richtlinien-Fingerabdruck",
  "b1.guided.cta.apply": "Schutz aktivieren",
  "b1.guided.cta.applying": "Wird aktiviert…",
  "b1.guided.toast.applyFailed": "Schutz konnte nicht aktiviert werden",
  "b1.guided.toast.applied.title": "Schutz ist aktiv",
  "b1.guided.toast.applied.body": "{name} ist jetzt geschützt.",
  "b1.guided.step.done.title": "Alles erledigt",
  "b1.guided.step.done.desc":
    "Für {name} ist der erste Schutz aktiviert. Fügen Sie als Nächstes Standorte hinzu, registrieren Sie Geräte oder verfeinern Sie die Richtlinie.",
  "b1.guided.cta.goDashboard": "Zum Dashboard",
  "b1.guided.cta.fullSetup": "Vollständige Einrichtung fortsetzen",
  "b1.onboard.title": "Schutz aktivieren",
  "b1.onboard.subtitle":
    "Eine kurze Einrichtung in fünf Schritten. Jederzeit verlassen und später fortsetzen.",
  "b1.onboard.steps": "Mandant|Standort|Anmeldung|Schutz|Geräte",
  "b1.onboard.tenant.title": "Mandanten zum Einrichten wählen",
  "b1.onboard.tenant.intro":
    "ShieldNet schützt den Internetverkehr Ihres Unternehmens — wehrt Bedrohungen ab, verhindert Datenlecks und schützt Remote-Mitarbeitende — ohne IT-Team. Alles in dieser Einrichtung gilt für den hier gewählten Mandanten.",
  "b1.onboard.anim.staff": "Personal",
  "b1.onboard.anim.sng": "ShieldNet",
  "b1.onboard.anim.internet": "Internet",
  "b1.onboard.tenant.existing": "Vorhandene Mandanten",
  "b1.onboard.tenant.createInstead": "Stattdessen neuen Mandanten erstellen",
  "b1.onboard.tenant.none":
    "Sie haben noch keine Mandanten. Erstellen Sie Ihren ersten, um zu beginnen.",
  "b1.onboard.newTenant.title": "Neuer Mandant",
  "b1.onboard.field.businessName": "Firmenname",
  "b1.onboard.field.businessName.help":
    "Die Organisation, die dieser Mandant repräsentiert, z. B. „Acme GmbH“. Wird überall in der Konsole angezeigt.",
  "b1.onboard.field.businessName.placeholder": "z. B. Acme GmbH",
  "b1.onboard.field.slug": "Kurzname (optional)",
  "b1.onboard.field.slug.help":
    "Eine kurze Kennung in Kleinbuchstaben für Webadressen und Konfigurationen. Leer lassen, dann erzeugen wir eine aus dem Namen.",
  "b1.onboard.field.slug.placeholder": "acme",
  "b1.onboard.field.region": "Region (optional)",
  "b1.onboard.field.region.help":
    "Wo die Daten dieses Mandanten verarbeitet werden. Leer lassen für den Plattformstandard.",
  "b1.onboard.field.region.placeholder": "z. B. eu-west-1",
  "b1.onboard.field.planTier": "Tarif",
  "b1.onboard.tier.starter.blurb":
    "Kleine Teams für den Einstieg — Kernschutz, sinnvolle Standardwerte.",
  "b1.onboard.tier.professional.blurb":
    "Wachsende Unternehmen — volle Richtliniensteuerung und Integrationen.",
  "b1.onboard.tier.enterprise.blurb":
    "Große oder regulierte Organisationen — erweiterte Kontrollen und Skalierung.",
  "b1.onboard.cta.createTenant": "Mandanten erstellen",
  "b1.onboard.cta.creating": "Wird erstellt…",
  "b1.onboard.cta.continue": "Weiter",
  "b1.onboard.toast.tenantCreated.title": "Mandant erstellt",
  "b1.onboard.toast.tenantCreated.body": "{name} ist jetzt aktiv.",
  "b1.onboard.toast.tenantFailed": "Mandant konnte nicht erstellt werden",
  "b1.onboard.site.title": "Ersten Standort hinzufügen",
  "b1.onboard.site.existing":
    "Sie haben bereits {count, plural, one {# Standort} other {# Standorte}}. Fügen Sie einen weiteren hinzu oder fahren Sie fort.",
  "b1.onboard.field.siteName": "Standortname",
  "b1.onboard.field.siteName.help":
    "Ein einprägsamer Name für diesen Standort, z. B. „Zentrale London“ oder „Lager“. Nur zur Wiedererkennung für Sie.",
  "b1.onboard.field.siteName.placeholder": "z. B. Zentrale London",
  "b1.onboard.field.siteSlug.help":
    "Eine kurze Kennung in Kleinbuchstaben für Webadressen und Konfigurationen. Leer lassen, dann erzeugen wir eine aus dem Namen.",
  "b1.onboard.field.siteSlug.placeholder": "zentrale-london",
  "b1.onboard.field.deployment": "Bereitstellungsart",
  "b1.onboard.field.deployment.help":
    "Wie dieser Standort verbunden ist. Die meisten Büros sind eine „Filiale“. Wählen Sie „Nur Cloud“, wenn es kein physisches Netzwerk zu schützen gibt.",
  "b1.onboard.template.branch.blurb":
    "Ein physisches Büro mit eigenem Netzwerk — Mitarbeitende vor Ort teilen einen Internetzugang.",
  "b1.onboard.template.hub.blurb":
    "Ein zentraler Standort, über den andere Standorte verbunden sind.",
  "b1.onboard.template.cloud_only.blurb":
    "Keine Hardware — schützt nur Cloud-Apps und Remote-Mitarbeitende.",
  "b1.onboard.template.home_office.blurb":
    "Eine einzelne remote arbeitende Person, eingerichtet von deren Gerät.",
  "b1.onboard.cta.createSite": "Standort erstellen",
  "b1.onboard.cta.creatingSite": "Wird erstellt…",
  "b1.onboard.cta.skip": "Überspringen",
  "b1.onboard.toast.siteCreated.title": "Standort erstellt",
  "b1.onboard.toast.siteCreated.body": "{name} ist jetzt verbunden.",
  "b1.onboard.toast.siteFailed": "Standort konnte nicht erstellt werden",
  "b1.onboard.identity.title": "Identitätsanbieter verbinden",
  "b1.onboard.identity.help":
    "ShieldNet übergibt die Anmeldung an Ihren Identitätsanbieter (Okta, Microsoft Entra ID, Google Workspace u. a.) und kann Benutzer und Gruppen automatisch synchronisieren. Single Sign-on wird bei der Bereitstellung der Konsole eingerichtet; hier prüfen wir, ob es aktiv ist.",
  "b1.onboard.identity.enabled": "Single Sign-on aktiviert",
  "b1.onboard.identity.issuer": "Anbieteradresse",
  "b1.onboard.identity.clientId": "Client-ID",
  "b1.onboard.identity.scopes": "Bereiche",
  "b1.onboard.identity.verifying": "Anbieter wird geprüft…",
  "b1.onboard.identity.verifyFailed":
    "Die Einstellungen Ihres Identitätsanbieters waren nicht erreichbar: {detail}. Prüfen Sie die Adresse und ob sie aus diesem Browser erreichbar ist.",
  "b1.onboard.identity.discoveryFailed": "die Verbindung wurde nicht abgeschlossen",
  "b1.onboard.identity.verified":
    "Verbindung bestätigt — Single Sign-on ist bereit.",
  "b1.onboard.identity.authorization": "Anmeldeadresse",
  "b1.onboard.identity.token": "Token-Adresse",
  "b1.onboard.identity.jwks": "Signaturschlüssel",
  "b1.onboard.identity.scimHint":
    "Um Benutzer und Gruppen automatisch hinzuzufügen, richten Sie die <scim>Verzeichnissynchronisierung</scim> ein. Vollständige Anmeldedetails finden Sie auf der Seite <idp>Identitätsanbieter</idp>.",
  "b1.onboard.identity.devBadge": "Entwickleranmeldung",
  "b1.onboard.identity.devBody":
    "Diese Konsole ist im Entwickleranmeldemodus und akzeptiert ein eingefügtes Betreiber-Token. Um die Anmeldung an Ihren Identitätsanbieter zu übergeben, aktivieren Sie Single Sign-on in den Bereitstellungseinstellungen und führen Sie diesen Schritt erneut aus, um die Verbindung zu prüfen.",
  "b1.onboard.identity.devNote":
    "Sie können dennoch fortfahren und die Einrichtung abschließen — Single Sign-on lässt sich später aktivieren, ohne den Rest zu wiederholen.",
  "b1.onboard.policy.title": "Schutzvorlage anwenden",
  "b1.onboard.policy.help":
    "Dies sind fertige Datenschutzrichtlinien. Sie legen fest, welche sensiblen Informationen — Kartennummern, Ausweisnummern, Geheimnisse — ShieldNet überwacht und blockiert. Alles lässt sich später verfeinern.",
  "b1.onboard.policy.none":
    "Für diesen Mandanten sind noch keine Schutzvorlagen veröffentlicht. Sie können diesen Schritt überspringen und den Datenschutz später einrichten.",
  "b1.onboard.policy.rules": "{count, plural, one {# Regel} other {# Regeln}}",
  "b1.onboard.cta.applyContinue": "Anwenden & fortfahren",
  "b1.onboard.cta.skipForNow": "Vorerst überspringen",
  "b1.onboard.cta.applyingPolicy": "Wird angewendet…",
  "b1.onboard.toast.protectionApplied.title": "Schutz angewendet",
  "b1.onboard.toast.protectionApplied.body":
    "Ihre Datenschutzrichtlinie ist jetzt aktiv.",
  "b1.onboard.toast.policyFailed": "Vorlage konnte nicht angewendet werden",
  "b1.onboard.deploy.title": "Erstes Gerät bereitstellen & registrieren",
  "b1.onboard.deploy.intro":
    "Ein Beitrittstoken lässt ein Gerät diesem Mandanten sicher beitreten. Erzeugen Sie eines, installieren Sie dann den ShieldNet-Agenten auf dem Gerät und fügen Sie das Token ein (oder scannen Sie den QR-Code), wenn danach gefragt wird.",
  "b1.onboard.deploy.enrolled":
    "{count, plural, one {# Gerät} other {# Geräte}} bereits registriert.",
  "b1.onboard.cta.generateToken": "Beitrittstoken erzeugen",
  "b1.onboard.cta.generating": "Wird erzeugt…",
  "b1.onboard.deploy.tokenLabel": "Beitrittstoken (einmalig angezeigt)",
  "b1.onboard.cta.copy": "Kopieren",
  "b1.onboard.cta.copied": "Kopiert",
  "b1.onboard.deploy.expires":
    "Läuft ab {date}. Erzeugen Sie ein neues Token, wenn es abläuft.",
  "b1.onboard.deploy.instructions":
    "Installieren Sie auf dem Gerät den ShieldNet-Agenten, wählen Sie „Mit Token registrieren“ und fügen Sie den obigen Wert ein. Mobile Agenten können stattdessen den QR-Code scannen.",
  "b1.onboard.deploy.scanHint": "Mit dem mobilen Agenten scannen",
  "b1.onboard.toast.copied.title": "Kopiert",
  "b1.onboard.toast.copied.body":
    "Beitrittstoken in die Zwischenablage kopiert.",
  "b1.onboard.toast.copyFailed.title": "Kopieren fehlgeschlagen",
  "b1.onboard.toast.copyFailed.body":
    "Markieren Sie das Token und kopieren Sie es manuell.",
  "b1.onboard.toast.tokenFailed": "Token konnte nicht erzeugt werden",
  "b1.onboard.deploy.doneTitle": "Sie sind geschützt",
  "b1.onboard.deploy.doneSub":
    "ShieldNet überwacht jetzt den Verkehr dieses Mandanten. Hier geht es weiter:",
  "b1.onboard.deploy.link.dashboard":
    "<link>Dashboard</link> — Ihre Sicherheit auf einen Blick.",
  "b1.onboard.deploy.link.alerts": "<link>Warnungen</link> — Bedrohungen sobald sie erkannt werden.",
  "b1.onboard.deploy.link.policy":
    "<link>Richtlinie</link> — prüfen und verfeinern, was erlaubt ist.",
  "b1.onboard.deploy.link.devices":
    "<link>Geräte</link> — jederzeit weitere Geräte registrieren.",
  "b1.onboard.cta.goDashboard": "Zum Dashboard",
  "b1.dash.title": "Dashboard",
  "b1.dash.subtitle.tenant": "Sicherheit für {name}",
  "b1.dash.subtitle.default": "Ihre Sicherheit auf einen Blick",
  "b1.dash.banner.title": "Aktivieren wir Ihren Schutz",
  "b1.dash.banner.sub":
    "Dieser Mandant hat noch keine Standorte oder Geräte. Die geführte Einrichtung aktiviert den Schutz in etwa fünf Minuten.",
  "b1.dash.banner.cta": "Loslegen",
  "b1.dash.stat.tenants": "Mandanten",
  "b1.dash.stat.sites": "Standorte",
  "b1.dash.stat.sites.tier": "Tarif: {tier}",
  "b1.dash.stat.devices": "Geräte",
  "b1.dash.stat.openAlerts": "Offene Warnungen",
  "b1.dash.stat.attention": "erfordert Aufmerksamkeit",
  "b1.dash.stat.clear": "alles in Ordnung",
  "b1.dash.score.title": "Sicherheitsbewertung",
  "b1.dash.score.none":
    "Für diesen Mandanten wurde noch keine Zustandsprüfung erfasst.",
  "b1.dash.score.composite":
    "Basierend auf {count, plural, =0 {Ihren Betriebsprüfungen} one {# Betriebsprüfung} other {# Betriebsprüfungen}}.",
  "b1.dash.qa.title": "Nächste Schritte",
  "b1.dash.qa.help":
    "Die nützlichsten nächsten Schritte aus Ihrer aktuellen Sicherheitslage — offene Warnungen, schwache Bereiche, Einrichtungslücken und Empfehlungen.",
  "b1.dash.qa.none":
    "Sie sind auf dem neuesten Stand — derzeit erfordert nichts Ihre Aufmerksamkeit.",
  "b1.dash.qa.addSite.title": "Ersten Standort hinzufügen",
  "b1.dash.qa.addSite.desc":
    "Verbinden Sie einen Standort, damit Verkehr durch das Gateway fließt.",
  "b1.dash.qa.addSite.cta": "Einrichten",
  "b1.dash.qa.enrolDevice.title": "Erstes Gerät registrieren",
  "b1.dash.qa.enrolDevice.desc":
    "Installieren Sie den Agenten und beanspruchen Sie ein Gerät, um den Schutz zu starten.",
  "b1.dash.qa.enrolDevice.cta": "Registrieren",
  "b1.dash.qa.critical.title":
    "{count, plural, one {# kritische Warnung beheben} other {# kritische Warnungen beheben}}",
  "b1.dash.qa.critical.desc":
    "Kritische Anomalien sind offen und sollten geprüft werden.",
  "b1.dash.qa.critical.cta": "Prüfen",
  "b1.dash.qa.usage.title": "Nutzung über einer harten Grenze",
  "b1.dash.qa.usage.desc": "{meters} hat seine Obergrenze überschritten.",
  "b1.dash.qa.usage.cta": "Öffnen",
  "b1.dash.qa.weak.title": "{label} verbessern ({score}/100)",
  "b1.dash.qa.weak.desc": "Dieser Bereich drückt Ihre Sicherheitsbewertung.",
  "b1.dash.qa.weak.cta": "Optimieren",
  "b1.dash.qa.review": "Prüfen",
  "b1.dash.cost.title": "Geschätzte monatliche Kosten",
  "b1.dash.cost.help":
    "Zählt jedes Ihrer {count, plural, one {# registrierte Gerät} other {# registrierten Geräte}} als einen Platz zum Listenpreis von ${price}/Platz (veröffentlichte Spanne $5–12). Nutzt eine Person mehrere Geräte, wird überschätzt — verbinden Sie die Abrechnung für genaue Zahlen.",
  "b1.dash.cost.perMo": "/ Mon.",
  "b1.dash.cost.basis":
    "{count, plural, one {# Gerät} other {# Geräte}} × ${price}/Platz pro Monat",
  "b1.dash.cost.enrol": "Registrieren Sie Geräte, um Kosten zu schätzen.",
  "b1.dash.cost.trend.up": "Nutzung steigt",
  "b1.dash.cost.trend.down": "Nutzung sinkt",
  "b1.dash.cost.trend.stable": "Nutzung stabil",
  "b1.dash.coverage.title": "Richtlinienabdeckung",
  "b1.dash.coverage.help":
    "Wie viel Ihres Betriebs aktiv durch Richtlinien geregelt ist. Bereichswerte stammen aus der letzten Zustandsprüfung; die Gesamtabdeckung aus dem Sicherheitsbericht.",
  "b1.dash.coverage.none":
    "Die Abdeckung erscheint, sobald ein Sicherheitsbericht oder eine Zustandsprüfung vorliegt.",
  "b1.dash.coverage.overall": "Gesamtabdeckung",
  "b1.dash.coverage.policies": "· {active}/{total} Richtlinien aktiv",
  "b1.dash.threat.title": "Bedrohungsaktivität nach Region",
  "b1.dash.threat.help":
    "Zeigt die Region dieses Mandanten, skaliert nach aktuell offenen Bedrohungen. Eine Herkunft je Ursprung ist nicht verfügbar; dies zeigt daher, von wo Ihr geschützter Verkehr bereitgestellt wird.",
  "b1.dash.activity.title": "Sicherheitsaktivität (letzte 24 Stunden)",
  "b1.dash.activity.help":
    "Stündliche Anzahl erkannter Anomalien der letzten 24 Stunden, nach Schweregrad gruppiert. Aus dem Live-Warnstrom.",
  "b1.dash.activity.clear.title": "Alles in Ordnung",
  "b1.dash.activity.clear.desc":
    "In den letzten 24 Stunden keine Anomalien erkannt.",
  "b1.dash.alerts.title": "Letzte Warnungen",
  "b1.dash.alerts.none.title": "Keine Warnungen",
  "b1.dash.alerts.none.desc": "Derzeit erfordert nichts Ihre Aufmerksamkeit.",
  "b1.dash.alerts.viewAll": "Alle Warnungen ansehen",
  "b1.dash.col.severity": "Schweregrad",
  "b1.dash.col.kind": "Art",
  "b1.dash.col.dimension": "Bereich",
  "b1.dash.col.zscore": "Z-Wert",
  "b1.dash.col.state": "Status",
  "b1.dash.col.when": "Wann",
};

const fr: PartialCatalog = {
  "b1.common.back": "Retour",
  "b1.common.continue": "Continuer",
  "b1.common.cancel": "Annuler",
  "b1.common.retry": "Réessayer",
  "b1.common.next": "Suivant",
  "b1.stepper.label": "Progression de la configuration",
  "b1.stepper.status.done": "Terminé",
  "b1.stepper.status.current": "Étape actuelle",
  "b1.stepper.status.todo": "À venir",
  "b1.login.subtitle": "Console opérateur",
  "b1.login.oidc.intro":
    "Connectez-vous avec l'authentification unique de votre organisation pour continuer.",
  "b1.login.oidc.cta": "Continuer avec l'authentification unique",
  "b1.login.jwt.label": "Jeton d'accès développeur",
  "b1.login.jwt.placeholder": "Collez votre jeton (commence par eyJ…)",
  "b1.login.jwt.help":
    "Collez le jeton opérateur fourni par votre administrateur. En production, cet écran utilise plutôt l'authentification unique de votre organisation.",
  "b1.login.jwt.cta": "Se connecter",
  "b1.login.error.empty": "Saisissez votre jeton d'accès pour continuer.",
  "b1.login.error.invalid":
    "Ce jeton est invalide ou a expiré. Collez-en un valide pour continuer.",
  "b1.login.error.oidc":
    "Impossible de démarrer l'authentification unique. Veuillez réessayer.",

  "b1.oidc.loading": "Connexion en cours…",
  "b1.oidc.error.title": "Impossible de terminer la connexion",
  "b1.oidc.error.unusable":
    "Votre fournisseur d'identité a renvoyé un jeton de connexion que cette console ne peut pas lire. ShieldNet a besoin d'un jeton standard et non expiré — demandez à votre administrateur de vérifier le format et l'audience du jeton d'authentification unique.",
  "b1.oidc.error.generic":
    "La connexion a été interrompue avant de se terminer. Revenez en arrière et réessayez.",
  "b1.oidc.back": "Retour à la connexion",
  "b1.settings.title": "Paramètres",
  "b1.settings.subtitle":
    "Préférences de cette console, enregistrées sur cet appareil.",
  "b1.settings.appearance.title": "Apparence",
  "b1.settings.appearance.subtitle":
    "Choisissez l'apparence de la console. Votre choix est enregistré sur cet appareil.",
  "b1.settings.theme.legend": "Thème",
  "b1.settings.theme.light": "Clair",
  "b1.settings.theme.light.hint": "Toujours utiliser le thème clair.",
  "b1.settings.theme.dark": "Sombre",
  "b1.settings.theme.dark.hint": "Toujours utiliser le thème sombre.",
  "b1.settings.theme.system": "Selon le système",
  "b1.settings.theme.system.hint": "Suivre le réglage d'apparence de votre appareil.",
  "b1.settings.theme.locked": "Thème réglé sur {theme}.",
  "b1.settings.theme.following": "Suit votre appareil — actuellement {theme}.",
  "b1.settings.theme.value.light": "clair",
  "b1.settings.theme.value.dark": "sombre",
  "b1.settings.language.title": "Langue",
  "b1.settings.language.subtitle":
    "Choisissez la langue de cette console. Votre choix est enregistré sur cet appareil.",
  "b1.guided.title": "Configuration guidée",
  "b1.guided.subtitle":
    "Créez votre locataire et activez sa première protection — en cinq étapes rapides.",
  "b1.guided.steps": "Locataire|Emplacement des données|Secteur|Première politique|Terminé",
  "b1.guided.step.tenant.title": "Créer le locataire",
  "b1.guided.step.tenant.desc":
    "Un locataire est l'espace de travail privé qui sépare les personnes, appareils et politiques d'une organisation de toutes les autres.",
  "b1.guided.field.businessName": "Nom de l'entreprise",
  "b1.guided.field.businessName.placeholder": "Acme SARL",
  "b1.guided.field.plan": "Forfait",
  "b1.guided.cta.create": "Créer le locataire",
  "b1.guided.toast.created.title": "Locataire créé",
  "b1.guided.toast.created.body": "{name} est prêt à être configuré.",
  "b1.guided.toast.createFailed": "Impossible de créer le locataire",
  "b1.guided.step.residency.title": "Où {name} opère-t-il ?",
  "b1.guided.step.residency.desc":
    "Cela définit où vos données sont stockées et quelles règles de conformité la première politique applique.",
  "b1.guided.field.country": "Pays / emplacement des données",
  "b1.guided.field.country.placeholder": "Choisir un pays…",
  "b1.guided.residency.regime": "Règles appliquées : <badge>{regime}</badge>",
  "b1.guided.step.industry.title": "Que fait l'entreprise ?",
  "b1.guided.step.industry.desc":
    "Votre secteur définit des valeurs par défaut adaptées pour l'usage acceptable et les données sensibles surveillées.",
  "b1.guided.cta.preview": "Aperçu de la protection",
  "b1.guided.cta.previewing": "Préparation…",
  "b1.guided.toast.renderFailed": "Impossible de préparer la base",
  "b1.guided.step.review.title": "Vérifier votre première protection",
  "b1.guided.review.summary": "{industry} · {country} · <badge>{regime}</badge>",
  "b1.guided.review.composedFrom": "Construit à partir de",
  "b1.guided.review.fingerprint": "Empreinte de la politique",
  "b1.guided.cta.apply": "Activer la protection",
  "b1.guided.cta.applying": "Activation…",
  "b1.guided.toast.applyFailed": "Impossible d'activer la protection",
  "b1.guided.toast.applied.title": "Protection activée",
  "b1.guided.toast.applied.body": "{name} est maintenant protégé.",
  "b1.guided.step.done.title": "Tout est prêt",
  "b1.guided.step.done.desc":
    "La première protection de {name} est activée. Ajoutez ensuite des emplacements, enrôlez des appareils ou affinez la politique.",
  "b1.guided.cta.goDashboard": "Aller au tableau de bord",
  "b1.guided.cta.fullSetup": "Continuer la configuration complète",
  "b1.onboard.title": "Activer la protection",
  "b1.onboard.subtitle":
    "Une configuration courte en cinq étapes. Quittez à tout moment et reprenez où vous en étiez.",
  "b1.onboard.steps": "Locataire|Site|Connexion|Protection|Appareils",
  "b1.onboard.tenant.title": "Choisir le locataire à configurer",
  "b1.onboard.tenant.intro":
    "ShieldNet protège le trafic internet de votre entreprise — en bloquant les menaces, en stoppant les fuites de données et en protégeant le personnel distant — sans équipe informatique. Tout dans cette configuration s'applique au locataire choisi ici.",
  "b1.onboard.anim.staff": "Personnel",
  "b1.onboard.anim.sng": "ShieldNet",
  "b1.onboard.anim.internet": "Internet",
  "b1.onboard.tenant.existing": "Locataires existants",
  "b1.onboard.tenant.createInstead": "Créer plutôt un nouveau locataire",
  "b1.onboard.tenant.none":
    "Vous n'avez pas encore de locataire. Créez votre premier pour commencer.",
  "b1.onboard.newTenant.title": "Nouveau locataire",
  "b1.onboard.field.businessName": "Nom de l'entreprise",
  "b1.onboard.field.businessName.help":
    "L'organisation que ce locataire représente, p. ex. « Acme SARL ». Affichée dans toute la console.",
  "b1.onboard.field.businessName.placeholder": "p. ex. Acme SARL",
  "b1.onboard.field.slug": "Nom court (facultatif)",
  "b1.onboard.field.slug.help":
    "Un identifiant court en minuscules utilisé dans les adresses web et les configurations. Laissez vide et nous en générerons un à partir du nom.",
  "b1.onboard.field.slug.placeholder": "acme",
  "b1.onboard.field.region": "Région (facultatif)",
  "b1.onboard.field.region.help":
    "Où les données de ce locataire sont traitées. Laissez vide pour utiliser la valeur par défaut de la plateforme.",
  "b1.onboard.field.region.placeholder": "p. ex. eu-west-1",
  "b1.onboard.field.planTier": "Forfait",
  "b1.onboard.tier.starter.blurb":
    "Petites équipes qui débutent — protection essentielle, valeurs par défaut judicieuses.",
  "b1.onboard.tier.professional.blurb":
    "Entreprises en croissance — contrôle complet des politiques et intégrations.",
  "b1.onboard.tier.enterprise.blurb":
    "Grandes organisations ou organisations réglementées — contrôles avancés et mise à l'échelle.",
  "b1.onboard.cta.createTenant": "Créer le locataire",
  "b1.onboard.cta.creating": "Création…",
  "b1.onboard.cta.continue": "Continuer",
  "b1.onboard.toast.tenantCreated.title": "Locataire créé",
  "b1.onboard.toast.tenantCreated.body": "{name} est maintenant actif.",
  "b1.onboard.toast.tenantFailed": "Impossible de créer le locataire",
  "b1.onboard.site.title": "Ajouter votre premier site",
  "b1.onboard.site.existing":
    "Vous avez déjà {count, plural, one {# site} other {# sites}}. Ajoutez-en un autre ou continuez.",
  "b1.onboard.field.siteName": "Nom du site",
  "b1.onboard.field.siteName.help":
    "Un nom convivial pour cet emplacement, p. ex. « Siège de Londres » ou « Entrepôt ». C'est juste pour vous repérer.",
  "b1.onboard.field.siteName.placeholder": "p. ex. Siège de Londres",
  "b1.onboard.field.siteSlug.help":
    "Un identifiant court en minuscules utilisé dans les adresses web et les configurations. Laissez vide et nous en générerons un à partir du nom.",
  "b1.onboard.field.siteSlug.placeholder": "siege-londres",
  "b1.onboard.field.deployment": "Type de déploiement",
  "b1.onboard.field.deployment.help":
    "Comment cet emplacement se connecte. La plupart des bureaux sont une « Succursale ». Choisissez « Cloud uniquement » s'il n'y a pas de réseau physique à protéger.",
  "b1.onboard.template.branch.blurb":
    "Un bureau physique avec son propre réseau — le personnel sur place partage une seule sortie internet.",
  "b1.onboard.template.hub.blurb":
    "Un emplacement central par lequel les autres sites se reconnectent.",
  "b1.onboard.template.cloud_only.blurb":
    "Aucun matériel — protège uniquement les applications cloud et le personnel distant.",
  "b1.onboard.template.home_office.blurb":
    "Un seul télétravailleur, configuré depuis son appareil.",
  "b1.onboard.cta.createSite": "Créer le site",
  "b1.onboard.cta.creatingSite": "Création…",
  "b1.onboard.cta.skip": "Ignorer",
  "b1.onboard.toast.siteCreated.title": "Site créé",
  "b1.onboard.toast.siteCreated.body": "{name} est maintenant connecté.",
  "b1.onboard.toast.siteFailed": "Impossible de créer le site",
  "b1.onboard.identity.title": "Connecter votre fournisseur d'identité",
  "b1.onboard.identity.help":
    "ShieldNet confie la connexion à votre fournisseur d'identité (Okta, Microsoft Entra ID, Google Workspace, etc.) et peut synchroniser automatiquement utilisateurs et groupes. L'authentification unique se configure au déploiement de la console ; ici, nous vérifions qu'elle est active.",
  "b1.onboard.identity.enabled": "Authentification unique activée",
  "b1.onboard.identity.issuer": "Adresse du fournisseur",
  "b1.onboard.identity.clientId": "ID client",
  "b1.onboard.identity.scopes": "Portées",
  "b1.onboard.identity.verifying": "Vérification de votre fournisseur…",
  "b1.onboard.identity.verifyFailed":
    "Impossible d'atteindre les paramètres de votre fournisseur d'identité : {detail}. Vérifiez l'adresse et qu'elle est joignable depuis ce navigateur.",
  "b1.onboard.identity.discoveryFailed": "la connexion n'a pas abouti",
  "b1.onboard.identity.verified":
    "Connexion vérifiée — l'authentification unique est prête.",
  "b1.onboard.identity.authorization": "Adresse de connexion",
  "b1.onboard.identity.token": "Adresse du jeton",
  "b1.onboard.identity.jwks": "Clés de signature",
  "b1.onboard.identity.scimHint":
    "Pour ajouter automatiquement utilisateurs et groupes, configurez la <scim>synchronisation d'annuaire</scim>. Les détails complets de connexion se trouvent sur la page <idp>fournisseur d'identité</idp>.",
  "b1.onboard.identity.devBadge": "Connexion développeur",
  "b1.onboard.identity.devBody":
    "Cette console est en mode connexion développeur, où elle accepte un jeton opérateur collé. Pour confier la connexion à votre fournisseur d'identité, activez l'authentification unique dans les paramètres de déploiement, puis relancez cette étape pour vérifier la connexion.",
  "b1.onboard.identity.devNote":
    "Vous pouvez tout de même continuer et terminer la configuration — l'authentification unique peut être activée plus tard sans refaire le reste.",
  "b1.onboard.policy.title": "Appliquer un modèle de protection",
  "b1.onboard.policy.help":
    "Ce sont des politiques de protection des données prêtes à l'emploi. Elles déterminent quelles informations sensibles — numéros de carte, numéros d'identité, secrets — ShieldNet surveille et bloque. Tout peut être ajusté plus tard.",
  "b1.onboard.policy.none":
    "Aucun modèle de protection n'est encore publié pour ce locataire. Vous pouvez ignorer cette étape et configurer la protection des données plus tard.",
  "b1.onboard.policy.rules": "{count, plural, one {# règle} other {# règles}}",
  "b1.onboard.cta.applyContinue": "Appliquer et continuer",
  "b1.onboard.cta.skipForNow": "Ignorer pour l'instant",
  "b1.onboard.cta.applyingPolicy": "Application…",
  "b1.onboard.toast.protectionApplied.title": "Protection appliquée",
  "b1.onboard.toast.protectionApplied.body":
    "Votre politique de protection des données est désormais active.",
  "b1.onboard.toast.policyFailed": "Impossible d'appliquer le modèle",
  "b1.onboard.deploy.title": "Déployer et enrôler votre premier appareil",
  "b1.onboard.deploy.intro":
    "Un jeton de rattachement permet à un appareil de rejoindre ce locataire en toute sécurité. Générez-en un, puis installez l'agent ShieldNet sur l'appareil et collez le jeton (ou scannez le QR code) lorsqu'il le demande.",
  "b1.onboard.deploy.enrolled":
    "{count, plural, one {# appareil déjà enrôlé} other {# appareils déjà enrôlés}}.",
  "b1.onboard.cta.generateToken": "Générer un jeton de rattachement",
  "b1.onboard.cta.generating": "Génération…",
  "b1.onboard.deploy.tokenLabel": "Jeton de rattachement (affiché une fois)",
  "b1.onboard.cta.copy": "Copier",
  "b1.onboard.cta.copied": "Copié",
  "b1.onboard.deploy.expires":
    "Expire le {date}. Générez un nouveau jeton s'il expire.",
  "b1.onboard.deploy.instructions":
    "Sur l'appareil, installez l'agent ShieldNet et choisissez « Enrôler avec un jeton », puis collez la valeur ci-dessus. Les agents mobiles peuvent scanner le QR code à la place.",
  "b1.onboard.deploy.scanHint": "Scanner avec l'agent mobile",
  "b1.onboard.toast.copied.title": "Copié",
  "b1.onboard.toast.copied.body":
    "Jeton de rattachement copié dans le presse-papiers.",
  "b1.onboard.toast.copyFailed.title": "Échec de la copie",
  "b1.onboard.toast.copyFailed.body":
    "Sélectionnez le jeton et copiez-le manuellement.",
  "b1.onboard.toast.tokenFailed": "Impossible de générer un jeton",
  "b1.onboard.deploy.doneTitle": "Vous êtes protégé",
  "b1.onboard.deploy.doneSub":
    "ShieldNet surveille désormais le trafic de ce locataire. Voici la suite :",
  "b1.onboard.deploy.link.dashboard":
    "<link>Tableau de bord</link> — votre sécurité en un coup d'œil.",
  "b1.onboard.deploy.link.alerts":
    "<link>Alertes</link> — les menaces dès qu'elles sont détectées.",
  "b1.onboard.deploy.link.policy":
    "<link>Politique</link> — vérifier et affiner ce qui est autorisé.",
  "b1.onboard.deploy.link.devices":
    "<link>Appareils</link> — enrôler d'autres appareils à tout moment.",
  "b1.onboard.cta.goDashboard": "Aller au tableau de bord",
  "b1.dash.title": "Tableau de bord",
  "b1.dash.subtitle.tenant": "Sécurité de {name}",
  "b1.dash.subtitle.default": "Votre sécurité en un coup d'œil",
  "b1.dash.banner.title": "Activons votre protection",
  "b1.dash.banner.sub":
    "Ce locataire n'a encore ni site ni appareil. La configuration guidée active la protection en environ cinq minutes.",
  "b1.dash.banner.cta": "Commencer",
  "b1.dash.stat.tenants": "Locataires",
  "b1.dash.stat.sites": "Sites",
  "b1.dash.stat.sites.tier": "Forfait : {tier}",
  "b1.dash.stat.devices": "Appareils",
  "b1.dash.stat.openAlerts": "Alertes ouvertes",
  "b1.dash.stat.attention": "à surveiller",
  "b1.dash.stat.clear": "tout va bien",
  "b1.dash.score.title": "Score de sécurité",
  "b1.dash.score.none":
    "Nous n'avons pas encore enregistré de contrôle d'état pour ce locataire.",
  "b1.dash.score.composite":
    "Basé sur {count, plural, =0 {vos contrôles opérationnels} one {# contrôle opérationnel} other {# contrôles opérationnels}}.",
  "b1.dash.qa.title": "Que faire ensuite",
  "b1.dash.qa.help":
    "Les prochaines étapes les plus utiles, issues de votre sécurité en temps réel — alertes ouvertes, points faibles, lacunes de configuration et recommandations.",
  "b1.dash.qa.none":
    "Vous êtes à jour — rien ne requiert votre attention pour l'instant.",
  "b1.dash.qa.addSite.title": "Ajouter votre premier site",
  "b1.dash.qa.addSite.desc":
    "Connectez un emplacement pour que le trafic commence à passer par la passerelle.",
  "b1.dash.qa.addSite.cta": "Configurer",
  "b1.dash.qa.enrolDevice.title": "Enrôler votre premier appareil",
  "b1.dash.qa.enrolDevice.desc":
    "Installez l'agent et rattachez un appareil pour démarrer la protection.",
  "b1.dash.qa.enrolDevice.cta": "Enrôler",
  "b1.dash.qa.critical.title":
    "{count, plural, one {Résoudre # alerte critique} other {Résoudre # alertes critiques}}",
  "b1.dash.qa.critical.desc":
    "Des anomalies critiques sont ouvertes et méritent un examen.",
  "b1.dash.qa.critical.cta": "Examiner",
  "b1.dash.qa.usage.title": "Utilisation au-delà d'une limite stricte",
  "b1.dash.qa.usage.desc": "{meters} a dépassé son plafond.",
  "b1.dash.qa.usage.cta": "Ouvrir",
  "b1.dash.qa.weak.title": "Améliorer {label} ({score}/100)",
  "b1.dash.qa.weak.desc": "Ce domaine fait baisser votre score de sécurité.",
  "b1.dash.qa.weak.cta": "Ajuster",
  "b1.dash.qa.review": "Examiner",
  "b1.dash.cost.title": "Coût mensuel estimé",
  "b1.dash.cost.help":
    "Compte chacun de vos {count, plural, one {# appareil enrôlé} other {# appareils enrôlés}} comme un poste au tarif public de {price} $/poste (fourchette publiée 5–12 $). Si une personne utilise plusieurs appareils, l'estimation est trop élevée — connectez la facturation pour des chiffres exacts.",
  "b1.dash.cost.perMo": "/ mois",
  "b1.dash.cost.basis":
    "{count, plural, one {# appareil} other {# appareils}} × {price} $/poste par mois",
  "b1.dash.cost.enrol": "Enrôlez des appareils pour estimer un coût.",
  "b1.dash.cost.trend.up": "Utilisation en hausse",
  "b1.dash.cost.trend.down": "Utilisation en baisse",
  "b1.dash.cost.trend.stable": "Utilisation stable",
  "b1.dash.coverage.title": "Couverture des politiques",
  "b1.dash.coverage.help":
    "La part de vos opérations activement régie par des politiques. Les scores par domaine proviennent du dernier contrôle d'état ; la couverture globale provient du rapport de sécurité.",
  "b1.dash.coverage.none":
    "La couverture apparaît dès qu'un rapport de sécurité ou un contrôle d'état existe.",
  "b1.dash.coverage.overall": "Couverture globale",
  "b1.dash.coverage.policies": "· {active}/{total} politiques actives",
  "b1.dash.threat.title": "Activité des menaces par région",
  "b1.dash.threat.help":
    "Trace la région de ce locataire, dimensionnée selon les menaces actuellement ouvertes. L'origine précise n'étant pas disponible, ceci reflète l'endroit d'où votre trafic protégé est servi.",
  "b1.dash.activity.title": "Activité de sécurité (24 dernières heures)",
  "b1.dash.activity.help":
    "Nombre horaire d'anomalies détectées sur les 24 dernières heures, regroupées par gravité. Issu du flux d'alertes en direct.",
  "b1.dash.activity.clear.title": "Tout va bien",
  "b1.dash.activity.clear.desc":
    "Aucune anomalie détectée au cours des 24 dernières heures.",
  "b1.dash.alerts.title": "Alertes récentes",
  "b1.dash.alerts.none.title": "Aucune alerte",
  "b1.dash.alerts.none.desc": "Rien ne requiert votre attention pour l'instant.",
  "b1.dash.alerts.viewAll": "Voir toutes les alertes",
  "b1.dash.col.severity": "Gravité",
  "b1.dash.col.kind": "Type",
  "b1.dash.col.dimension": "Domaine",
  "b1.dash.col.zscore": "Score Z",
  "b1.dash.col.state": "État",
  "b1.dash.col.when": "Quand",
};

// Locales adopt keys incrementally. Until a catalog is filled, react-intl
// falls back to the English source string above (defaultLocale="en"), so the
// console stays fully legible in every locale.
const zhHant: PartialCatalog = {};
const ms: PartialCatalog = {};
const id: PartialCatalog = {};
const th: PartialCatalog = {};
const vi: PartialCatalog = {};
const ja: PartialCatalog = {};
const ko: PartialCatalog = {};
const ar: PartialCatalog = {};

const LANE_MESSAGES: Record<Locale, PartialCatalog> = {
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

// Merge the locale catalog over the English source so every key resolves,
// falling back to English for any not-yet-translated string.
export function laneMessagesFor(locale: Locale): Record<string, string> {
  return { ...en, ...(LANE_MESSAGES[locale] ?? LANE_MESSAGES[DEFAULT_LOCALE]) };
}
