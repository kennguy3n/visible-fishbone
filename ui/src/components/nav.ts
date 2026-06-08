// Sidebar navigation model. Each entry maps to a route built in
// `src/router.tsx`. Grouped to mirror the operator mental model:
// overview, the policy/security domains, fleet, operations, and the
// MSP partner portal.

export interface NavItem {
  label: string;
  to: string;
  icon: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { label: "Dashboard", to: "/", icon: "▦" },
      { label: "Get started", to: "/onboarding", icon: "✸" },
      { label: "Tenants", to: "/tenants", icon: "◳" },
      { label: "Sites", to: "/sites", icon: "⌂" },
      { label: "Devices", to: "/devices", icon: "▢" },
    ],
  },
  {
    label: "Security policy",
    items: [
      { label: "Policy editor", to: "/policy", icon: "⎇" },
      { label: "Network policies", to: "/network-policies", icon: "⇄" },
      { label: "DLP", to: "/dlp", icon: "❏" },
      { label: "CASB", to: "/casb", icon: "☁" },
      { label: "Browser protection", to: "/browser", icon: "◍" },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Alerts", to: "/alerts", icon: "◆" },
      { label: "AI assistant", to: "/assistant", icon: "✦" },
      { label: "Troubleshooting", to: "/troubleshoot", icon: "✚" },
      { label: "Compliance", to: "/compliance", icon: "✓" },
      { label: "Playbooks", to: "/playbooks", icon: "⛭" },
      { label: "Audit log", to: "/audit", icon: "≡" },
      { label: "Metering", to: "/metering", icon: "▤" },
    ],
  },
  {
    label: "Platform",
    items: [
      { label: "Integrations", to: "/integrations", icon: "⌥" },
      { label: "Terraform / IaC", to: "/terraform", icon: "ⓣ" },
      { label: "API keys", to: "/api-keys", icon: "⚿" },
      { label: "Webhooks", to: "/webhooks", icon: "➶" },
      { label: "RBAC roles", to: "/rbac", icon: "⚖" },
      { label: "SCIM provisioning", to: "/scim", icon: "⇆" },
      { label: "IdP / SSO", to: "/idp", icon: "⛨" },
      { label: "App registry", to: "/app-registry", icon: "▣" },
      { label: "Points of presence", to: "/pops", icon: "◉" },
    ],
  },
  {
    label: "MSP portal",
    items: [
      { label: "MSP hierarchy", to: "/msp", icon: "⧉" },
      { label: "Bulk operations", to: "/msp/bulk", icon: "⨁" },
      { label: "Branding", to: "/msp/branding", icon: "🖌" },
      { label: "Policy templates", to: "/msp/templates", icon: "❒" },
      { label: "MSP RBAC", to: "/msp/rbac", icon: "⚐" },
    ],
  },
];
