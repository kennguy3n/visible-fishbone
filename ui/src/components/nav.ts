// Sidebar navigation model. Each entry maps to a route built in
// `src/router.tsx`. Grouped to mirror the operator mental model:
// overview, the policy/security domains, fleet, operations, and the
// MSP partner portal.

import type { IconName } from "./Icon";

export interface NavItem {
  label: string;
  to: string;
  icon: IconName;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { label: "Dashboard", to: "/", icon: "dashboard" },
      { label: "Get started", to: "/onboarding", icon: "rocket" },
      { label: "Tenants", to: "/tenants", icon: "tenants" },
      { label: "Sites", to: "/sites", icon: "sites" },
      { label: "Devices", to: "/devices", icon: "devices" },
    ],
  },
  {
    label: "Security policy",
    items: [
      { label: "Policy editor", to: "/policy", icon: "policy" },
      { label: "Network policies", to: "/network-policies", icon: "network" },
      { label: "DLP", to: "/dlp", icon: "dlp" },
      { label: "DLP review queue", to: "/dlp/review-queue", icon: "flag" },
      { label: "CASB", to: "/casb", icon: "casb" },
      { label: "Browser protection", to: "/browser", icon: "browser" },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Alerts", to: "/alerts", icon: "alerts" },
      { label: "AI assistant", to: "/assistant", icon: "assistant" },
      { label: "Troubleshooting", to: "/troubleshoot", icon: "troubleshoot" },
      { label: "Compliance", to: "/compliance", icon: "compliance" },
      { label: "Playbooks", to: "/playbooks", icon: "playbooks" },
      { label: "Audit log", to: "/audit", icon: "audit" },
      { label: "Metering", to: "/metering", icon: "metering" },
    ],
  },
  {
    label: "Platform",
    items: [
      { label: "Integrations", to: "/integrations", icon: "integrations" },
      { label: "Terraform / IaC", to: "/terraform", icon: "terraform" },
      { label: "API keys", to: "/api-keys", icon: "key" },
      { label: "Webhooks", to: "/webhooks", icon: "webhooks" },
      { label: "RBAC roles", to: "/rbac", icon: "rbac" },
      { label: "SCIM provisioning", to: "/scim", icon: "scim" },
      { label: "IdP / SSO", to: "/idp", icon: "idp" },
      { label: "App registry", to: "/app-registry", icon: "registry" },
      { label: "Points of presence", to: "/pops", icon: "pops" },
    ],
  },
  {
    label: "MSP portal",
    items: [
      { label: "MSP hierarchy", to: "/msp", icon: "msp" },
      { label: "Bulk operations", to: "/msp/bulk", icon: "bulk" },
      { label: "Branding", to: "/msp/branding", icon: "branding" },
      { label: "Policy templates", to: "/msp/templates", icon: "templates" },
      { label: "MSP RBAC", to: "/msp/rbac", icon: "flag" },
    ],
  },
  {
    label: "Preferences",
    items: [{ label: "Settings", to: "/settings", icon: "settings" }],
  },
];
