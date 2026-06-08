import type { SVGProps } from "react";

/**
 * Crisp inline SVG icon set (Lucide-style, 24x24, stroke, inherits
 * `currentColor`). Replaces the unicode-glyph icons the sidebar used to
 * render, which looked inconsistent across platforms. Each nav entry and
 * several UI affordances reference an icon by semantic `name`.
 */
export type IconName =
  | "dashboard"
  | "rocket"
  | "tenants"
  | "sites"
  | "devices"
  | "policy"
  | "network"
  | "dlp"
  | "casb"
  | "browser"
  | "alerts"
  | "assistant"
  | "troubleshoot"
  | "compliance"
  | "playbooks"
  | "audit"
  | "metering"
  | "integrations"
  | "terraform"
  | "key"
  | "webhooks"
  | "rbac"
  | "scim"
  | "idp"
  | "registry"
  | "pops"
  | "msp"
  | "bulk"
  | "branding"
  | "templates"
  | "flag"
  | "menu"
  | "logout"
  | "search"
  | "plus"
  | "chevron-down";

// Each value is the inner markup of a 24x24 viewBox icon. Kept as small,
// recognizable line shapes so they read well at 16-18px in the nav rail.
const PATHS: Record<IconName, JSX.Element> = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  rocket: (
    <>
      <path d="M4.5 16.5c-1.5 1.3-2 5-2 5s3.7-.5 5-2c.7-.8.7-2 0-2.8a2 2 0 0 0-3 0Z" />
      <path d="M12 15 9 12a13 13 0 0 1 7-9 11 11 0 0 1 5-1 11 11 0 0 1-1 5 13 13 0 0 1-9 7Z" />
      <path d="M9 12H5a1 1 0 0 1-.6-1.7l3-3a2 2 0 0 1 1.4-.6h2.5M12 15v4a1 1 0 0 0 1.7.6l3-3a2 2 0 0 0 .6-1.4V12" />
    </>
  ),
  tenants: (
    <>
      <path d="M3 21h18" />
      <path d="M5 21V7l7-4 7 4v14" />
      <path d="M9 9h.01M9 13h.01M9 17h.01M15 9h.01M15 13h.01M15 17h.01" />
    </>
  ),
  sites: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  devices: (
    <>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <path d="M2 20h20" />
    </>
  ),
  policy: (
    <>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="6" cy="18" r="2.5" />
      <circle cx="18" cy="12" r="2.5" />
      <path d="M6 8.5v7M8.3 7.2 15.7 11M8.3 16.8 15.7 13" />
    </>
  ),
  network: (
    <>
      <path d="M4 8h12l-3-3M20 16H8l3 3" />
    </>
  ),
  dlp: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
      <path d="M14 3v5h5" />
      <rect x="9" y="12" width="6" height="5" rx="1" />
      <path d="M10.5 12v-1.2a1.5 1.5 0 0 1 3 0V12" />
    </>
  ),
  casb: (
    <>
      <path d="M7 18a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.4A3.5 3.5 0 0 1 18 18Z" />
    </>
  ),
  browser: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z" />
    </>
  ),
  alerts: (
    <>
      <path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 0 1-3.4 0" />
    </>
  ),
  assistant: (
    <>
      <path d="M12 3l1.8 4.7L18.5 9l-4.7 1.8L12 15l-1.8-4.2L5.5 9l4.7-1.3Z" />
      <path d="M18 15l.9 2.1L21 18l-2.1.9L18 21l-.9-2.1L15 18l2.1-.9Z" />
    </>
  ),
  troubleshoot: (
    <>
      <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4l-6 6a1.5 1.5 0 0 0 2 2l6-6a4 4 0 0 0 5.4-5.4l-2.3 2.3-2-2Z" />
    </>
  ),
  compliance: (
    <>
      <path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6Z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  playbooks: (
    <>
      <path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2Z" />
      <path d="M19 19v2H6a2 2 0 0 1-2-2" />
      <path d="M9 7h6M9 10h6" />
    </>
  ),
  audit: (
    <>
      <path d="M4 6h16M4 12h16M4 18h10" />
    </>
  ),
  metering: (
    <>
      <path d="M3 20a9 9 0 1 1 18 0" />
      <path d="M12 20l4-6" />
      <path d="M3 20h18" />
    </>
  ),
  integrations: (
    <>
      <path d="M9 3v5M15 3v5" />
      <path d="M7 8h10v3a5 5 0 0 1-10 0Z" />
      <path d="M12 16v5" />
    </>
  ),
  terraform: (
    <>
      <path d="M12 3 3 7.5 12 12l9-4.5Z" />
      <path d="M3 12l9 4.5L21 12" />
      <path d="M3 16.5 12 21l9-4.5" />
    </>
  ),
  key: (
    <>
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.5 12.5 20 3M16 7l3 3M14 9l2 2" />
    </>
  ),
  webhooks: (
    <>
      <path d="M9 8a3 3 0 1 1 4 2.8L10 16" />
      <circle cx="6" cy="18" r="3" />
      <circle cx="18" cy="16" r="3" />
      <path d="M9 18h6.2M14 10l2.5 4.3" />
    </>
  ),
  rbac: (
    <>
      <path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6Z" />
      <circle cx="12" cy="10" r="2" />
      <path d="M9 16c0-1.7 1.3-3 3-3s3 1.3 3 3" />
    </>
  ),
  scim: (
    <>
      <path d="M4 12a8 8 0 0 1 14-5.3L20 8" />
      <path d="M20 4v4h-4" />
      <path d="M20 12a8 8 0 0 1-14 5.3L4 16" />
      <path d="M4 20v-4h4" />
    </>
  ),
  idp: (
    <>
      <path d="M12 2a5 5 0 0 0-5 5c0 1 .2 2 .5 3M12 8v5M7 21c-1-2-1.5-4-1.5-6M17 7c0 5 0 9-2 13M12 12c0 4-.5 6-1.5 8" />
    </>
  ),
  registry: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  pops: (
    <>
      <circle cx="12" cy="10" r="3" />
      <path d="M12 21c5-5 7-8 7-11a7 7 0 1 0-14 0c0 3 2 6 7 11Z" />
    </>
  ),
  msp: (
    <>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="19" r="2.5" />
      <circle cx="19" cy="19" r="2.5" />
      <path d="M12 7.5V12M12 12 6.5 17M12 12l5.5 5" />
    </>
  ),
  bulk: (
    <>
      <path d="M12 3 3 7.5 12 12l9-4.5Z" />
      <path d="M5 11l7 3.5L19 11M5 15l7 3.5L19 15" />
    </>
  ),
  branding: (
    <>
      <path d="M12 3a9 9 0 0 0 0 18c1.7 0 2-1.3 1.2-2.2-.8-1-.3-2.3 1-2.3H18a3 3 0 0 0 3-3c0-4.4-4-7.5-9-7.5Z" />
      <circle cx="7.5" cy="11" r="1" />
      <circle cx="12" cy="8" r="1" />
      <circle cx="16.5" cy="11" r="1" />
    </>
  ),
  templates: (
    <>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
    </>
  ),
  flag: (
    <>
      <path d="M5 21V4M5 4h11l-2 4 2 4H5" />
    </>
  ),
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  logout: (
    <>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5M21 12H9" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  "chevron-down": <path d="M6 9l6 6 6-6" />,
};

export function Icon({
  name,
  size = 18,
  ...rest
}: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, "name">) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {PATHS[name]}
    </svg>
  );
}
