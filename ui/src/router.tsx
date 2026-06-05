import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";
import { AppLayout } from "@/components/AppLayout";
import { Login } from "@/routes/Login";
import { OidcCallback } from "@/routes/OidcCallback";
import { Dashboard } from "@/routes/Dashboard";
import { Tenants } from "@/routes/Tenants";
import { Sites } from "@/routes/Sites";
import { Devices } from "@/routes/Devices";
import { Policy } from "@/routes/Policy";
import { NetworkPolicies } from "@/routes/NetworkPolicies";
import { Dlp } from "@/routes/Dlp";
import { Casb } from "@/routes/Casb";
import { Browser } from "@/routes/Browser";
import { Alerts } from "@/routes/Alerts";
import { Assistant } from "@/routes/Assistant";
import { Troubleshoot } from "@/routes/Troubleshoot";
import { Compliance } from "@/routes/Compliance";
import { Playbooks } from "@/routes/Playbooks";
import { Audit } from "@/routes/Audit";
import { Metering } from "@/routes/Metering";
import { Integrations } from "@/routes/Integrations";
import { Terraform } from "@/routes/Terraform";
import { ApiKeys } from "@/routes/ApiKeys";
import { Webhooks } from "@/routes/Webhooks";
import { Rbac } from "@/routes/Rbac";
import { Scim } from "@/routes/Scim";
import { Idp } from "@/routes/Idp";
import { AppRegistry } from "@/routes/AppRegistry";
import { Pops } from "@/routes/Pops";
import { MspHierarchy } from "@/routes/msp/MspHierarchy";
import { MspBulkOps } from "@/routes/msp/MspBulkOps";
import { MspBranding } from "@/routes/msp/MspBranding";
import { MspTemplates } from "@/routes/msp/MspTemplates";
import { MspRbac } from "@/routes/msp/MspRbac";

const rootRoute = createRootRoute({ component: Outlet });

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: Login,
});

const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/auth/callback",
  component: OidcCallback,
});

// Pathless layout route: wraps every authenticated page in the app shell.
const appLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: AppLayout,
});

const page = <P extends string>(path: P, component: () => JSX.Element) =>
  createRoute({ getParentRoute: () => appLayoutRoute, path, component });

const appRoutes = [
  page("/", Dashboard),
  page("/tenants", Tenants),
  page("/sites", Sites),
  page("/devices", Devices),
  page("/policy", Policy),
  page("/network-policies", NetworkPolicies),
  page("/dlp", Dlp),
  page("/casb", Casb),
  page("/browser", Browser),
  page("/alerts", Alerts),
  page("/assistant", Assistant),
  page("/troubleshoot", Troubleshoot),
  page("/compliance", Compliance),
  page("/playbooks", Playbooks),
  page("/audit", Audit),
  page("/metering", Metering),
  page("/integrations", Integrations),
  page("/terraform", Terraform),
  page("/api-keys", ApiKeys),
  page("/webhooks", Webhooks),
  page("/rbac", Rbac),
  page("/scim", Scim),
  page("/idp", Idp),
  page("/app-registry", AppRegistry),
  page("/pops", Pops),
  page("/msp", MspHierarchy),
  page("/msp/bulk", MspBulkOps),
  page("/msp/branding", MspBranding),
  page("/msp/templates", MspTemplates),
  page("/msp/rbac", MspRbac),
];

const routeTree = rootRoute.addChildren([
  loginRoute,
  callbackRoute,
  appLayoutRoute.addChildren(appRoutes),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
