// Runtime configuration.
//
// The static nginx container injects values at container start by
// writing `window.__SNG_CONFIG__` into `config.js` (see
// `ui/docker/docker-entrypoint.sh`). This lets a single immutable image
// be promoted across environments — the API endpoint and OIDC settings
// are supplied at deploy time, not baked into the bundle.
//
// During local `vite dev` the global is absent, so we fall back to
// build-time Vite env vars and finally to same-origin defaults (the
// dev server proxies `/api` to a local sng-control).

export interface SngRuntimeConfig {
  /** Base URL of the control-plane API, including the `/api/v1` suffix. */
  apiBaseUrl: string;
  /** Authentication mode: HMAC bearer JWT (dev) or OIDC redirect (prod). */
  authMode: "jwt" | "oidc";
  /** OIDC issuer discovery URL (authMode === "oidc"). */
  oidcIssuer?: string;
  /** OIDC public client id (authMode === "oidc"). */
  oidcClientId?: string;
  /** OIDC scopes; defaults to "openid profile email". */
  oidcScope?: string;
}

declare global {
  interface Window {
    __SNG_CONFIG__?: Partial<SngRuntimeConfig>;
  }
}

const viteEnv = import.meta.env;

function resolveConfig(): SngRuntimeConfig {
  const injected = (typeof window !== "undefined" && window.__SNG_CONFIG__) || {};

  const apiBaseUrl =
    injected.apiBaseUrl ||
    (viteEnv.VITE_API_BASE_URL as string | undefined) ||
    "/api/v1";

  const authMode: SngRuntimeConfig["authMode"] =
    injected.authMode ||
    (viteEnv.VITE_AUTH_MODE as SngRuntimeConfig["authMode"] | undefined) ||
    "jwt";

  return {
    apiBaseUrl: apiBaseUrl.replace(/\/+$/, ""),
    authMode,
    oidcIssuer:
      injected.oidcIssuer || (viteEnv.VITE_OIDC_ISSUER as string | undefined),
    oidcClientId:
      injected.oidcClientId ||
      (viteEnv.VITE_OIDC_CLIENT_ID as string | undefined),
    oidcScope:
      injected.oidcScope ||
      (viteEnv.VITE_OIDC_SCOPE as string | undefined) ||
      "openid profile email",
  };
}

let cached: SngRuntimeConfig | null = null;

export function runtimeConfig(): SngRuntimeConfig {
  if (!cached) {
    cached = resolveConfig();
  }
  return cached;
}
