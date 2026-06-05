// Minimal OIDC Authorization Code + PKCE helper.
//
// Production deployments front the control plane with an OIDC IdP
// (config.Auth switches from HMAC JWT verification to OIDC at the
// gateway). The SPA performs the public-client PKCE flow and forwards
// the resulting access token as the `Authorization: Bearer` credential
// the API already understands. No client secret is involved.

import { runtimeConfig } from "@/lib/runtime-config";

interface DiscoveryDocument {
  authorization_endpoint: string;
  token_endpoint: string;
}

const PKCE_VERIFIER_KEY = "sng.pkce_verifier";
const OIDC_STATE_KEY = "sng.oidc_state";

function redirectUri(): string {
  return `${window.location.origin}/auth/callback`;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function sha256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64UrlEncode(new Uint8Array(digest));
}

async function discover(issuer: string): Promise<DiscoveryDocument> {
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`OIDC discovery failed (${res.status})`);
  }
  return (await res.json()) as DiscoveryDocument;
}

/** Kick off the redirect to the IdP authorization endpoint. */
export async function beginOidcLogin(): Promise<void> {
  const cfg = runtimeConfig();
  if (!cfg.oidcIssuer || !cfg.oidcClientId) {
    throw new Error("OIDC issuer / client id not configured");
  }
  const doc = await discover(cfg.oidcIssuer);

  const verifier = randomString();
  const state = randomString(16);
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
  sessionStorage.setItem(OIDC_STATE_KEY, state);

  const challenge = await sha256Challenge(verifier);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.oidcClientId,
    redirect_uri: redirectUri(),
    scope: cfg.oidcScope ?? "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  window.location.assign(`${doc.authorization_endpoint}?${params.toString()}`);
}

/** Complete the flow after the IdP redirects back with `code` + `state`. */
export async function completeOidcLogin(
  search: string,
): Promise<{ accessToken: string }> {
  const cfg = runtimeConfig();
  if (!cfg.oidcIssuer || !cfg.oidcClientId) {
    throw new Error("OIDC issuer / client id not configured");
  }
  const qp = new URLSearchParams(search);
  const code = qp.get("code");
  const returnedState = qp.get("state");
  const error = qp.get("error");
  if (error) throw new Error(`IdP returned error: ${error}`);
  if (!code) throw new Error("Missing authorization code");

  // The state and verifier are single-use: read them, then immediately clear
  // them from storage before doing anything that can throw. This guarantees no
  // failure path — state mismatch, missing verifier, or a failed token
  // exchange — can leave stale PKCE material behind. A retry must restart the
  // flow via beginOidcLogin(), which mints fresh material. (A plain `finally`
  // wouldn't cover the validation throws below, since they run before it.)
  const expectedState = sessionStorage.getItem(OIDC_STATE_KEY);
  const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY);
  sessionStorage.removeItem(OIDC_STATE_KEY);
  sessionStorage.removeItem(PKCE_VERIFIER_KEY);

  if (!returnedState || returnedState !== expectedState) {
    throw new Error("OIDC state mismatch — possible CSRF");
  }
  if (!verifier) throw new Error("Missing PKCE verifier");

  const doc = await discover(cfg.oidcIssuer);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(),
    client_id: cfg.oidcClientId,
    code_verifier: verifier,
  });
  const res = await fetch(doc.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    throw new Error(`Token exchange failed (${res.status})`);
  }
  const tokens = (await res.json()) as { access_token?: string };
  if (!tokens.access_token) {
    throw new Error("Token response missing access_token");
  }
  return { accessToken: tokens.access_token };
}
