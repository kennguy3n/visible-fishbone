// Access-token storage shared by the auth context and the HTTP client.
//
// The token is kept in module state (fast, synchronous reads on every
// request) and mirrored to sessionStorage so a full-page reload — e.g.
// returning from an OIDC redirect — does not drop the session. We use
// sessionStorage rather than localStorage so the token does not outlive
// the browser tab, narrowing the exfiltration window.

const STORAGE_KEY = "sng.access_token";

let accessToken: string | null = readInitial();

function readInitial(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(STORAGE_KEY);
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
  if (typeof sessionStorage === "undefined") return;
  if (token) {
    sessionStorage.setItem(STORAGE_KEY, token);
  } else {
    sessionStorage.removeItem(STORAGE_KEY);
  }
}

export function clearAccessToken(): void {
  setAccessToken(null);
}
