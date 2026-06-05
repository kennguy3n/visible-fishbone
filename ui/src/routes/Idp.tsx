import { useEffect, useState } from "react";
import { runtimeConfig } from "@/lib/runtime-config";
import { PageHeader, Card, Badge, Spinner } from "@/components/ui";

async function fetchDiscovery(issuer: string): Promise<Record<string, unknown>> {
  const base = issuer.replace(/\/+$/, "");
  const url = base.endsWith("/.well-known/openid-configuration")
    ? base
    : `${base}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Discovery failed (${res.status})`);
  return (await res.json()) as Record<string, unknown>;
}

export function Idp() {
  const cfg = runtimeConfig();
  const [discovery, setDiscovery] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (cfg.authMode !== "oidc" || !cfg.oidcIssuer) return;
    setLoading(true);
    fetchDiscovery(cfg.oidcIssuer)
      .then((d) => setDiscovery(d))
      .catch((e) => setError(e instanceof Error ? e.message : "Discovery failed"))
      .finally(() => setLoading(false));
  }, [cfg.authMode, cfg.oidcIssuer]);

  return (
    <>
      <PageHeader
        title="Identity provider / SSO"
        subtitle="Active authentication mode and OIDC federation metadata."
      />
      <div className="grid grid--2">
        <Card title="Authentication mode">
          <div style={{ marginBottom: 12 }}>
            <Badge tone={cfg.authMode === "oidc" ? "ok" : "info"}>
              {cfg.authMode === "oidc" ? "OIDC / SSO (production)" : "JWT bearer (development)"}
            </Badge>
          </div>
          <dl className="kv">
            <dt>Issuer</dt>
            <dd className="mono">{cfg.oidcIssuer || "—"}</dd>
            <dt>Client ID</dt>
            <dd className="mono">{cfg.oidcClientId || "—"}</dd>
            <dt>Scopes</dt>
            <dd className="mono">{cfg.oidcScope}</dd>
          </dl>
          {cfg.authMode === "jwt" && (
            <p className="muted" style={{ fontSize: 12.5 }}>
              In development the console accepts a pasted HMAC-signed JWT. Set
              <span className="mono"> auth_mode=oidc </span> and the issuer/client
              in runtime config to enable the Authorization Code + PKCE flow.
            </p>
          )}
        </Card>

        <Card title="OIDC discovery">
          {cfg.authMode !== "oidc" ? (
            <p className="muted">OIDC is not the active mode.</p>
          ) : loading ? (
            <Spinner />
          ) : error ? (
            <p className="error-text">{error}</p>
          ) : discovery ? (
            <dl className="kv">
              <dt>Authorization</dt>
              <dd className="mono">{String(discovery.authorization_endpoint ?? "—")}</dd>
              <dt>Token</dt>
              <dd className="mono">{String(discovery.token_endpoint ?? "—")}</dd>
              <dt>JWKS</dt>
              <dd className="mono">{String(discovery.jwks_uri ?? "—")}</dd>
              <dt>Userinfo</dt>
              <dd className="mono">{String(discovery.userinfo_endpoint ?? "—")}</dd>
            </dl>
          ) : (
            <p className="muted">No issuer configured.</p>
          )}
        </Card>
      </div>
    </>
  );
}
