import { useCallback, useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { runtimeConfig } from "@/lib/runtime-config";
import {
  PageHeader,
  Card,
  Badge,
  LoadingState,
  EmptyState,
  EmptyIllustration,
} from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { LaneB4Screen, useT } from "./lane-b4-i18n";

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
  return (
    <LaneB4Screen>
      <IdpInner />
    </LaneB4Screen>
  );
}

function IdpInner() {
  const t = useT();
  const cfg = runtimeConfig();
  const [discovery, setDiscovery] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<boolean>(false);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    if (cfg.authMode !== "oidc" || !cfg.oidcIssuer) return;
    setLoading(true);
    setError(false);
    fetchDiscovery(cfg.oidcIssuer)
      .then((d) => setDiscovery(d))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, [cfg.authMode, cfg.oidcIssuer]);

  useEffect(() => {
    load();
  }, [load]);

  const isOidc = cfg.authMode === "oidc";

  return (
    <>
      <PageHeader
        title={t("idp.title")}
        subtitle={t("idp.subtitle")}
        actions={
          <HelpTooltip title={t("idp.help.title")} align="right">
            {t("idp.help.body")}
          </HelpTooltip>
        }
      />
      <div className="grid grid--2">
        <Card title={t("idp.mode.card")}>
          <div style={{ marginBottom: 12 }}>
            <Badge tone={isOidc ? "ok" : "info"} dot>
              {isOidc ? t("idp.mode.oidc") : t("idp.mode.jwt")}
            </Badge>
          </div>
          <dl className="kv">
            <dt>{t("idp.field.issuer")}</dt>
            <dd className="mono">{cfg.oidcIssuer || "—"}</dd>
            <dt>{t("idp.field.clientId")}</dt>
            <dd className="mono">{cfg.oidcClientId || "—"}</dd>
            <dt>{t("idp.field.scopes")}</dt>
            <dd className="mono">{cfg.oidcScope}</dd>
          </dl>
          {!isOidc && (
            <p className="field-help" style={{ marginTop: 12 }}>
              {t("idp.jwt.help")}
            </p>
          )}
        </Card>

        <Card title={t("idp.discovery.card")}>
          {!isOidc ? (
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("idp.empty.title")}
              description={t("idp.empty.desc")}
              action={
                <Link to="/onboarding/guided" className="btn btn--primary btn--sm">
                  {t("idp.empty.action")}
                </Link>
              }
            />
          ) : loading ? (
            <LoadingState label={t("idp.discovery.loading")} />
          ) : error ? (
            <EmptyState
              illustration={<EmptyIllustration kind="alert" />}
              title={t("idp.discovery.errorTitle")}
              description={t("idp.discovery.errorDesc")}
              action={
                <button className="btn btn--sm" onClick={load}>
                  {t("b4.action.retry")}
                </button>
              }
            />
          ) : discovery ? (
            <dl className="kv">
              <dt>{t("idp.discovery.authorization")}</dt>
              <dd className="mono">{String(discovery.authorization_endpoint ?? "—")}</dd>
              <dt>{t("idp.discovery.token")}</dt>
              <dd className="mono">{String(discovery.token_endpoint ?? "—")}</dd>
              <dt>{t("idp.discovery.jwks")}</dt>
              <dd className="mono">{String(discovery.jwks_uri ?? "—")}</dd>
              <dt>{t("idp.discovery.userinfo")}</dt>
              <dd className="mono">{String(discovery.userinfo_endpoint ?? "—")}</dd>
            </dl>
          ) : (
            <EmptyState
              illustration={<EmptyIllustration kind="shield" />}
              title={t("idp.empty.title")}
              description={t("idp.empty.desc")}
              action={
                <Link to="/onboarding/guided" className="btn btn--primary btn--sm">
                  {t("idp.empty.action")}
                </Link>
              }
            />
          )}
        </Card>
      </div>
    </>
  );
}
