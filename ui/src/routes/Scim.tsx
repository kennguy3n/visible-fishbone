import { runtimeConfig } from "@/lib/runtime-config";
import { PageHeader, Card } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";
import { LaneB4Screen, useT } from "./lane-b4-i18n";
import { CopyField } from "./lane-b4-ui";
import type { LaneKey } from "./lane-b4-messages";

// SCIM 2.0 provisioning is push-based: the customer's identity provider
// creates, updates and deletes Users/Groups against the control plane. There
// is no list endpoint, so this page documents the connection details and
// supported changes rather than rendering a resource table.

const RESOURCES: {
  nameKey: LaneKey;
  path: string;
  opsKey: LaneKey;
}[] = [
  { nameKey: "scim.resource.users", path: "/Users", opsKey: "scim.ops.users" },
  { nameKey: "scim.resource.groups", path: "/Groups", opsKey: "scim.ops.groups" },
];

export function Scim() {
  return (
    <LaneB4Screen>
      <ScimInner />
    </LaneB4Screen>
  );
}

function ScimInner() {
  const t = useT();
  const cfg = runtimeConfig();
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const scimBase = `${origin}/scim/v2`;

  return (
    <>
      <PageHeader
        title={t("scim.title")}
        subtitle={t("scim.subtitle")}
        actions={
          <HelpTooltip title={t("scim.help.title")} align="right">
            {t("scim.help.body")}
          </HelpTooltip>
        }
      />
      <div className="grid grid--2">
        <Card title={t("scim.connection.card")}>
          <dl className="kv">
            <dt>{t("scim.field.baseUrl")}</dt>
            <dd>
              <CopyField
                value={scimBase}
                label={t("scim.field.baseUrl")}
                copyLabel={t("scim.copyBaseUrl")}
              />
            </dd>
            <dt>{t("scim.field.auth")}</dt>
            <dd>{t("scim.field.auth.value")}</dd>
            <dt>{t("scim.field.apiBase")}</dt>
            <dd className="mono">{cfg.apiBaseUrl}</dd>
          </dl>
          <p className="field-help" style={{ marginTop: 12 }}>
            {t("scim.connection.help")}
          </p>
        </Card>
        <Card title={t("scim.resources.card")}>
          <table className="data">
            <thead>
              <tr>
                <th scope="col">{t("scim.col.resource")}</th>
                <th scope="col">{t("scim.col.path")}</th>
                <th scope="col">{t("scim.col.operations")}</th>
              </tr>
            </thead>
            <tbody>
              {RESOURCES.map((r) => (
                <tr key={r.path}>
                  <th scope="row">{t(r.nameKey)}</th>
                  <td className="mono">{r.path}</td>
                  <td>{t(r.opsKey)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}
