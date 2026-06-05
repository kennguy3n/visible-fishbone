import { runtimeConfig } from "@/lib/runtime-config";
import { PageHeader, Card, Badge } from "@/components/ui";

// SCIM 2.0 provisioning is push-based: the customer IdP creates,
// updates and deletes Users/Groups against the control plane. There
// is no list endpoint, so this page documents the connection details
// and supported operations rather than rendering a resource table.

const RESOURCES = [
  { name: "Users", path: "/Users", ops: "POST · PUT · PATCH · DELETE" },
  { name: "Groups", path: "/Groups", ops: "POST · PUT · PATCH · DELETE" },
];

export function Scim() {
  const cfg = runtimeConfig();
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const scimBase = `${origin}/scim/v2`;

  return (
    <>
      <PageHeader
        title="SCIM provisioning"
        subtitle="System for Cross-domain Identity Management 2.0 — IdP-driven user lifecycle."
      />
      <div className="grid grid--2">
        <Card title="Connection">
          <dl className="kv">
            <dt>SCIM base URL</dt>
            <dd className="mono">{scimBase}</dd>
            <dt>Token endpoint</dt>
            <dd className="mono">Bearer (provisioned per IdP)</dd>
            <dt>API base</dt>
            <dd className="mono">{cfg.apiBaseUrl}</dd>
          </dl>
          <p className="muted" style={{ fontSize: 12.5 }}>
            Configure this base URL and a provisioning bearer token in your
            identity provider (Okta, Entra ID, etc). The control plane validates
            each request and reconciles users into tenant directories.
          </p>
        </Card>
        <Card title="Supported resources">
          <table className="data">
            <thead>
              <tr>
                <th>Resource</th>
                <th>Path</th>
                <th>Operations</th>
              </tr>
            </thead>
            <tbody>
              {RESOURCES.map((r) => (
                <tr key={r.name}>
                  <td>
                    <Badge tone="info">{r.name}</Badge>
                  </td>
                  <td className="mono">{r.path}</td>
                  <td className="mono">{r.ops}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}
