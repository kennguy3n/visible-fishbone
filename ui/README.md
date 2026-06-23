# ShieldNet Gateway — Admin UI / MSP Portal

A Vite + React + TypeScript single-page app for the SNG control plane. It
covers the full admin surface (tenants, sites, devices, policy, DLP, CASB,
browser protection / RBI, AI governance, ZTNA (agent + clientless), DEM,
alerts, compliance, playbooks, integrations, metering, audit, etc.) and the
MSP portal (hierarchy, bulk operations, white-label branding, policy
templates, MSP-scoped RBAC).

## Stack

- **Vite 5** + **React 18** + **TypeScript 5**
- **TanStack Router v1** — type-safe routing
- **TanStack Query v5** — server state / caching
- **Recharts** — metrics & anomaly charts
- **@xyflow/react (React Flow)** — policy graph visualization
- **Axios** — HTTP client with auth + tenant interceptors
- **orval** — generates React Query hooks + models from `../api/openapi.yaml`

## Project layout

```
ui/
├── src/
│   ├── api/
│   │   ├── http-client.ts        # axios instance + sngRequest() used by hooks
│   │   ├── generated/            # orval output (DO NOT edit by hand)
│   │   └── manual/               # hand-written hooks for endpoints not in openapi.yaml
│   ├── auth/                     # JWT (dev) + OIDC/PKCE (prod) flows
│   ├── components/               # AppLayout, DataTable, Modal, shared UI
│   ├── lib/                      # runtime config, tenant context, formatters
│   ├── routes/                   # one component per admin page
│   │   └── msp/                  # MSP portal pages
│   ├── router.tsx                # TanStack Router route tree
│   └── main.tsx                  # entrypoint (providers + router)
├── docker/                       # nginx.conf + runtime-config entrypoint
├── helm/                         # static-serve Helm chart
├── Dockerfile                    # multi-stage build → nginx static serve
└── orval.config.ts
```

## Local development

```bash
make ui-install      # npm install
make ui-dev          # vite dev server on http://localhost:5173
```

The dev server proxies `/api` to a local `sng-control` (default
`http://localhost:8080`). Override via `VITE_API_BASE_URL`.

Other targets (from the repo root):

```bash
make ui-lint         # eslint
make ui-typecheck    # tsc -b --noEmit
make ui-build        # tsc -b && vite build → dist/
make ui-gen-api      # regenerate the OpenAPI client from ../api/openapi.yaml
make ui-docker       # build the nginx container image
```

## Authentication

Auth mode is chosen at runtime (`window.__SNG_CONFIG__.authMode`):

- **`jwt`** (default, dev): an HMAC-signed bearer token is pasted/stored and
  attached to every request. Matches the dev auth path in
  `internal/config/config.go`.
- **`oidc`** (prod): Authorization Code + PKCE redirect against the configured
  issuer; tokens are refreshed and attached automatically.

## Runtime configuration

The built bundle is environment-agnostic. Deploy-time config is served from
`/config.js`, which sets `window.__SNG_CONFIG__`. In the container,
`docker/docker-entrypoint.sh` regenerates `/config.js` from environment
variables at start, so one immutable image is promoted across environments:

| Env var              | `window.__SNG_CONFIG__` key | Default               |
| -------------------- | --------------------------- | --------------------- |
| `SNG_API_BASE_URL`   | `apiBaseUrl`                | `/api/v1`             |
| `SNG_AUTH_MODE`      | `authMode`                  | `jwt`                 |
| `SNG_OIDC_ISSUER`    | `oidcIssuer`                | (empty)               |
| `SNG_OIDC_CLIENT_ID` | `oidcClientId`              | (empty)               |
| `SNG_OIDC_SCOPE`     | `oidcScope`                 | `openid profile email`|

During `vite dev` the committed `public/config.js` default is served and the
app falls back to Vite env vars / the dev proxy.

## Container / Helm

```bash
docker build -t sng-ui:dev ui/
docker run -p 8080:8080 -e SNG_API_BASE_URL=https://api.example.com/api/v1 sng-ui:dev
```

Deploy with the bundled chart:

```bash
helm upgrade --install sng-ui ui/helm \
  --set image.repository=ghcr.io/kennguy3n/sng-ui \
  --set config.apiBaseUrl=https://api.example.com/api/v1
```
