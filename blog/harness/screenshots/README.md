# SNG blog screenshot harness

A reproducible CDP capture harness that regenerates the console screenshots in
[`../../artifacts/screenshots/`](../../artifacts/screenshots/) from the live
admin console, so the showcase blog always reflects the current ShieldNet 360
branding and the seeded nine-tenant fleet.

It drives the real UI (Vite dev server on `:5173`, proxied to the Go control
plane on `:8080`) with Playwright/Chromium: mints a global platform-admin JWT
signed with `AUTH_JWT_SECRET`, injects it into `sessionStorage` before the app
boots, pins the dark theme + English locale, selects each tenant through the
real header dropdown (firing the React `onChange`), drives the Policy
simple/advanced + graph/json toggles where needed, parks the pointer off-content
so no hover tooltip leaks into a frame, and writes PNGs at the committed
viewports (1568×993 for the regular set, 1600×1200 for the wider `scenario-*`
and `overview-dashboard` frames).

## Prerequisites

The full stack must be up and the fleet seeded — the same preconditions as the
other blog harnesses (see [`../../posts/README.md`](../../posts/README.md) →
"Reproducing the artifacts"):

```bash
docker compose up -d                 # Postgres + NATS
go run ./cmd/sng-migrate up          # migrations (provision sng_app first — see docs/deploy.md)
go run ./cmd/sng-control             # control plane on :8080
(cd ui && npm install && npm run dev)# console on :5173

# Seed the fleet + drive the data the screenshots depend on:
(cd blog/harness/seed      && AUTH_JWT_SECRET=… go run .)
(cd blog/harness/usage     && AUTH_JWT_SECRET=… go run .)
(cd blog/harness/anomalies && AUTH_JWT_SECRET=… go run .)
(cd blog/harness/casb      && AUTH_JWT_SECRET=… go run .)   # CASB NoOps shadow-IT findings
(cd blog/harness/newcaps   && AUTH_JWT_SECRET=… go run .)   # DEM + compliance + app-registry data
```

## Install (one-time)

```bash
cd blog/harness/screenshots
npm install
npx playwright install chromium
```

`npm install` and the browser download are heavy; on a disk-constrained
machine point the caches elsewhere:

```bash
npm_config_cache=/path npm install
PLAYWRIGHT_BROWSERS_PATH=/path npx playwright install chromium
```

## Capture

```bash
AUTH_JWT_SECRET=… node capture.mjs                       # every screenshot
AUTH_JWT_SECRET=… node capture.mjs --only=s2-policy-graph.png,alerts
AUTH_JWT_SECRET=… node capture.mjs --base http://localhost:5173
```

Output goes to `blog/artifacts/screenshots/`. The catalogue of shots (file →
route, tenant, view toggles) lives in `capture.mjs` as the `SHOTS` array — add
or edit an entry there to capture a new surface or change a tenant.

## Notes

- The tenant UUIDs are pinned by `blog/harness/seed` (canonical fixture
  identities) so captures stay reproducible across reseeds.
- The originals were shot in dark mode; this harness pins `--theme=dark` for
  palette consistency.
- PNG file sizes differ from the prior set partly because the ShieldNet 360
  brand refresh (the `--on-brand` migration + brand-solid/on-brand split) changed
  on-screen colours and partly because Playwright's PNG encoder compresses
  differently from the CDP tool that produced the originals. The dimensions
  (1568×993 / 1600×1200) are preserved.
