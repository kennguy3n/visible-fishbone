// CDP capture harness for the ShieldNet Gateway blog screenshots.
//
// Drives the live admin console (Vite dev server on :5173, proxied to the
// Go control plane on :8080) against the seeded nine-tenant fleet and writes
// PNGs into blog/artifacts/screenshots so the showcase blog shows the current
// ShieldNet 360 branding.
//
// Auth: mints a short-lived global platform-admin JWT (HS256) signed with
// AUTH_JWT_SECRET — the same token shape the seed harness
// (blog/harness/seed) mints — and injects it into sessionStorage before the
// app boots, so the route guard never bounces us to /login.
//
// Theme: forces the dark theme via localStorage["sng-theme"] = "dark" so the
// set is palette-consistent (the originals were shot in dark mode).
//
// Tenant: selected through the real header tenant dropdown (firing the React
// onChange), matching how the committed screenshots were captured, so the
// on-screen data is pixel-consistent with the seeded payloads.
//
// Usage:
//   AUTH_JWT_SECRET=... node capture.mjs                # capture every shot
//   AUTH_JWT_SECRET=... node capture.mjs --only s2-policy-graph.png,alerts
//   AUTH_JWT_SECRET=... node capture.mjs --base http://localhost:5173
//
// Reproducible: deterministic tenant UUIDs come from the seed harness, the
// theme is pinned, and the pointer is parked off-content so no hover tooltip
// leaks into a frame.

import { createHmac } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";

const ROOT = path.resolve(import.meta.dirname, "../../..");
const OUT_DIR = path.join(ROOT, "blog/artifacts/screenshots");

const CONSOLE_BASE = process.env.SNG_CONSOLE_BASE ?? "http://localhost:5173";
const SECRET = process.env.AUTH_JWT_SECRET ?? "";
const OPERATOR = "190fc952-71ff-4ad5-a0fa-68b78ec39fca";

if (!SECRET) {
  console.error("fatal: AUTH_JWT_SECRET is unset (set it to the control-plane JWT secret)");
  process.exit(1);
}

// --- Canonical tenant UUIDs (pinned by blog/harness/seed) -----------------
const TENANTS = {
  acme: "92112770-7c0a-410b-b0f4-09dde70e063a",
  globex: "3bd7bb7b-d48a-4569-8f97-46be31ae8e5a",
  initech: "b6520bda-e7bb-4af9-9c53-7b0051eae65b",
  umbrella: "0c8d2d9d-896d-45b1-8001-6a6776f832b9",
  britannia: "2d0935d3-8c57-4f66-a5a9-0de368f16a7c",
  maple: "cef9c934-507c-4adc-985b-48f3cbe274b0",
  outback: "37619610-53b4-4eab-87f9-45ba902d30c2",
  lumiere: "890486df-98bd-482b-85a8-af361706676f",
  nordic: "8c93e8b9-5710-4f3a-9981-6d2c558bb78f",
};

// Viewport matching the committed set: 1568x993 for the regular captures,
// 1600x1200 for the wider scenario-* frames.
const VP = { width: 1568, height: 993 };
const VP_WIDE = { width: 1600, height: 1200 };

// --- JWT (HS256, base64url, no padding) — mirrors seed/mintGlobalAdminJWT -
function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function mintJwt(secret, sub) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: "sng-control",
    aud: "sng-control",
    sub,
    email: "operator@shieldnet.dev",
    name: "Platform Operator",
    roles: ["platform_admin"],
    iat: now,
    nbf: now,
    exp: now + 6 * 3600,
  };
  const body = b64url(JSON.stringify(claims));
  const seg = `${header}.${body}`;
  const sig = b64url(createHmac("sha256", secret).update(seg).digest());
  return `${seg}.${sig}`;
}

// --- Shot catalogue -------------------------------------------------------
// Each entry: { file, path, tenant?, wide?, actions?, scrollToSelector?,
//   dlpSection?, assistantQuery?, fullPage? }
// `actions` is a list of { click: cssSelector, nth?: number } applied in order
// after the page settles (used for the Policy simple/advanced + graph/json
// toggles).
const SHOTS = [
  // --- Dashboard / fleet -------------------------------------------------
  { file: "overview-dashboard.png", path: "/", tenant: "acme", wide: true },
  { file: "refresh-dashboard-fleet.png", path: "/", tenant: "acme" },
  { file: "scenario-00-dashboard-fleet.png", path: "/", tenant: "acme", wide: true },

  // --- S1: multi-tenant / MSP -------------------------------------------
  { file: "s1-tenants.png", path: "/tenants", tenant: "acme" },
  { file: "scenario-01-tenants-multicountry.png", path: "/tenants", tenant: "acme", wide: true },
  { file: "s1-msp-hierarchy.png", path: "/msp", tenant: "acme" },
  { file: "s1-audit-log.png", path: "/audit", tenant: "acme" },

  // --- S2: typed policy graph -------------------------------------------
  { file: "s2-sites.png", path: "/sites", tenant: "acme" },
  { file: "s2-devices.png", path: "/devices", tenant: "acme" },
  // Simple editor = default mode.
  { file: "s2-policy-editor-simple.png", path: "/policy", tenant: "acme" },
  { file: "scenario-02-policy-editor-6verbs.png", path: "/policy", tenant: "acme", wide: true },
  // Advanced -> Graph tab (default advanced tab).
  { file: "s2-policy-graph.png", path: "/policy", tenant: "acme", actions: [{ click: ".mode-toggle button", nth: 1 }] },
  { file: "s2-policy-graph-advanced.png", path: "/policy", tenant: "acme", actions: [{ click: ".mode-toggle button", nth: 1 }] },
  { file: "scenario-03-policy-graph-advanced.png", path: "/policy", tenant: "acme", wide: true, actions: [{ click: ".mode-toggle button", nth: 1 }] },
  // Advanced -> JSON tab.
  { file: "s2-policy-json.png", path: "/policy", tenant: "acme", actions: [{ click: ".mode-toggle button", nth: 1 }, { click: ".pill-tabs button[role='tab']", nth: 1 }] },
  { file: "scenario-05-policy-json-sla.png", path: "/policy", tenant: "acme", wide: true, actions: [{ click: ".mode-toggle button", nth: 1 }, { click: ".pill-tabs button[role='tab']", nth: 1 }] },
  { file: "new-cross-tenant-rollout.png", path: "/policy/rollout", tenant: "acme" },

  // --- S3: detection efficacy / alerts ----------------------------------
  { file: "s3-alerts.png", path: "/alerts", tenant: "acme" },
  { file: "s3-alerts-anomaly-scatter.png", path: "/alerts", tenant: "acme", scrollToSelector: "canvas" },

  // --- S4: ZTNA / posture ------------------------------------------------
  { file: "s4-devices-posture.png", path: "/devices", tenant: "acme" },

  // --- S5: DLP / CASB / RBI ----------------------------------------------
  // /dlp renders Templates (top) -> Sandbox -> Policies (bottom) as one page.
  { file: "s5-dlp-templates.png", path: "/dlp", tenant: "acme" },
  { file: "s5-dlp-classifier-sandbox.png", path: "/dlp", tenant: "acme", scrollToText: "sandbox", runDlpSandbox: true },
  { file: "s5-dlp-policies.png", path: "/dlp", tenant: "acme", scrollToText: "policies" },
  { file: "new-dlp-review-queue.png", path: "/dlp/review-queue", tenant: "acme" },
  { file: "scenario-04-dlp-review-queue.png", path: "/dlp/review-queue", tenant: "acme", wide: true },
  { file: "s5-casb-connectors.png", path: "/casb", tenant: "acme", scrollToText: "connectors" },
  { file: "new-casb-noops-shadow-it.png", path: "/casb", tenant: "acme" },
  { file: "s5-browser-policies.png", path: "/browser", tenant: "acme", scrollToText: "policies" },
  { file: "s5-browser-isolation.png", path: "/browser", tenant: "acme" },

  // --- S6: AI-assisted ops -----------------------------------------------
  { file: "s6-assistant.png", path: "/assistant", tenant: "acme" },
  { file: "s6-assistant-nl-policy-query.png", path: "/assistant", tenant: "acme", assistantPolicyQuery: true },
  { file: "s6-playbooks.png", path: "/playbooks", tenant: "acme" },

  // --- S7: cost / metering -----------------------------------------------
  // Fleet view: the platform-admin fleet table renders regardless of the
  // selected tenant. "top" = top of the page; "table" = scrolled to the fleet
  // table card.
  { file: "new-metering-fleet-top.png", path: "/metering", tenant: "acme" },
  { file: "new-metering-fleet-table.png", path: "/metering", tenant: "acme", scrollToText: "fleet" },
  { file: "s7-metering-acme.png", path: "/metering", tenant: "acme" },
  { file: "s7-metering-globex.png", path: "/metering", tenant: "globex" },
  { file: "s7-metering-initech.png", path: "/metering", tenant: "initech" },
  { file: "s7-metering-umbrella.png", path: "/metering", tenant: "umbrella" },

  // --- WS10a: identity / app registry ------------------------------------
  { file: "ws10a-idp-directory.png", path: "/idp", tenant: "acme" },
  { file: "ws10a-app-registry.png", path: "/app-registry", tenant: "acme" },

  // --- Other surfaces referenced across the series -----------------------
  { file: "refresh-compliance.png", path: "/compliance", tenant: "acme" },
  { file: "new-msp-cross-tenant-templates.png", path: "/msp/templates", tenant: "acme" },
  { file: "new-pops-topology.png", path: "/pops", tenant: "acme" },
  { file: "new-guided-onboarding-wizard.png", path: "/onboarding/guided", tenant: "acme" },
];

// --- CLI filtering --------------------------------------------------------
const onlyArg = process.argv.find((a) => a.startsWith("--only="));
const only = onlyArg ? onlyArg.slice(7).split(",").map((s) => s.trim()).filter(Boolean) : null;
const baseArgIdx = process.argv.indexOf("--base");
if (baseArgIdx !== -1 && process.argv[baseArgIdx + 1]) {
  // override via CLI
  process.env.SNG_CONSOLE_BASE = process.argv[baseArgIdx + 1];
}
const CONSOLE = process.env.SNG_CONSOLE_BASE ?? CONSOLE_BASE;

let shots = SHOTS;
if (only) {
  shots = SHOTS.filter((s) => only.some((o) => s.file.includes(o) || o.includes(s.file)));
}

// --- Helpers --------------------------------------------------------------
async function settle(page) {
  // Wait for the app shell (authenticated) and for async data to land.
  await page.waitForSelector(".app-shell", { state: "visible", timeout: 20000 });
  // Let any in-flight queries + charts settle. networkidle covers the bulk;
  // the extra waits clear spinners/skeletons and let Recharts/ReactFlow paint.
  await page.waitForLoadState("networkidle", { timeout: 20000 }).catch(() => {});
  await page.waitForFunction(
    () => {
      const live = document.querySelectorAll(".spinner, .skeleton, .skeleton-row, .skeleton-card");
      return live.length === 0;
    },
    { timeout: 20000 },
  ).catch(() => {});
  // Recharts/ReactFlow need a tick after data lands to paint canvases/SVG.
  await page.waitForTimeout(900);
}

async function selectTenant(page, tenantId) {
  if (!tenantId) return;
  const sel = ".tenant-switcher select";
  await page.waitForSelector(sel, { state: "visible", timeout: 20000 });
  // Wait until the dropdown is populated with the target tenant.
  await page.waitForFunction(
    (id) => {
      const el = document.querySelector(".tenant-switcher select");
      return !!el && Array.from(el.options).some((o) => o.value === id);
    },
    tenantId,
    { timeout: 20000 },
  ).catch(() => {});
  await page.selectOption(sel, tenantId);
  // Let the tenant-scoped queries refetch.
  await page.waitForTimeout(700);
}

async function parkPointer(page) {
  // Move the pointer onto a non-interactive chrome area so no data-viz /
  // row hover tooltip leaks into the frame.
  await page.mouse.move(8, 8);
}

async function applyActions(page, actions) {
  for (const a of actions ?? []) {
    if (a.click) {
      const els = await page.$$(a.click);
      const target = a.nth != null ? els[a.nth] : els[0];
      if (target) {
        await target.click();
        await page.waitForTimeout(600);
      }
    }
  }
}

async function scrollToTextFn(page, needle) {
  if (!needle) return;
  const lower = needle.toLowerCase();
  await page.evaluate((l) => {
    const heads = Array.from(document.querySelectorAll("h2, h3, .card__title, .card__heading, legend, .page-header__title"));
    const hit = heads.find((h) => h.textContent && h.textContent.toLowerCase().includes(l));
    if (hit) hit.scrollIntoView({ block: "start" });
  }, lower);
  await page.waitForTimeout(500);
}

async function runDlpSandbox(page) {
  // Type a sample containing a credit-card-shaped number and run the
  // classifier so the sandbox shows a deterministic "flagged" verdict.
  const textarea = await page.$(".dlp-sandbox textarea, textarea[placeholder*='sample' i], .sandbox textarea");
  if (textarea) {
    await textarea.fill("Card on file: 4111-1111-1111-1111, exp 03/27.");
    const runBtn = await page.$("button:not([disabled])");
    // The Run button is the one next to the sandbox textarea; click the last
    // enabled button in the sandbox card.
    const btns = await page.$$(".sandbox button, .dlp-sandbox button");
    const run = btns[btns.length - 1];
    if (run) {
      await run.click();
      await page.waitForTimeout(1200);
    }
  }
}

async function runAssistantPolicyQuery(page) {
  // Switch the assistant to policy-synthesis mode, ask a natural-language
  // policy question, and wait for the rendered answer.
  const modeBtns = await page.$$(".assistant__mode button, .mode-toggle button");
  // The second mode button is "policy synthesis".
  if (modeBtns[1]) {
    await modeBtns[1].click();
    await page.waitForTimeout(400);
  }
  const input = await page.$(".assistant input, input[type='text']");
  if (input) {
    await input.fill("Show me a policy that blocks guest-net from private apps");
    await input.press("Enter");
    // Wait for the response bubble to render.
    await page.waitForTimeout(2500);
  }
}

async function captureShot(context, shot, token) {
  const vp = shot.wide ? VP_WIDE : VP;
  const page = await context.newPage();
  page.setViewportSize(vp);
  try {
    // Boot the app on the root; addInitScript has already injected the token
    // + dark theme, so the route guard lets us through.
    await page.goto(CONSOLE + "/", { waitUntil: "domcontentloaded" });
    await settle(page);
    // Select the tenant through the real dropdown (fires React onChange).
    if (shot.tenant) await selectTenant(page, TENANTS[shot.tenant] ?? shot.tenant);
    // Navigate to the target route (full reload keeps the persisted tenant).
    await page.goto(CONSOLE + shot.path, { waitUntil: "domcontentloaded" });
    await settle(page);
    if (shot.tenant) {
      // Re-select in case the reload reset to the first tenant.
      const sel = ".tenant-switcher select";
      const current = await page.$eval(sel, (el) => el.value).catch(() => "");
      if (current !== (TENANTS[shot.tenant] ?? shot.tenant)) {
        await selectTenant(page, TENANTS[shot.tenant] ?? shot.tenant);
        await page.waitForTimeout(500);
      }
    }
    await applyActions(page, shot.actions);
    if (shot.scrollToText) await scrollToTextFn(page, shot.scrollToText);
    if (shot.scrollToSelector) {
      await page.locator(shot.scrollToSelector).first().scrollIntoViewIfNeeded().catch(() => {});
      await page.waitForTimeout(400);
    }
    if (shot.runDlpSandbox) await runDlpSandbox(page);
    if (shot.assistantPolicyQuery) await runAssistantPolicyQuery(page);
    await parkPointer(page);
    const out = path.join(OUT_DIR, shot.file);
    await page.screenshot({ path: out, fullPage: !!shot.fullPage });
    console.log(`OK  ${shot.file}`);
  } catch (err) {
    console.error(`ERR ${shot.file}: ${err.message}`);
  } finally {
    await page.close();
  }
}

// --- Main -----------------------------------------------------------------
const token = mintJwt(SECRET, OPERATOR);
mkdirSync(OUT_DIR, { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: VP,
  deviceScaleFactor: 1,
});
// Inject the access token + dark theme before any page script runs so the
// route guard passes and there is no light-on-dark flash.
await context.addInitScript((tok) => {
  try {
    sessionStorage.setItem("sng.access_token", tok);
    localStorage.setItem("sng-theme", "dark");
    // Pin English so heading text (used for section scrolls) is stable
    // regardless of the host browser's preferred language.
    localStorage.setItem("sng.locale", "en");
    document.documentElement.setAttribute("data-theme", "dark");
  } catch (e) {
    /* ignore */
  }
}, token);

console.log(`Capturing ${shots.length} screenshot(s) -> ${OUT_DIR}`);
let ok = 0;
let err = 0;
for (const shot of shots) {
  try {
    await captureShot(context, shot, token);
    ok++;
  } catch (e) {
    err++;
    console.error(`ERR ${shot.file}: ${e.message}`);
  }
}

await browser.close();
console.log(`\nDone: ${ok} ok, ${err} error(s).`);
process.exit(err ? 1 : 0);
