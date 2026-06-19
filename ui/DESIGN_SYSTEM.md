# ShieldNet Gateway — Design System (WS0 foundation)

This console is a first-party **ShieldNet 360** surface. Its look, voice, and
behaviour follow [shieldnet360.com](https://shieldnet360.com/). This note is the
contract every screen builds against — read it before touching UI.

## 1. Token layer (`src/styles.css`)

All colour, radius, shadow, motion, and focus values live as CSS custom
properties in the `:root` (light), `:root[data-theme="dark"]`, and the no-JS
`prefers-color-scheme` fallback blocks. **Never hard-code a colour, radius, or
shadow** — reference a token so light/dark and future retheming stay automatic.

Key tokens:

| Token | Purpose |
|---|---|
| `--brand` / `--brand-strong` | ShieldNet blue (`#255fe5`). Primary CTAs, active nav, links, all UI accents. |
| `--brand-rgb` | Brand channels for translucent tints (`rgba(var(--brand-rgb), …)`). |
| `--accent` | **Data-viz only** (cyan). Charts read it; do **not** use it for UI chrome. |
| `--chart-1 … --chart-5` | Sequential blue data-viz ramp for quantitative scales. |
| `--chart-violet` | Categorical data-viz accent. |
| `--ok` / `--warn` / `--danger` (+ `-soft`, `-strong`, `-border`) | Semantic status. |
| `--bg` / `--bg-elev` / `--surface` / `--border` / `--text*` | Surfaces & text. |
| `--radius` (10px) / `--radius-sm` / `--radius-xs` (2px) / `--radius-lg` / `--radius-pill` | Corner radii (aligned to the site's `.625rem`). |
| `--shadow` / `--elev-flat` / `--elev-raised` / `--elev-floating` | Subtle layered depth (no heavy single drops). |
| `--transition` / `--focus-ring` | One motion curve, one keyboard focus treatment. |

### Cyan is data-viz only
The product accent is **brand blue**, not cyan. `--accent` (cyan) is reserved
for charts/graphs so the console reads as one ShieldNet 360 blue surface. UI
gradients and accent bars use `--brand` / `--brand-strong`.

### Charts
`src/lib/chart-theme.ts` resolves tokens live for Recharts / React Flow (which
can't read CSS variables). Use `CHART.brand/accent/violet/ok/warn` for
categorical series and `CHART.ramp` (the blue `--chart-1…5` scale) for
quantitative/ordered scales.

## 2. Shared primitives (`src/components/ui.tsx`)

Consume these — don't fork them: `PageHeader`, `Card`, `Stat`, `Badge`,
`StatusBadge`, `Spinner`, `LoadingState`, `ErrorState`, `SkeletonTable`,
`SkeletonCard`, `AsyncBoundary`, plus `DataTable`, `EmptyState`, `Modal`,
`Toast`, `HelpTooltip`, `Icon`, `CircularScore`, `ThreatMap`, `AppLayout`. Wrap
every async screen in `AsyncBoundary` so the loading / error / empty lifecycle
is consistent.

## 3. Brand voice (microcopy)

Plain language, reassuring, jargon-free. Every label/empty/error/tooltip
explains **what happened, why it matters, and what to do next**. No raw error
codes, no naked acronyms on first use. All strings go through `react-intl`
(no hard-coded text).

> "Security made simple." · "…cybersecurity that speaks your language." ·
> "No confusing alerts nor cryptic warnings."

## 4. Accessibility baseline (WCAG 2.2 AA)

Contrast ≥ 4.5:1, visible `:focus-visible` ring, full keyboard path, correct
ARIA roles/labels, form errors announced, `prefers-reduced-motion` respected.

## 5. Module-lane rules (parallel work)

- **WS0 owns** `src/styles.css` tokens, `src/lib/chart-theme.ts`, and the shared
  primitives in `src/components/`. These are **frozen** after WS0 merges.
- Module lanes edit **their own screen files only**; they consume tokens and
  primitives, never edit them.
- Need a new shared token or primitive? Request it as a small WS0 follow-up
  rather than editing the shared layer (keeps lanes conflict-free).
- One PR per lane, branched from post-WS0 `main`.
