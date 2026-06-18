// Color values for chart/graph libraries (Recharts, React Flow) that cannot
// read CSS custom properties themselves. These are resolved live from the
// design tokens in `styles.css` (the active `:root` / `[data-theme]` scope) so
// charts track the current theme — switching Light/Dark recolors them on the
// next render without a second source of truth to keep in sync. The fallbacks
// are the dark-theme values, used only during SSR / before first paint when
// `getComputedStyle` is unavailable.
function cssVar(name: string, fallback: string): string {
  if (typeof document === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return v || fallback;
}

// Memoize the sequential ramp so repeated accesses return the same array
// reference until a theme flip actually changes the resolved colors. The token
// reads stay live (they still re-resolve every call), but the returned array is
// only re-allocated when its contents differ — keeping `CHART.ramp` stable for
// React dependency arrays / memoized chart components.
let rampCache: string[] = [];
let rampKey = "";
function resolveRamp(): string[] {
  const next = [
    cssVar("--chart-1", "#91c5ff"),
    cssVar("--chart-2", "#3a81f6"),
    cssVar("--chart-3", "#2563ef"),
    cssVar("--chart-4", "#1a4eda"),
    cssVar("--chart-5", "#1f3fad"),
  ];
  const key = next.join("|");
  if (key !== rampKey) {
    rampKey = key;
    rampCache = next;
  }
  return rampCache;
}

// Live palette: each access re-reads the token, so a component that reads these
// at render time (the common case) always gets the active theme's color.
export const CHART = {
  get brand() {
    return cssVar("--brand", "#4d83f0");
  },
  get accent() {
    return cssVar("--accent", "#22d3ee");
  },
  get violet() {
    return cssVar("--chart-violet", "#a78bfa");
  },

  // Sequential blue data-viz ramp (ShieldNet 360). Use for quantitative /
  // ordered scales (heatmaps, gauges, single-series gradients) so charts stay
  // on-brand; categorical series keep using brand/accent/violet/ok/warn.
  // Returns a stable array reference that only changes when the resolved token
  // values change (e.g. on a theme flip), so it is safe to pass into React
  // memoization / dependency arrays without forcing re-renders every access.
  get ramp(): string[] {
    return resolveRamp();
  },
  get ok() {
    return cssVar("--ok", "#34d399");
  },
  get warn() {
    return cssVar("--warn", "#fbbf24");
  },
  get warnAlt() {
    return cssVar("--warn-alt", "#f59e0b");
  },
  get danger() {
    return cssVar("--danger", "#f87171");
  },

  // Surfaces / structure (match --bg-elev, --surface, --border, --text*).
  get elev() {
    return cssVar("--bg-elev", "#10141b");
  },
  get surface() {
    return cssVar("--surface", "#141a23");
  },
  get border() {
    return cssVar("--border", "#2b3543");
  },
  get text() {
    return cssVar("--text", "#eef2f8");
  },
  get axis() {
    return cssVar("--text-dim", "#9aa7bd");
  },
};

// Standard tooltip styling for Recharts <Tooltip contentStyle={...}>. Getters
// keep the surface/border/text colors tracking the active theme.
export const CHART_TOOLTIP = {
  get background() {
    return CHART.elev;
  },
  get border() {
    return `1px solid ${CHART.border}`;
  },
  borderRadius: 10,
  get color() {
    return CHART.text;
  },
};
