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

// Live palette: each access re-reads the token, so a component that reads these
// at render time (the common case) always gets the active theme's color.
export const CHART = {
  get brand() {
    return cssVar("--brand", "#8b5cf6");
  },
  get accent() {
    return cssVar("--accent", "#22d3ee");
  },
  get violet() {
    return cssVar("--chart-violet", "#a78bfa");
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
