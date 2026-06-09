// Concrete color values for chart/graph libraries (Recharts, React Flow)
// that cannot read CSS custom properties at render time. These MUST stay in
// sync with the design tokens in `styles.css` (`:root`) so charts share the
// same palette as the rest of the console — otherwise series render in a
// stale brand blue while the nav/buttons use the current one.
export const CHART = {
  brand: "#4f8dff",
  accent: "#22d3ee",
  violet: "#a78bfa",
  ok: "#34d399",
  warn: "#fbbf24",
  warnAlt: "#f59e0b",
  danger: "#f87171",

  // Surfaces / structure (match --bg-elev, --surface, --border, --text*).
  elev: "#10141b",
  surface: "#141a23",
  border: "#2b3543",
  text: "#eef2f8",
  axis: "#9aa7bd",
} as const;

// Standard tooltip styling for Recharts <Tooltip contentStyle={...}>.
export const CHART_TOOLTIP = {
  background: CHART.elev,
  border: `1px solid ${CHART.border}`,
  borderRadius: 10,
  color: CHART.text,
} as const;
