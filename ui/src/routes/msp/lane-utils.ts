// Lane B6 pure helpers (no JSX — keeps `_lane.tsx` exporting only components
// so react-refresh stays happy).
import axios from "axios";

/** HTTP status of a failed request, or null if it isn't an HTTP error. */
export function httpStatus(error: unknown): number | null {
  if (axios.isAxiosError(error)) return error.response?.status ?? null;
  return null;
}

/** True when a query failed because the operator lacks permission. */
export function isPermissionDenied(error: unknown): boolean {
  return httpStatus(error) === 403;
}

/**
 * Relative luminance (WCAG) of a #rrggbb / #rgb colour, used to choose a
 * readable foreground over an operator-chosen branding colour so the live
 * preview never renders illegible text.
 */
function luminance(hex: string): number {
  const m = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return 1;
  let h = m[1];
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  const ch = [0, 2, 4].map((i) => {
    const v = parseInt(h.slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

/** Pick black or white text for legibility on an arbitrary background colour. */
export function readableTextOn(bg: string): string {
  return luminance(bg) > 0.4 ? "#0b1220" : "#ffffff";
}
