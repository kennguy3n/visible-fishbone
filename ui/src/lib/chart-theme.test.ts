import { afterEach, describe, expect, it, vi } from "vitest";
import { CHART } from "./chart-theme";

// Drive cssVar()'s getComputedStyle lookups so the ramp's caching behaviour can
// be asserted deterministically, independent of any stylesheet being loaded.
function stubTokens(map: Record<string, string>) {
  vi.spyOn(window, "getComputedStyle").mockReturnValue({
    getPropertyValue: (name: string) => map[name] ?? "",
  } as unknown as CSSStyleDeclaration);
}

const LIGHT = {
  "--chart-1": "#91c5ff",
  "--chart-2": "#3a81f6",
  "--chart-3": "#2563ef",
  "--chart-4": "#1a4eda",
  "--chart-5": "#1f3fad",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CHART.ramp", () => {
  it("exposes the five-stop sequential ramp", () => {
    stubTokens(LIGHT);
    expect(CHART.ramp).toEqual([
      "#91c5ff",
      "#3a81f6",
      "#2563ef",
      "#1a4eda",
      "#1f3fad",
    ]);
  });

  it("returns a stable reference while the resolved tokens are unchanged", () => {
    stubTokens(LIGHT);
    // Same array identity across accesses -> safe in React memo / dep arrays.
    expect(CHART.ramp).toBe(CHART.ramp);
  });

  it("re-resolves to a new reference when the tokens change (theme flip)", () => {
    stubTokens(LIGHT);
    const light = CHART.ramp;
    stubTokens({
      "--chart-1": "#0b1f4d",
      "--chart-2": "#13357f",
      "--chart-3": "#1a4eda",
      "--chart-4": "#2563ef",
      "--chart-5": "#3a81f6",
    });
    const flipped = CHART.ramp;
    expect(flipped).not.toBe(light);
    expect(flipped[0]).toBe("#0b1f4d");
  });
});
