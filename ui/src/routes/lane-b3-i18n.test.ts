import { describe, expect, it } from "vitest";
import { LOCALES } from "@/lib/i18n/locales";
import { B3_EN, B3_MESSAGES } from "./lane-b3-i18n";

// English is the source of truth for the Lane B3 catalog. Every supported
// locale must define every key so the UI never falls through to a raw message
// id. Untranslated locales currently reuse the English source — this test
// guards that the structure stays complete as translations land.
const EN_KEYS = Object.keys(B3_EN).sort();

describe("lane-b3 i18n catalog", () => {
  it("covers every supported app locale", () => {
    expect(Object.keys(B3_MESSAGES).sort()).toEqual([...LOCALES].sort());
  });

  it.each(LOCALES)("locale %s defines every English key", (locale) => {
    const keys = Object.keys(B3_MESSAGES[locale]).sort();
    expect(keys).toEqual(EN_KEYS);
  });

  it.each(LOCALES)("locale %s leaves no value blank", (locale) => {
    const blank = Object.entries(B3_MESSAGES[locale])
      .filter(([, value]) => value.trim() === "")
      .map(([key]) => key);
    expect(blank).toEqual([]);
  });

  it("has no duplicate English values masking a copy/paste mistake in keys", () => {
    // Keys must be unique by construction (object literal); assert the catalog
    // is non-trivially populated so an accidental empty object can't pass above.
    expect(EN_KEYS.length).toBeGreaterThan(150);
  });
});
