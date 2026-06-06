// Locale persistence + the framework-agnostic accessor the axios
// layer uses. Kept separate from the React context so non-React code
// (the http-client request interceptor) can read the active locale
// without importing React or the provider.

import { DEFAULT_LOCALE, type Locale, resolveLocale } from "./locales";

const STORAGE_KEY = "sng.locale";

export function getStoredLocale(): Locale | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  const resolved = resolveLocale(raw);
  // Only treat it as "stored" if the persisted value resolved to a
  // real supported locale (guards against a stale/garbage value).
  return resolved;
}

export function storeLocale(locale: Locale): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(STORAGE_KEY, locale);
}

// detectInitialLocale picks the startup locale: an explicit stored
// choice wins; otherwise the browser's preferred language is mapped
// onto the supported set; otherwise English.
export function detectInitialLocale(): Locale {
  const stored = getStoredLocale();
  if (stored) return stored;
  if (typeof navigator !== "undefined") {
    const nav = navigator.languages?.[0] ?? navigator.language;
    return resolveLocale(nav);
  }
  return DEFAULT_LOCALE;
}

// getActiveLocale is the accessor the axios interceptor calls to stamp
// Accept-Language on every API request, so the API negotiates the same
// language the operator selected in the UI.
export function getActiveLocale(): Locale {
  return getStoredLocale() ?? detectInitialLocale();
}
