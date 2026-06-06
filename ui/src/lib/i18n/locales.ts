// Locale catalog for the admin UI. The set here is the SAME set the
// Go control plane negotiates over (internal/i18n) so the language the
// operator picks in the UI is exactly the language the API will
// localize responses into via the Accept-Language header.

export const DEFAULT_LOCALE = "en" as const;

// Locale tags in BCP-47 form. zh-Hans / zh-Hant select Simplified vs
// Traditional Chinese; both map to the matching Go locale files.
export const LOCALES = [
  "en",
  "zh-Hans",
  "zh-Hant",
  "ms",
  "id",
  "th",
  "vi",
  "ja",
  "ko",
  "ar",
  "de",
  "fr",
] as const;

export type Locale = (typeof LOCALES)[number];

// Endonyms (each language named in itself) — the conventional, most
// recognizable way to render a language switcher.
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  "zh-Hans": "简体中文",
  "zh-Hant": "繁體中文",
  ms: "Bahasa Melayu",
  id: "Bahasa Indonesia",
  th: "ไทย",
  vi: "Tiếng Việt",
  ja: "日本語",
  ko: "한국어",
  ar: "العربية",
  de: "Deutsch",
  fr: "Français",
};

// Right-to-left locales. Arabic is the only RTL locale in the priority
// set; kept as a set so adding he/fa/ur later is a one-line change.
const RTL_LOCALES = new Set<Locale>(["ar"]);

export function isRTL(locale: Locale): boolean {
  return RTL_LOCALES.has(locale);
}

export function dirFor(locale: Locale): "rtl" | "ltr" {
  return isRTL(locale) ? "rtl" : "ltr";
}

export function isLocale(value: string): value is Locale {
  return (LOCALES as readonly string[]).includes(value);
}

// resolveLocale coerces an arbitrary tag (e.g. from navigator.language
// or a persisted value) onto a supported Locale, falling back to the
// default. It honours an exact match first, then a base-language match
// (so "de-AT" → "de", "zh-Hans-SG" → "zh-Hans", "zh" → "zh-Hans").
export function resolveLocale(
  tag: string | null | undefined,
): Locale {
  if (!tag) return DEFAULT_LOCALE;
  const normalized = tag.trim();
  if (normalized === "") return DEFAULT_LOCALE;
  if (isLocale(normalized)) return normalized;

  const lower = normalized.toLowerCase();
  // Bare "zh" defaults to Simplified, the more common variant.
  if (lower === "zh" || lower.startsWith("zh-hans") || lower.startsWith("zh-cn") || lower.startsWith("zh-sg")) {
    return "zh-Hans";
  }
  if (lower.startsWith("zh-hant") || lower.startsWith("zh-tw") || lower.startsWith("zh-hk") || lower.startsWith("zh-mo")) {
    return "zh-Hant";
  }
  const base = lower.split("-")[0];
  const match = (LOCALES as readonly string[]).find(
    (l) => l.toLowerCase() === base,
  );
  return (match as Locale) ?? DEFAULT_LOCALE;
}
