// LocaleProvider wires react-intl into the app and owns the active
// locale. It:
//   - seeds the locale from persistence / the browser,
//   - exposes { locale, setLocale, locales } via useLocale(),
//   - keeps <html lang> and <html dir> in sync (RTL for Arabic), and
//   - feeds react-intl the message catalog with English as the
//     fallback locale.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { IntlProvider } from "react-intl";
import {
  DEFAULT_LOCALE,
  dirFor,
  type Locale,
  LOCALES,
} from "./locales";
import { messagesFor } from "./messages";
import { detectInitialLocale, storeLocale } from "./locale-store";

interface LocaleContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  locales: readonly Locale[];
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() =>
    detectInitialLocale(),
  );

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    storeLocale(next);
  }, []);

  // Reflect the locale onto the document so CSS (RTL flip, CJK font
  // stacks via :lang()) and assistive tech see the right language and
  // direction.
  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.lang = locale;
    document.documentElement.dir = dirFor(locale);
  }, [locale]);

  const value = useMemo<LocaleContextValue>(
    () => ({ locale, setLocale, locales: LOCALES }),
    [locale, setLocale],
  );

  return (
    <LocaleContext.Provider value={value}>
      <IntlProvider
        locale={locale}
        defaultLocale={DEFAULT_LOCALE}
        messages={messagesFor(locale)}
      >
        {children}
      </IntlProvider>
    </LocaleContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext);
  if (!ctx) {
    throw new Error("useLocale must be used within a LocaleProvider");
  }
  return ctx;
}
