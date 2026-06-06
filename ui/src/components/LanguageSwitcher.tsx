import { useIntl } from "react-intl";
import { LOCALE_LABELS, isLocale } from "@/lib/i18n/locales";
import { useLocale } from "@/lib/i18n/locale-context";

// LanguageSwitcher renders the supported-locale set as a select. The
// list is driven by the same LOCALES constant the API negotiates over,
// so the UI can never offer a language the backend can't localize.
export function LanguageSwitcher() {
  const { locale, setLocale, locales } = useLocale();
  const intl = useIntl();
  const label = intl.formatMessage({ id: "topbar.language" });

  return (
    <div className="language-switcher">
      <span className="muted" style={{ fontSize: 12 }}>
        {label}
      </span>
      <select
        aria-label={label}
        value={locale}
        onChange={(e) => {
          const next = e.target.value;
          if (isLocale(next)) setLocale(next);
        }}
      >
        {locales.map((l) => (
          <option key={l} value={l}>
            {LOCALE_LABELS[l]}
          </option>
        ))}
      </select>
    </div>
  );
}
