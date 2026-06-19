import { useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { PageHeader, Card } from "@/components/ui";
import { Icon } from "@/components/Icon";
import { LOCALE_LABELS, isLocale } from "@/lib/i18n/locales";
import { useLocale } from "@/lib/i18n/locale-context";
import {
  getStoredChoice,
  resolveTheme,
  setTheme,
  type ThemeChoice,
} from "@/lib/theme";
import { LaneB1Intl } from "./lane-b1-intl";
import "./lane-b1.css";

const THEME_OPTIONS: {
  value: ThemeChoice;
  labelId: string;
  hintId: string;
  icon: "dashboard" | "browser" | "settings";
}[] = [
  {
    value: "light",
    labelId: "b1.settings.theme.light",
    hintId: "b1.settings.theme.light.hint",
    icon: "dashboard",
  },
  {
    value: "dark",
    labelId: "b1.settings.theme.dark",
    hintId: "b1.settings.theme.dark.hint",
    icon: "browser",
  },
  {
    value: "system",
    labelId: "b1.settings.theme.system",
    hintId: "b1.settings.theme.system.hint",
    icon: "settings",
  },
];

export function Settings() {
  return (
    <LaneB1Intl>
      <SettingsInner />
    </LaneB1Intl>
  );
}

function SettingsInner() {
  const intl = useIntl();
  const { locale, setLocale, locales } = useLocale();
  const [choice, setChoice] = useState<ThemeChoice>(() => getStoredChoice());

  const select = (next: ThemeChoice) => {
    setChoice(next);
    setTheme(next);
  };

  const resolved = resolveTheme(choice);
  const resolvedLabel = intl.formatMessage({
    id: resolved === "dark" ? "b1.settings.theme.value.dark" : "b1.settings.theme.value.light",
  });
  const choiceLabel = intl.formatMessage({ id: `b1.settings.theme.${choice}` });

  return (
    <div className="lane-b1">
      <PageHeader
        title={intl.formatMessage({ id: "b1.settings.title" })}
        subtitle={intl.formatMessage({ id: "b1.settings.subtitle" })}
      />
      <div className="grid grid--2">
        <Card
          title={intl.formatMessage({ id: "b1.settings.appearance.title" })}
          subtitle={intl.formatMessage({ id: "b1.settings.appearance.subtitle" })}
        >
          <div
            className="theme-toggle"
            role="radiogroup"
            aria-label={intl.formatMessage({ id: "b1.settings.theme.legend" })}
          >
            {THEME_OPTIONS.map((opt) => {
              const active = choice === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={`theme-toggle__option${active ? " active" : ""}`}
                  onClick={() => select(opt.value)}
                >
                  <Icon name={opt.icon} size={18} />
                  <b>
                    <FormattedMessage id={opt.labelId} />
                  </b>
                  <span className="muted">
                    <FormattedMessage id={opt.hintId} />
                  </span>
                </button>
              );
            })}
          </div>
          <p className="muted" style={{ marginTop: 14, fontSize: 12 }} aria-live="polite">
            {choice === "system" ? (
              <FormattedMessage
                id="b1.settings.theme.following"
                values={{ theme: <b>{resolvedLabel}</b> }}
              />
            ) : (
              <FormattedMessage
                id="b1.settings.theme.locked"
                values={{ theme: <b>{choiceLabel}</b> }}
              />
            )}
          </p>
        </Card>

        <Card
          title={intl.formatMessage({ id: "b1.settings.language.title" })}
          subtitle={intl.formatMessage({ id: "b1.settings.language.subtitle" })}
        >
          <label className="field field--narrow">
            <span>
              <FormattedMessage id="b1.settings.language.title" />
            </span>
            <select
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
          </label>
        </Card>
      </div>
    </div>
  );
}
