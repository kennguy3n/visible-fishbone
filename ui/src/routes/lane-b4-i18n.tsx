// Lane B4 i18n + screen shell.
//
// `LaneB4Screen` wraps each owned screen in:
//   1. a `.lane-b4` element that scopes the lane's CSS overrides, and
//   2. a nested <IntlProvider> carrying the lane's own message catalog.
//
// The nested provider reuses the foundation's active locale (via `useLocale`)
// so switching language in the top bar re-renders the lane too. None of the
// shared primitives the lane renders consume react-intl, so the nested
// provider only affects this lane's strings.

import type { ReactNode } from "react";
import { IntlProvider, useIntl } from "react-intl";
import { useLocale } from "@/lib/i18n/locale-context";
import { DEFAULT_LOCALE } from "@/lib/i18n/locales";
import { laneMessagesFor, type LaneKey } from "./lane-b4-messages";
import "./lane-b4.css";

export function LaneB4Screen({ children }: { children: ReactNode }) {
  const { locale } = useLocale();
  return (
    <IntlProvider
      locale={locale}
      defaultLocale={DEFAULT_LOCALE}
      messages={laneMessagesFor(locale)}
    >
      <div className="lane-b4">{children}</div>
    </IntlProvider>
  );
}

export type TValues = Record<string, string | number>;

/** Typed translation helper bound to the lane catalog: `t("idp.title")`. */
// eslint-disable-next-line react-refresh/only-export-components
export function useT(): (key: LaneKey, values?: TValues) => string {
  const intl = useIntl();
  return (key, values) =>
    intl.formatMessage({ id: key }, values) as string;
}
