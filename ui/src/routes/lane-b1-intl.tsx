// Wraps a Lane B1 screen in a nested react-intl provider that layers the
// lane-local catalog (lane-b1.messages.ts) on top of the shared chrome
// catalog. This keeps lane strings out of the frozen foundation catalog while
// still resolving through the same locale, direction and error handling the
// rest of the app uses.

import { type ReactNode, useMemo } from "react";
import { IntlProvider, useIntl } from "react-intl";
import { useLocale } from "@/lib/i18n/locale-context";
import { laneMessagesFor } from "./lane-b1.messages";

export function LaneB1Intl({ children }: { children: ReactNode }) {
  const { locale } = useLocale();
  const parent = useIntl();
  // Merge the lane catalog over the chrome catalog so both resolve through one
  // provider. `IntlShape.messages` is typed as string | MessageFormatElement[]
  // values; this app ships plain-string catalogs (not @formatjs pre-compiled
  // AST), so the cast to Record<string, string> is safe. If the chrome catalog
  // ever switches to pre-compiled AST, this merge must be revisited.
  // Memoize so the merged object keeps a stable identity across re-renders —
  // IntlProvider compares messages by reference, so a fresh object every render
  // would needlessly re-render every useIntl() consumer in the subtree.
  const messages = useMemo<Record<string, string>>(
    () => ({
      ...(parent.messages as Record<string, string>),
      ...laneMessagesFor(locale),
    }),
    [parent.messages, locale],
  );

  return (
    <IntlProvider
      locale={parent.locale}
      defaultLocale={parent.defaultLocale}
      messages={messages}
      onError={parent.onError}
    >
      {children}
    </IntlProvider>
  );
}
