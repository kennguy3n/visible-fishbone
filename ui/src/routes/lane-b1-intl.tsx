// Wraps a Lane B1 screen in a nested react-intl provider that layers the
// lane-local catalog (lane-b1.messages.ts) on top of the shared chrome
// catalog. This keeps lane strings out of the frozen foundation catalog while
// still resolving through the same locale, direction and error handling the
// rest of the app uses.

import { type ReactNode } from "react";
import { IntlProvider, useIntl } from "react-intl";
import { useLocale } from "@/lib/i18n/locale-context";
import { laneMessagesFor } from "./lane-b1.messages";

export function LaneB1Intl({ children }: { children: ReactNode }) {
  const { locale } = useLocale();
  const parent = useIntl();
  // The parent catalog is pre-compiled to plain strings; merge the lane catalog
  // over it so both the chrome and lane keys resolve through one provider.
  const messages: Record<string, string> = {
    ...(parent.messages as Record<string, string>),
    ...laneMessagesFor(locale),
  };

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
