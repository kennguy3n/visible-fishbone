// Lane B4 shared screen helpers: a permission-denied state, a reveal/copy
// field, and a 403 detector. All copy flows through the lane catalog (useT).

import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { Card, EmptyState, EmptyIllustration } from "@/components/ui";
import { useT } from "./lane-b4-i18n";

/** True when a React Query error is an HTTP 403 (caller lacks permission). */
// eslint-disable-next-line react-refresh/only-export-components
export function isForbidden(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 403;
}

/** Friendly "you don’t have access" state shown when a list query returns 403. */
export function PermissionDenied() {
  const t = useT();
  return (
    <Card>
      <EmptyState
        illustration={<EmptyIllustration kind="shield" />}
        title={t("b4.denied.title")}
        description={t("b4.denied.desc")}
      />
    </Card>
  );
}

/**
 * Read-only monospace value with a Copy button. Used for connection URLs and
 * the reveal-once API key. Announces "Copied" via the button label briefly.
 */
export function CopyField({
  value,
  label,
  copyLabel,
}: {
  value: string;
  /** Accessible label for the value field. */
  label: string;
  /** Accessible label for the copy button (e.g. "Copy key"). */
  copyLabel: string;
}) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(resetTimer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.clearTimeout(resetTimer.current);
      resetTimer.current = window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access can be denied; the value stays visible to copy by hand.
    }
  };

  return (
    <div className="copy-field">
      <input
        className="mono"
        value={value}
        readOnly
        aria-label={label}
        onFocus={(e) => e.currentTarget.select()}
      />
      <button
        type="button"
        className="btn btn--sm"
        onClick={copy}
        aria-label={copyLabel}
      >
        {copied ? t("b4.action.copied") : t("b4.action.copy")}
      </button>
    </div>
  );
}
