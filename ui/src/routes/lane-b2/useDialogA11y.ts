import { useEffect, type RefObject } from "react";

/**
 * Keyboard/focus management for Lane B2 dialogs built on the frozen `Modal`
 * primitive. `Modal` sets `role="dialog"`/`aria-modal="true"` and wires
 * Escape-to-close, but it does not move focus into the dialog, keep Tab inside
 * it, or return focus to the control that opened it. Leaving those out fails
 * the keyboard path (WCAG 2.1.2 No Keyboard Trap / 2.4.3 Focus Order), so this
 * lane-local hook adds them without touching the foundation.
 *
 * - `initialFocus`: element to focus on open (e.g. the Cancel button so the
 *   safe choice is the default). When omitted and `focusFirst` is set, the
 *   first control in the dialog body is used.
 * - On unmount, focus returns to whatever was focused before the dialog opened
 *   (the opener), unless that element has since left the DOM (e.g. the row it
 *   lived in was deleted), in which case the browser default applies.
 *
 * Drive initial focus through this hook (`initialFocus`/`focusFirst`), NOT a
 * child's `autoFocus` attribute: React applies `autoFocus` during commit,
 * before this effect runs, so the opener would already be lost by the time we
 * capture `document.activeElement` and focus could not be restored on close.
 */
export function useDialogA11y(opts?: {
  initialFocus?: RefObject<HTMLElement | null>;
  focusFirst?: boolean;
}) {
  const initialFocus = opts?.initialFocus;
  const focusFirst = opts?.focusFirst ?? false;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>(".modal");
    const focusables = () =>
      dialog
        ? Array.from(
            dialog.querySelectorAll<HTMLElement>(
              'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            ),
          )
        : [];

    // For `focusFirst`, prefer the first control in the dialog body so focus
    // lands on a meaningful element rather than the header's ✕ dismiss button,
    // while still moving focus inside the dialog.
    const firstInBody = () => {
      const body = dialog?.querySelector<HTMLElement>(".modal__body");
      const inBody = body
        ?.querySelector<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
      return inBody ?? focusables()[0];
    };
    const target =
      initialFocus?.current ?? (focusFirst ? firstInBody() : undefined);
    target?.focus?.();

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab" || !dialog) return;
      const f = focusables();
      if (f.length === 0) return;
      const first = f[0];
      const last = f[f.length - 1];
      const active = document.activeElement as HTMLElement | null;
      const outside = !dialog.contains(active);
      if (e.shiftKey && (active === first || outside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || outside)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (opener && document.contains(opener)) opener.focus?.();
    };
    // Opener/dialog are captured once on open; this effect must run only on
    // mount/unmount so the trap and restoration bracket the dialog's lifetime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
