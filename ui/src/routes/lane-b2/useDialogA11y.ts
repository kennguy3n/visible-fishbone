import { useEffect, type RefObject } from "react";

/**
 * Keyboard/focus management for Lane B2 dialogs built on the frozen `Modal`
 * primitive. `Modal` sets `role="dialog"`/`aria-modal="true"` and wires
 * Escape-to-close, but it does not move focus into the dialog, keep Tab inside
 * it, or return focus to the control that opened it. Leaving those out fails
 * the keyboard path (WCAG 2.1.2 No Keyboard Trap / 2.4.3 Focus Order), so this
 * lane-local hook adds them without touching the foundation.
 *
 * Pass `initialFocus`: a ref to the control that should receive focus on open
 * (e.g. the Cancel button so the safe choice is the default, or a form's first
 * field). The hook also uses it to locate *this* dialog's container, via
 * `initialFocus.current.closest(".modal")`, so the Tab trap stays scoped to the
 * right dialog even when another `.modal` is in the DOM — unlike a global
 * `document.querySelector(".modal")`, which always returns the first one.
 *
 * On unmount, focus returns to whatever was focused before the dialog opened
 * (the opener), unless that element has since left the DOM (e.g. the row it
 * lived in was deleted), in which case the browser default applies.
 *
 * Drive initial focus through this hook, NOT a child's `autoFocus` attribute:
 * React applies `autoFocus` during commit, before this effect runs, so the
 * opener would already be lost by the time we capture `document.activeElement`
 * and focus could not be restored on close.
 */
export function useDialogA11y(opts?: {
  initialFocus?: RefObject<HTMLElement | null>;
}) {
  const initialFocus = opts?.initialFocus;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    // Scope to THIS dialog by climbing from the initial-focus target to its
    // enclosing `.modal`, rather than grabbing the first `.modal` in the
    // document. The global lookup is only a last-resort fallback for the
    // unlikely case the ref isn't attached when this effect runs.
    const dialog =
      initialFocus?.current?.closest<HTMLElement>(".modal") ??
      document.querySelector<HTMLElement>(".modal");
    const focusables = () =>
      dialog
        ? Array.from(
            dialog.querySelectorAll<HTMLElement>(
              'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            ),
          )
        : [];

    initialFocus?.current?.focus?.();

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
