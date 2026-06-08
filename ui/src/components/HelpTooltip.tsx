import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/**
 * A small "(?)" affordance that reveals a plain-English explanation in a
 * popover. Used to demystify jargon on the policy editor, DLP, CASB, Alerts
 * and Compliance screens for operators without a security background.
 *
 * Opens on hover for mouse/pen, and on click/tap for every input (keyboard
 * accessible via Enter/Space, since the trigger is a real button). Closes on
 * Escape, blur, pointer-leave (mouse/pen) or an outside press.
 */
export function HelpTooltip({
  title,
  children,
  align = "center",
}: {
  /** Optional bold heading shown above the explanation. */
  title?: string;
  /** The plain-English explanation. */
  children: ReactNode;
  align?: "center" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const popoverId = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    // `pointerdown` fires for mouse, pen and touch, so an outside tap closes the
    // popover on mobile too (where there is no hover/mouseleave to rely on).
    const onDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as globalThis.Node)) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onDown);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onDown);
    };
  }, [open]);

  return (
    <span
      className="help"
      ref={ref}
      // Hover-open/close is for pointers that actually hover (mouse, pen). Touch
      // is excluded: a tap synthesises pointerenter→click→pointerleave, and if
      // pointerleave closed the popover the help would flash open then vanish.
      // Touch instead opens via the click handler and closes on outside-tap or
      // Escape — see the pointerdown listener above.
      onPointerEnter={(e) => {
        if (e.pointerType !== "touch") setOpen(true);
      }}
      onPointerLeave={(e) => {
        if (e.pointerType !== "touch") setOpen(false);
      }}
    >
      <button
        type="button"
        className="help__trigger"
        aria-label={title ? `Help: ${title}` : "Help"}
        aria-expanded={open}
        aria-describedby={open ? popoverId : undefined}
        // A click/tap always *opens* (never toggles). Toggling fought the
        // hover-open above: a mouse user's `pointerenter` opened the popover and
        // the ensuing `click` would immediately toggle it shut. Opening is
        // idempotent, so click (mouse), tap (touch) and Enter/Space (keyboard,
        // since the trigger is a real button) all reliably reveal the help.
        // Closing is handled by pointerleave, blur, Escape and outside-press.
        onClick={() => setOpen(true)}
        // Close when focus leaves the trigger so keyboard users aren't left
        // with a stuck popover after tabbing away.
        onBlur={() => setOpen(false)}
      >
        ?
      </button>
      {open && (
        <span
          id={popoverId}
          role="tooltip"
          className={`help__popover${align === "right" ? " help__popover--right" : ""}`}
        >
          {title && <h5>{title}</h5>}
          {children}
        </span>
      )}
    </span>
  );
}
