import type { ReactNode } from "react";
import { useEffect } from "react";

export function Modal({
  title,
  onClose,
  children,
  footer,
  busy = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  /** When an in-flight action is running, make dismissal inert: Escape and
      backdrop clicks are ignored and the header close button is disabled, so
      the operator can't abandon the dialog mid-request.

      Note: `footer` is an opaque node, so the Modal cannot disable controls
      inside it. Callers must also disable their own footer dismissal buttons
      (Cancel/Close) with the same `busy` flag to close that fourth path. */
  busy?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, busy]);

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal__header">
          <h2>{title}</h2>
          <button
            className="btn btn--ghost btn--sm"
            onClick={onClose}
            disabled={busy}
            aria-disabled={busy}
            aria-label="Close"
          >
            ✕
          </button>
        </div>
        <div className="modal__body">{children}</div>
        {footer && <div className="modal__footer">{footer}</div>}
      </div>
    </div>
  );
}
