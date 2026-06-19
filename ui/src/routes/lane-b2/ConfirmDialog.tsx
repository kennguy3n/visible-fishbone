import { useEffect, useRef, type ReactNode } from "react";
import { Modal } from "@/components/Modal";

/**
 * Safe-by-default confirmation for destructive actions in Lane B2.
 *
 * Built on the frozen `Modal` primitive, it adds the plain-language
 * "what happens next" consequence copy and a clearly destructive primary
 * action that the bare `window.confirm()` calls elsewhere can't express.
 * Focus lands on Cancel so the non-destructive choice is the default, and
 * Modal already wires Escape-to-close and `role="dialog"`/`aria-modal`.
 *
 * While a mutation is in flight (`busy`) every dismissal path is neutralised —
 * the footer buttons disable and `onClose` becomes a no-op so Escape, a
 * backdrop click, or the ✕ can't abandon the dialog mid-request and leave the
 * user unsure whether the destructive action actually ran.
 */
export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  cancelLabel,
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  return (
    <Modal
      title={title}
      onClose={busy ? () => {} : onCancel}
      footer={
        <>
          <button
            ref={cancelRef}
            className="btn"
            onClick={onCancel}
            disabled={busy}
          >
            {cancelLabel}
          </button>
          <button
            className="btn btn--danger"
            onClick={onConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </button>
        </>
      }
    >
      <p style={{ margin: 0, lineHeight: 1.6 }}>{message}</p>
    </Modal>
  );
}
