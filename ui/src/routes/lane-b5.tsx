// Shared Lane B5 building blocks. Importing this module also pulls in the
// lane's scoped stylesheet, so every owned screen gets the `.lane-b5`
// overrides and layout utilities by wrapping its content in <LanePage>.

import type { ReactNode } from "react";
import { Modal } from "@/components/Modal";
import "./lane-b5.css";

/** Wraps a screen so the `.lane-b5` scoped styles/overrides apply. */
export function LanePage({ children }: { children: ReactNode }) {
  return <div className="lane-b5">{children}</div>;
}

/**
 * Accessible confirmation dialog used to guard destructive actions
 * (replaces the browser `confirm()`, which traps focus poorly and can't be
 * styled or translated). Built on the frozen Modal primitive, so it inherits
 * Escape-to-close, backdrop dismissal, and dialog semantics.
 */
export function ConfirmDialog({
  title,
  body,
  error,
  confirmLabel,
  cancelLabel,
  busyLabel,
  tone = "primary",
  busy = false,
  onConfirm,
  onClose,
}: {
  title: string;
  body: ReactNode;
  /** Plain-language failure message shown in-dialog so the user can retry. */
  error?: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  busyLabel?: string;
  tone?: "primary" | "danger";
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          {/* For destructive dialogs, initial focus lands on the safe option
              (Cancel) per the WAI-ARIA alert-dialog pattern, so a stray Enter
              can't trigger the irreversible action. Confirmatory (primary)
              dialogs focus the confirm button for fast keyboard completion. */}
          <button
            className="btn"
            onClick={onClose}
            disabled={busy}
            autoFocus={tone === "danger"}
          >
            {cancelLabel}
          </button>
          <button
            className={`btn ${tone === "danger" ? "btn--danger" : "btn--primary"}`}
            onClick={onConfirm}
            disabled={busy}
            autoFocus={tone !== "danger"}
          >
            {busy && busyLabel ? busyLabel : confirmLabel}
          </button>
        </>
      }
    >
      <p className="lane-prose">{body}</p>
      {error ? (
        <p className="error-text" role="alert">
          {error}
        </p>
      ) : null}
    </Modal>
  );
}
