// Lane B6 shared UI building blocks. Components only (helpers live in
// `lane-utils.ts`) so react-refresh stays happy. Importing this module also
// pulls in the lane's scoped stylesheet exactly once.
import type { ReactNode } from "react";
import { useEffect, useRef } from "react";
import { useIntl } from "react-intl";
import { EmptyState, EmptyIllustration } from "@/components/ui";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { M } from "./lane-b6.messages";
import "@/routes/lane-b6.css";

/** Wraps a screen so the lane's scoped styles (`.lane-b6 …`) apply. */
export function LanePage({ children }: { children: ReactNode }) {
  return <div className="lane-b6">{children}</div>;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Drop-in wrapper around the frozen WS0 `Modal` that adds the keyboard focus
 * management the shared component doesn't implement: it moves initial focus
 * into the dialog (unless a child already claimed it via `autoFocus`) and traps
 * Tab / Shift+Tab inside the dialog while it is open. The foundation component
 * is not modified — we only manage focus on the `.modal` node it renders.
 */
export function LaneModal({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const anchorRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const dialog = anchorRef.current?.closest<HTMLElement>(".modal");
    if (!dialog) return;
    const focusables = () =>
      Array.from(
        dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter((el) => el.offsetParent !== null);

    // Respect a child's `autoFocus`; otherwise pull focus into the dialog.
    if (!dialog.contains(document.activeElement)) {
      (focusables()[0] ?? dialog).focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const items = focusables();
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (!dialog.contains(active)) {
        e.preventDefault();
        first.focus();
      } else if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    // Capture phase so we intercept Tab even if focus has escaped the dialog.
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, []);

  return (
    <Modal title={title} onClose={onClose} footer={footer}>
      <span ref={anchorRef} aria-hidden="true" style={{ display: "none" }} />
      {children}
    </Modal>
  );
}

function ScopeIcon() {
  return (
    <span className="lb6-scope__icon" aria-hidden="true">
      <svg
        viewBox="0 0 24 24"
        width="18"
        height="18"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3Z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    </span>
  );
}

/**
 * Persistent "which tenant am I acting on" context bar. Prevents cross-tenant
 * mistakes on the single-tenant screens (branding, roles).
 */
export function TenantScopeBanner({
  name,
  aside,
}: {
  name: string;
  aside?: ReactNode;
}) {
  const { formatMessage } = useIntl();
  return (
    <div className="banner lb6-scope" role="note">
      <ScopeIcon />
      <div className="banner__body">
        <div className="lb6-scope__label">
          {formatMessage(M.scopeTenantLabel)}
        </div>
        <div className="lb6-scope__name">{name}</div>
        <div className="banner__sub">{formatMessage(M.scopeTenantSub)}</div>
      </div>
      {aside && <div className="lb6-scope__aside">{aside}</div>}
    </div>
  );
}

/** "Acting on behalf of <MSP>" context bar for cohort-wide screens. */
export function MspScopeBanner({
  name,
  aside,
}: {
  name: string;
  aside?: ReactNode;
}) {
  const { formatMessage } = useIntl();
  return (
    <div className="banner lb6-scope" role="note">
      <ScopeIcon />
      <div className="banner__body">
        <div className="lb6-scope__label">{formatMessage(M.scopeMspLabel)}</div>
        <div className="lb6-scope__name">{name}</div>
        <div className="banner__sub">{formatMessage(M.scopeMspSub)}</div>
      </div>
      {aside && <div className="lb6-scope__aside">{aside}</div>}
    </div>
  );
}

/** Permission-denied state shown when a query comes back 403. */
export function PermissionDenied() {
  const { formatMessage } = useIntl();
  return (
    <EmptyState
      illustration={<EmptyIllustration kind="shield" />}
      title={formatMessage(M.permTitle)}
      description={formatMessage(M.permBody)}
      action={
        <button
          className="btn btn--primary"
          onClick={() => window.location.reload()}
        >
          {formatMessage(M.permReload)}
        </button>
      }
    />
  );
}

/**
 * Branded confirmation modal that replaces native `confirm()` for guarded /
 * destructive actions. The body is free-form so callers can preview the exact
 * scope of a bulk action before the operator commits.
 */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  tone = "primary",
  busy = false,
  confirmDisabled = false,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  tone?: "primary" | "danger";
  busy?: boolean;
  confirmDisabled?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { formatMessage } = useIntl();
  return (
    <LaneModal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            {formatMessage(M.cancel)}
          </button>
          <button
            className={`btn btn--${tone}`}
            onClick={onConfirm}
            disabled={busy || confirmDisabled}
          >
            {confirmLabel}
          </button>
        </>
      }
    >
      {children}
    </LaneModal>
  );
}

/** A `.field` label with an inline plain-language help affordance. */
export function LabelText({
  children,
  help,
  helpTitle,
}: {
  children: ReactNode;
  help?: ReactNode;
  helpTitle?: string;
}) {
  return (
    <span className="lb6-label">
      {children}
      {help && <HelpTooltip title={helpTitle}>{help}</HelpTooltip>}
    </span>
  );
}
