import type { ReactNode } from "react";

/**
 * Reusable empty-state block: an illustration (or glyph), a title, a short
 * explanation and an optional call-to-action. Replaces the ad-hoc
 * `<p className="muted">No items…</p>` pattern across the route pages so
 * empty screens read as intentional product states rather than dead ends.
 *
 * `description` is the preferred prop; `hint` is kept as an alias so the
 * earlier call sites (which passed `hint`) keep working unchanged.
 */
export function EmptyState({
  icon,
  illustration,
  title,
  description,
  hint,
  action,
}: {
  /** Single glyph/emoji fallback when no illustration is supplied. */
  icon?: ReactNode;
  /** Inline SVG illustration (see {@link EmptyIllustration}). */
  illustration?: ReactNode;
  title: string;
  description?: ReactNode;
  /** @deprecated use `description`. */
  hint?: ReactNode;
  action?: ReactNode;
}) {
  const body = description ?? hint;
  return (
    <div className="state">
      {illustration ? (
        <div className="state__illustration">{illustration}</div>
      ) : (
        <div className="state__icon">{icon ?? <EmptyIllustration kind="inbox" />}</div>
      )}
      <p style={{ fontWeight: 600, color: "var(--text)" }}>{title}</p>
      {body && <p style={{ maxWidth: "50ch" }}>{body}</p>}
      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  );
}

export type EmptyIllustrationKind =
  | "inbox"
  | "shield"
  | "search"
  | "policy"
  | "alert";

/**
 * Small library of inline SVG line-art used by empty states. They inherit
 * `currentColor` so the surrounding `.state__illustration` colour applies.
 */
export function EmptyIllustration({
  kind = "inbox",
}: {
  kind?: EmptyIllustrationKind;
}) {
  const common = {
    width: "100%",
    height: "100%",
    viewBox: "0 0 64 64",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  switch (kind) {
    case "shield":
      return (
        <svg {...common}>
          <path d="M32 6 54 14V30C54 44 44 54 32 58 20 54 10 44 10 30V14L32 6Z" />
          <path d="M23 31l7 7 12-14" />
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <circle cx="28" cy="28" r="16" />
          <path d="M40 40 54 54" />
        </svg>
      );
    case "policy":
      return (
        <svg {...common}>
          <rect x="14" y="8" width="36" height="48" rx="4" />
          <path d="M22 20h20M22 30h20M22 40h12" />
        </svg>
      );
    case "alert":
      return (
        <svg {...common}>
          <path d="M32 10 58 54H6L32 10Z" />
          <path d="M32 28v12M32 46v.5" />
        </svg>
      );
    case "inbox":
    default:
      return (
        <svg {...common}>
          <path d="M8 36 18 14h28l10 22v14a4 4 0 0 1-4 4H12a4 4 0 0 1-4-4V36Z" />
          <path d="M8 36h14l3 6h14l3-6h14" />
        </svg>
      );
  }
}
