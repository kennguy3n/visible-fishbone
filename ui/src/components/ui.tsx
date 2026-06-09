import type { ReactNode } from "react";
import { statusTone, titleCase, type Tone } from "@/lib/format";
import { EmptyState } from "./EmptyState";

export { EmptyState, EmptyIllustration } from "./EmptyState";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </div>
  );
}

export function Card({
  title,
  children,
  className,
  actions,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <div className={`card${className ? ` ${className}` : ""}`}>
      {(title || actions) && (
        <div className="card__header">
          {title && <h3 className="card__title">{title}</h3>}
          {actions && <div className="card__actions">{actions}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

export function Stat({
  label,
  value,
  delta,
}: {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
}) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
      {delta != null && <div className="stat__delta">{delta}</div>}
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral",
  dot = false,
}: {
  children: ReactNode;
  tone?: Tone;
  /** Show a leading status dot. Reserved for badges that signal live state
   *  (see StatusBadge); plain label/count/verdict badges leave it off so the
   *  dot doesn't read as a status indicator where none is meant. */
  dot?: boolean;
}) {
  return (
    <span className={`badge badge--${tone}${dot ? " badge--dot" : ""}`}>
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status?: string | null }) {
  return (
    <Badge tone={statusTone(status)} dot>
      {titleCase(status)}
    </Badge>
  );
}

export function Spinner() {
  return <span className="spinner" aria-label="Loading" role="status" />;
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state">
      <Spinner />
      <p style={{ marginTop: 12 }}>{label}</p>
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "An unexpected error occurred.";
  return (
    <div className="state state--error">
      <div className="state__icon">⚠</div>
      <p style={{ fontWeight: 600 }}>Could not load data</p>
      <p>{message}</p>
      {onRetry && (
        <div style={{ marginTop: 12 }}>
          <button className="btn btn--sm" onClick={onRetry}>
            Try again
          </button>
        </div>
      )}
    </div>
  );
}

/** Shimmer placeholder for a data table while its query is loading. */
export function SkeletonTable({
  rows = 5,
  cols = 4,
}: {
  rows?: number;
  cols?: number;
}) {
  return (
    <div
      className="table-wrap skeleton-rows"
      style={{ padding: 14, border: "1px solid var(--border-soft)" }}
      aria-busy="true"
      aria-label="Loading"
    >
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          className="skeleton-row"
          style={{ ["--skeleton-cols" as string]: `repeat(${cols}, 1fr)` }}
        >
          {Array.from({ length: cols }).map((__, c) => (
            <div key={c} className="skeleton skeleton--text" />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Shimmer placeholder for a card body. */
export function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div className="card" aria-busy="true" aria-label="Loading">
      <div className="skeleton skeleton--title" />
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="skeleton skeleton--text"
          // Taper each line, but never below a readable minimum so larger
          // `lines` counts can't produce invalid (negative) widths.
          style={{ width: `${Math.max(30, 90 - i * 12)}%` }}
        />
      ))}
    </div>
  );
}

/**
 * Render-prop boundary that handles the standard loading / error / empty
 * lifecycle of a React Query result so pages stay declarative.
 */
export function AsyncBoundary<T>({
  isLoading,
  error,
  data,
  isEmpty,
  empty,
  loading,
  onRetry,
  children,
}: {
  isLoading: boolean;
  error: unknown;
  data: T | undefined;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  /** Custom loading placeholder (defaults to a skeleton table). */
  loading?: ReactNode;
  /** When provided, the error state shows a "Try again" button. */
  onRetry?: () => void;
  children: (data: T) => ReactNode;
}) {
  if (isLoading) return <>{loading ?? <SkeletonTable />}</>;
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (data === undefined)
    return <ErrorState error="No data returned" onRetry={onRetry} />;
  if (isEmpty?.(data)) {
    return <>{empty ?? <EmptyState title="Nothing here yet" />}</>;
  }
  return <>{children(data)}</>;
}
