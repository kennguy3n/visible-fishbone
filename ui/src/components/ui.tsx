import type { ReactNode } from "react";
import { statusTone, titleCase, type Tone } from "@/lib/format";

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
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  return <Badge tone={statusTone(status)}>{titleCase(status)}</Badge>;
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

export function EmptyState({
  icon = "∅",
  title,
  hint,
  action,
}: {
  icon?: string;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="state">
      <div className="state__icon">{icon}</div>
      <p style={{ fontWeight: 600, color: "var(--text)" }}>{title}</p>
      {hint && <p style={{ maxWidth: "50ch" }}>{hint}</p>}
      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
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
  children,
}: {
  isLoading: boolean;
  error: unknown;
  data: T | undefined;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (data === undefined) return <ErrorState error="No data returned" />;
  if (isEmpty?.(data)) {
    return <>{empty ?? <EmptyState title="Nothing here yet" />}</>;
  }
  return <>{children(data)}</>;
}
