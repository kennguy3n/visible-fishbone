// Shared formatting + presentation helpers.

export type Tone = "ok" | "warn" | "danger" | "neutral" | "info";

const OK = new Set([
  "active",
  "healthy",
  "enabled",
  "online",
  "ok",
  "resolved",
  "approved",
  "completed",
  "succeeded",
  "success",
  "connected",
  "compliant",
  "pass",
]);
const WARN = new Set([
  "pending",
  "degraded",
  "warning",
  "suspended",
  "draft",
  "syncing",
  "in_progress",
  "running",
  "partial",
  "shadow",
]);
const DANGER = new Set([
  "failed",
  "error",
  "revoked",
  "deleted",
  "offline",
  "disabled",
  "unhealthy",
  "critical",
  "rejected",
  "expired",
  "blocked",
  "noncompliant",
  "fail",
]);

/** Map an arbitrary status string to a badge tone. */
export function statusTone(status?: string | null): Tone {
  if (!status) return "neutral";
  const s = status.toLowerCase();
  if (OK.has(s)) return "ok";
  if (WARN.has(s)) return "warn";
  if (DANGER.has(s)) return "danger";
  return "info";
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const diffMs = Date.now() - d.getTime();
  const sec = Math.round(diffMs / 1000);
  const abs = Math.abs(sec);
  const units: [number, string][] = [
    [60, "s"],
    [3600, "m"],
    [86400, "h"],
    [2592000, "d"],
  ];
  if (abs < 60) return `${sec}s ago`;
  for (let i = 1; i < units.length; i++) {
    if (abs < units[i][0]) {
      return `${Math.round(sec / units[i - 1][0])}${units[i - 1][1]} ago`;
    }
  }
  return `${Math.round(sec / 86400)}d ago`;
}

export function shortId(id?: string | null): string {
  if (!id) return "—";
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

export function formatNumber(n?: number | null): string {
  if (n == null) return "—";
  return n.toLocaleString();
}

export function titleCase(s?: string | null): string {
  if (!s) return "—";
  return s
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
