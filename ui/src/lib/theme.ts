// Theme controller. The console ships a light (default) and a dark palette,
// both defined as CSS-variable scopes in styles.css. The operator's choice
// (Light / Dark / System) is persisted in localStorage and applied by stamping
// `data-theme="light|dark"` on <html>. "System" resolves against
// prefers-color-scheme and live-tracks OS changes.
//
// A tiny inline script in index.html applies the resolved theme before first
// paint (no flash); `initTheme()` re-applies from storage at app boot and wires
// the System-mode listener.

export type ThemeChoice = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

// Shared with the inline bootstrap in index.html — keep the key in sync.
const STORAGE_KEY = "sng-theme";

export function getStoredChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* localStorage may be unavailable (private mode); fall through */
  }
  return "system";
}

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function resolveTheme(choice: ThemeChoice): ResolvedTheme {
  if (choice === "system") return systemPrefersDark() ? "dark" : "light";
  return choice;
}

function applyResolved(choice: ThemeChoice): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-theme", resolveTheme(choice));
}

// Single OS-preference listener, rebound whenever the choice changes so it only
// fires while "System" is active.
let mql: MediaQueryList | null = null;
let mqlListener: (() => void) | null = null;

function bindSystemListener(choice: ThemeChoice): void {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return;
  }
  if (!mql) mql = window.matchMedia("(prefers-color-scheme: dark)");
  if (mqlListener) mql.removeEventListener("change", mqlListener);
  if (choice === "system") {
    mqlListener = () => applyResolved("system");
    mql.addEventListener("change", mqlListener);
  } else {
    mqlListener = null;
  }
}

export function setTheme(choice: ThemeChoice): void {
  try {
    localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    /* ignore persistence failures */
  }
  applyResolved(choice);
  bindSystemListener(choice);
}

export function initTheme(): void {
  const choice = getStoredChoice();
  applyResolved(choice);
  bindSystemListener(choice);
}
