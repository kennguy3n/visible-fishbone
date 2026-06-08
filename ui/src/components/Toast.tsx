import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export type ToastKind = "success" | "error" | "info";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
  leaving?: boolean;
}

interface ToastApi {
  push: (kind: ToastKind, title: string, message?: string) => void;
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const ICONS: Record<ToastKind, string> = {
  success: "✓",
  error: "✕",
  info: "ℹ",
};

const VISIBLE_MS = 5000;
const EXIT_MS = 180;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const remove = useCallback((id: number) => {
    // Animate out, then drop from state after the exit transition.
    setToasts((prev) =>
      prev.map((t) => (t.id === id ? { ...t, leaving: true } : t)),
    );
    const exit = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
      timers.current.delete(id);
    }, EXIT_MS);
    timers.current.set(id, exit);
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, message?: string) => {
      const id = ++idRef.current;
      setToasts((prev) => [...prev, { id, kind, title, message }]);
      const auto = setTimeout(() => remove(id), VISIBLE_MS);
      timers.current.set(id, auto);
    },
    [remove],
  );

  const api = useMemo<ToastApi>(
    () => ({
      push,
      success: (title, message) => push("success", title, message),
      error: (title, message) => push("error", title, message),
      info: (title, message) => push("info", title, message),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-viewport" role="region" aria-label="Notifications">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast--${t.kind}${t.leaving ? " toast--leaving" : ""}`}
            role={t.kind === "error" ? "alert" : "status"}
          >
            <span className="toast__icon" aria-hidden>
              {ICONS[t.kind]}
            </span>
            <div className="toast__body">
              <div className="toast__title">{t.title}</div>
              {t.message && <div className="toast__msg">{t.message}</div>}
            </div>
            <button
              className="toast__close"
              aria-label="Dismiss notification"
              onClick={() => remove(t.id)}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
