import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import {
  MutationCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { AuthProvider } from "@/auth/auth-context";
import { LocaleProvider } from "@/lib/i18n/locale-context";
import { ToastProvider } from "@/components/Toast";
import { router } from "@/router";
import "@/styles.css";

// The orval-generated mutation hooks don't invalidate query caches on success
// (unlike the hand-written hooks in src/api/manual/hooks.ts). Without a global
// rule, list views backed by the generated client would show stale data for up
// to `staleTime` (30s) after an ack/resolve/delete/etc. Invalidating all active
// queries on every successful mutation keeps every page consistent without
// having to remember per-call `onSuccess` wiring across ~24 generated
// endpoints; any per-call `onSuccess` the page passes still runs (this is
// additive, not a replacement).
const queryClient: QueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
  mutationCache: new MutationCache({
    onSuccess: () => {
      void queryClient.invalidateQueries();
    },
  }),
});

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found");

createRoot(rootEl).render(
  <StrictMode>
    <LocaleProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastProvider>
            <RouterProvider router={router} />
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
    </LocaleProvider>
  </StrictMode>,
);
