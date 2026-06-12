import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Vitest config for the console's component/route tests. Kept separate from
// vite.config.ts so the build pipeline stays untouched. jsdom gives the
// React Testing Library renders a DOM, and the "@" alias mirrors the app
// tsconfig path mapping.
export default defineConfig({
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.{ts,tsx}"],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
