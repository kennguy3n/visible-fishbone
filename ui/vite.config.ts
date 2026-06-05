import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Dev convenience: proxy API calls to a locally-running
      // sng-control so the UI can be developed without CORS config.
      "/api": {
        target: process.env.SNG_API_PROXY ?? "http://localhost:8080",
        changeOrigin: true,
      },
      "/scim": {
        target: process.env.SNG_API_PROXY ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
