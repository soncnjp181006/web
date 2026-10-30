import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    sourcemap: true, // [VULN #43] sourcemaps deployed to production -> source disclosure
  },
  // local/CI verification only: proxy API to the backend (same as Cloudflare _redirects in prod).
  // CHỈ proxy path API của ST - /auth (UI) phải do SPA phục vụ.
  preview: {
    port: 4173,
    proxy: {
      "/api": "http://127.0.0.1:4000",
      "/graphql": "http://127.0.0.1:4000",
      "/uploads": "http://127.0.0.1:4000",
      "/auth/signup": "http://127.0.0.1:4000",
      "/auth/signin": "http://127.0.0.1:4000",
      "/auth/signout": "http://127.0.0.1:4000",
      "/auth/session": "http://127.0.0.1:4000",
      "/auth/user": "http://127.0.0.1:4000",
      "/auth/dashboard": "http://127.0.0.1:4000",
      "/ws": { target: "ws://127.0.0.1:4000", ws: true },
    },
  },
});
