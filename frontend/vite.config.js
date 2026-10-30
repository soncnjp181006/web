import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    sourcemap: true, // [VULN #43] sourcemaps deployed to production -> source disclosure
  },
});
