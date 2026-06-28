import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built `dist/` in production and the dev server in dev.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
});
