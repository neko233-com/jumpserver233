import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const apiTarget = env.VITE_API_TARGET || "http://127.0.0.1:8080";
  return {
    plugins: [react()],
    build: { manifest: true, outDir: process.env.JMS_E2E_WEB_DIR || "dist" },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: apiTarget,
          changeOrigin: true,
        },
        "/ws": {
          target: apiTarget.replace(/^http/, "ws"),
          ws: true,
        },
      },
    },
  };
});
