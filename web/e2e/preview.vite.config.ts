import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
const target = process.env.VITE_API_TARGET || "http://127.0.0.1:8083";
export default defineConfig({
  root: fileURLToPath(new URL("../", import.meta.url)),
  preview: { proxy: { "/api": { target }, "/ws": { target, ws: true } } },
});
