import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const api = { "/api": `http://127.0.0.1:${process.env.VPNIX_API_PORT ?? "8000"}` };

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: api },
  preview: { proxy: api },
  build: { sourcemap: false },
});
