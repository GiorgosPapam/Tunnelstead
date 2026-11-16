import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e", workers: 1, fullyParallel: false, retries: process.env.CI ? 1 : 0,
  use: { baseURL: "http://localhost:4181", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    { command: "node e2e/start-api.mjs", url: "http://127.0.0.1:8011/api/health", reuseExistingServer: false, timeout: 60_000 },
    { command: "npx vite preview --port 4181 --strictPort", url: "http://localhost:4181", reuseExistingServer: false, env: { VPNIX_API_PORT: "8011" } },
  ],
});
