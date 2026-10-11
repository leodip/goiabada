import { defineConfig, devices } from "@playwright/test";

// Every test runs against the one environment e2e/infra/prepare.sh built (lib/environment.ts reads
// it), so the URLs come from there rather than from a baseURL here.
export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  // One shared deployment, and later one shared settings row: start serial, widen once tests
  // provision their own users and clients.
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    locale: "en-US",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
