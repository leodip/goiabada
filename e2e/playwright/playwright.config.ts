import { defineConfig, devices } from "@playwright/test";

// Every test runs against the one environment e2e/infra/prepare.sh built (lib/environment.ts reads
// it), so the URLs come from there rather than from a baseURL here.
//
// The environment is shared and long-lived: a test creates what it needs under a unique name and
// removes it afterwards, changes nothing global, and never depends on what another test left, so
// the suite runs again and again without e2e/reset.sh.
export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: 4,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    locale: "en-US",
  },
  projects: [
    // Sweeps what earlier runs left, before any test starts.
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    // Each worker signs the administrator in for itself (lib/fixtures.ts).
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, dependencies: ["setup"] },
  ],
});
