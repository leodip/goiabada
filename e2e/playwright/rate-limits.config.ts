import { defineConfig, devices } from "@playwright/test";

// The rate-limits suite: the limits the auth server counts by a client's address, which every request
// from this machine shares, so it is kept apart from the e2e suite (playwright.config.ts), which runs
// with the limiter off. e2e/test-rate-limits.sh switches the limiter on for it and off again after.
// One test at a time, each starting from a restarted auth server (lib/rate-limits.ts).
export default defineConfig({
  testDir: "./rate-limits",
  outputDir: "./test-results-rate-limits",
  // The sign-in form's test signs in forty times through the browser before its failures.
  timeout: 5 * 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report-rate-limits" }]],
  use: {
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    locale: "en-US",
  },
});
