import { defineConfig, devices } from "@playwright/test";

// The e2e suite. Every test runs against the one environment e2e/infra/prepare.sh built
// (lib/environment.ts reads it), so the URLs come from there rather than from a baseURL here, with
// the auth server's rate limiter off: the limits it counts by an address are the rate-limits suite's
// (rate-limits.config.ts).
//
// The environment is shared and long-lived: a test creates what it needs under a unique name and
// removes it afterwards, changes nothing global, and never depends on what another test left, so
// the suite runs again and again without e2e/reset.sh.

// The one spec the Firefox and WebKit projects run.
const focusNotObscured = /accessibility\/focus-not-obscured\.spec\.ts$/;

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: 8,
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
    { name: "setup", testMatch: /.*\.setup\.ts/, teardown: "system" },
    // Each worker signs the administrator in for itself (lib/fixtures.ts).
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, dependencies: ["setup"] },
    // How a browser scrolls a focused field into view is its engine's own code, so the spec that
    // keeps the focus clear of the console's header runs in Firefox and WebKit too (#722 decision 12).
    // Every other spec runs in Chromium alone.
    { name: "firefox", testMatch: focusNotObscured, use: { ...devices["Desktop Firefox"] }, dependencies: ["setup"] },
    { name: "webkit", testMatch: focusNotObscured, use: { ...devices["Desktop Safari"] }, dependencies: ["setup"] },
    // Changes to what the whole instance shares: the settings, the signing keys, and the guards around
    // the system resource. Every other test would run against such a change, so these run once all of
    // them have finished, pass or fail (as setup's teardown, which runs after every project depending
    // on setup), one at a time, each putting back what it changed.
    { name: "system", testMatch: /.*\.system\.ts/, use: { ...devices["Desktop Chrome"] }, workers: 1, fullyParallel: false },
  ],
});
