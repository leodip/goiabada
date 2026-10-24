import { defineConfig, devices } from "@playwright/test";
import { env } from "./lib/environment";

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
  // With the rate limiter on, every test signs in against the budgets of this machine's one address,
  // which four at a time stay under; with it off nothing counts the address, and eight run at once.
  workers: env.rateLimiter ? 4 : 8,
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
    // Changes to what the whole instance shares: the settings, the signing keys, and the guards around
    // the system resource. Every other test would run against such a change, so these run once all of
    // them have finished, pass or fail (as setup's teardown, which runs after every project depending
    // on setup), one at a time, each putting back what it changed.
    { name: "system", testMatch: /.*\.system\.ts/, use: { ...devices["Desktop Chrome"] }, workers: 1, fullyParallel: false },
  ],
});
