import { defineConfig, devices } from "@playwright/test";

// Not the suite: the one script e2e/infra/testapp.sh runs to set up the test app's clients in the
// environment, before the test app is deployed. playwright.config.ts never picks it up, since its
// testDir is ./tests.
export default defineConfig({
  testDir: "./provision",
  testMatch: /.*\.provision\.ts/,
  timeout: 180_000,
  expect: { timeout: 10_000 },
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    locale: "en-US",
  },
});
