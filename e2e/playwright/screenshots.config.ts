import { defineConfig } from "@playwright/test";

// Not a suite: the capture e2e/screenshots.sh runs in its own Compose project (e2e/screenshots.yml),
// against the servers it started there, in the browser of Playwright's image. playwright.config.ts
// never picks it up, since its testDir is ./tests. The images are in the dark scheme and in English,
// at one CSS pixel to a pixel; each spec sets its own viewport.
export default defineConfig({
  testDir: "./screenshots",
  testMatch: /.*\.screenshots\.ts/,
  timeout: 300_000,
  expect: { timeout: 15_000 },
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    // The long wait is the whole run, which creates the sample users one by one: a control the
    // capture cannot find, or a page that does not load, fails within these instead.
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    browserName: "chromium",
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "dark",
    deviceScaleFactor: 1,
  },
});
