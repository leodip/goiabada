// The auth server's own pages a user of the test app meets beyond the steps the other files drive:
// the two-factor setup page's key, for an authenticator app that cannot scan the QR code, and its
// Copy key; the page an older tab of a sign-in started again meets; and the not found page.
import type { Browser, BrowserContextOptions } from "@playwright/test";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, type TestUser, test } from "../../lib/fixtures";
import { expectResult, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

// Signs the user in to the web app at level 2 mandatory, in a browser of their own with these
// options, and returns once the page that sets up their authenticator shows. initScript runs in the
// page before its own scripts. The caller closes the context.
async function openTwoFactorSetup(browser: Browser, user: TestUser, options: BrowserContextOptions = {}, initScript?: () => void) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, ...options });
  if (initScript) await context.addInitScript(initScript);
  const page = await context.newPage();
  await signInToWebApp(page, testapp.web, user, { acr_values: "urn:goiabada:level2_mandatory" });
  await expect(page.getByRole("heading", { name: "Set up two-factor authentication" })).toBeVisible();
  const key = (await page.locator("#otp-secret").innerText()).trim();
  expect(key, "a base32 key").toMatch(/^[A-Z2-7]+=*$/);
  return { context, page, key };
}

test("Copy key on the two-factor setup page copies the key it shows", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page, key } = await openTwoFactorSetup(browser, user, { permissions: ["clipboard-read", "clipboard-write"] });
  await page.getByRole("button", { name: "Copy key" }).click();
  await expect(page.getByRole("button", { name: "Key copied" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(key);
  await context.close();
});

test("without the clipboard, the two-factor setup page offers no Copy key, and the key is there to copy by hand", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await openTwoFactorSetup(browser, user, {}, () => {
    Object.defineProperty(Navigator.prototype, "clipboard", { get: () => undefined, configurable: true });
  });
  const copy = page.getByRole("button", { name: "Copy key", includeHidden: true });
  await expect(copy).toHaveCount(1);
  await expect(copy).toBeHidden();
  await expect(page.locator("#otp-secret")).toBeVisible();
  await context.close();
});

test("a copy the browser refuses selects the key instead, and says so", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page, key } = await openTwoFactorSetup(browser, user, {}, () => {
    Clipboard.prototype.writeText = () => Promise.reject(new DOMException("Write permission denied.", "NotAllowedError"));
  });
  await page.getByRole("button", { name: "Copy key" }).click();
  await expect(page.getByRole("button", { name: "Couldn't copy" })).toBeVisible();
  await expect(page.locator("#otp-secret-copied")).toHaveText("Couldn't copy the key. It's selected, so you can copy it yourself.");
  expect(await page.evaluate(() => window.getSelection()?.toString().trim())).toBe(key);
  await context.close();
});

// A browser holds one sign-in at a time: starting another replaces it, and a tab of the first one
// can no longer go on, so it cannot finish the newer one's authorization either.
test("a sign-in started again in another tab leaves the first tab saying its request is no longer active, and the new one goes on", async ({
  browser,
  users,
}) => {
  const user = await users.create();
  const { context, page: first } = await userBrowser(browser);
  await first.goto(`${testapp.web.url}/login`);
  await expect(first).toHaveURL(/\/auth\/pwd/);
  const second = await context.newPage();
  await second.goto(`${testapp.web.url}/login`);
  await expect(second).toHaveURL(/\/auth\/pwd/);

  await submitPassword(first, user.email, user.password);
  await expect(first.getByRole("heading", { name: "This request is no longer active" })).toBeVisible();
  await expect(first).toHaveTitle(/^This request is no longer active – /);
  await expect(first.locator("#errorMsg")).toContainText("Another one was started in this browser, so this one can no longer continue.");

  await submitPassword(second, user.email, user.password);
  await second.waitForURL(testapp.web.url);
  await expectResult(second, "Signed in");
  await context.close();
});

test("an address the auth server doesn't have says so, and its one action leads to the admin console's home page", async ({ page }) => {
  const response = await page.goto(`${env.authUrl}/no-such-page`);
  expect(response?.status()).toBe(404);
  await expect(page).toHaveTitle(/^Page not found – /);
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await expect(page.getByText("The address may be mistyped, or the page may have moved.")).toBeVisible();

  await page.getByRole("link", { name: "Go to the home page" }).click();
  await expect(page).toHaveURL((url) => url.origin === env.adminUrl);
  await expect(page.getByRole("heading", { name: "Admin console" })).toBeVisible();
});
