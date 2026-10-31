// The auth server's own pages a user of the test app meets beyond the steps the other files drive:
// the two-factor setup page's key, for an authenticator app that cannot scan the QR code, and its
// Copy key; the page after it showing the new authenticator's recovery codes once, and its Copy
// codes; two tabs signing in side by side, and the page a sign-in pushed out meets; and the not
// found page.
import type { Browser, BrowserContextOptions } from "@playwright/test";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, type TestUser, test } from "../../lib/fixtures";
import { expectResult, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";
import { freshTotp } from "../../lib/totp";

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

// The code from the setup page sends the user to a page of its own showing the ten recovery codes the
// authenticator came with (#257 decision 14). Copy codes copies them, one a line; a reload shows them
// no more, and Continue on either page finishes the sign-in.
test("after two-factor setup, the recovery codes are shown once, Copy codes copies them, and Continue signs in", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page, key } = await openTwoFactorSetup(browser, user, { permissions: ["clipboard-read", "clipboard-write"] });
  await page.locator('input[name="otp"]').fill(await freshTotp(key));
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page).toHaveURL(/\/auth\/recovery-codes/);
  await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  const shown = (await page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts()).map((c) => c.trim());
  expect(shown).toHaveLength(10);
  await page.getByRole("button", { name: "Copy codes" }).click();
  await expect(page.getByRole("button", { name: "Codes copied" })).toBeVisible();
  expect((await page.evaluate(() => navigator.clipboard.readText())).split(/\s+/).filter(Boolean)).toEqual(shown);

  await page.reload();
  await expect(page.getByRole("heading", { name: "Your recovery codes were already shown" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Recovery codes" })).toHaveCount(0);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForURL(testapp.web.url);
  await expectResult(page, "Signed in");
  await context.close();
});

// A browser holds up to five sign-ins side by side, each finishing on its own, so a user signing in
// to two applications from two tabs finishes both (#246). Two applications, since each keeps one
// sign-in of its own per browser.
test("sign-ins started in two tabs both finish", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: first } = await userBrowser(browser);
  await first.goto(`${testapp.web.url}/login`);
  await expect(first).toHaveURL(/\/auth\/pwd/);
  const second = await context.newPage();
  await second.goto(`${testapp.web2.url}/login`);
  await expect(second).toHaveURL(/\/auth\/pwd/);

  await submitPassword(first, user.email, user.password);
  await first.waitForURL(testapp.web.url);
  await expectResult(first, "Signed in");

  await submitPassword(second, user.email, user.password);
  await second.waitForURL(testapp.web2.url);
  await expectResult(second, "Signed in");
  await context.close();
});

// A sixth sign-in pushes out the one least recently moved, and that sign-in's next page says its
// request is no longer active, in words that do not blame a newer sign-in; the newer ones go on.
test("a sign-in pushed out by five newer ones says its request is no longer active, and the newer ones go on", async ({
  browser,
  users,
}) => {
  const user = await users.create();
  const { context, page: first } = await userBrowser(browser);
  await first.goto(`${testapp.web.url}/login`);
  await expect(first).toHaveURL(/\/auth\/pwd/);
  const newer = await context.newPage();
  for (let i = 0; i < 5; i++) {
    await newer.goto(`${testapp.web2.url}/login`);
    await expect(newer).toHaveURL(/\/auth\/pwd/);
  }

  await submitPassword(first, user.email, user.password);
  await expect(first.getByRole("heading", { name: "This request is no longer active" })).toBeVisible();
  await expect(first).toHaveTitle(/^This request is no longer active – /);
  await expect(first.locator("#errorMsg")).toHaveText(
    "This page belongs to a sign-in that can no longer continue. It may have finished already, or a later sign-in or sign-out in this browser ended it. Go back to the application you were signing in to and start again.",
  );

  await submitPassword(newer, user.email, user.password);
  await newer.waitForURL(testapp.web2.url);
  await expectResult(newer, "Signed in");
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
