// The Turnstile challenge on the auth server's forms, with the real widget and Cloudflare's public
// test keys, which work on any host name (#642 decision 6): the always-pass site key's widget
// solves itself and the form goes on, the always-block one's leaves no token and the form is
// refused with the address typed kept. The fixtures' watcher fails a test on any
// Content-Security-Policy violation, so the widget's script and frame load under the policy the
// forms are sent. The sign-in, forgot-password and registration forms each carry it. Runs alone, since on the challenge refuses every other test's sign-in, and every
// test starts and ends with it off and no keys stored, as the baseline has it (lib/settings.ts).
import type { Browser, Page } from "@playwright/test";
import { openSignIn, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { browserSignInClient } from "../../lib/test-clients";
import { uniqueIdentifier } from "../../lib/unique";

const turnstile = "/admin/settings/turnstile";
const general = "/admin/settings/general";
const forgotPasswordUrl = `${env.authUrl}/forgot-password`;
const registerUrl = `${env.authUrl}/account/register`;
const alwaysPassSiteKey = "1x00000000000000000000AA";
const alwaysBlockSiteKey = "2x00000000000000000000AB";
const alwaysPassSecretKey = "1x0000000000000000000000000000000AA";

const refusal = "Complete the security check, then try again. The check needs JavaScript.";

// Turns the challenge on, with siteKey and the always-pass secret key. The administrator's console
// session is already signed in, so the challenge does not stand in its way.
async function turnOn(page: Page, siteKey: string) {
  await page.goto(`${env.adminUrl}${turnstile}`);
  await fillSettingsForm(page, { turnstileEnabled: true, turnstileSiteKey: siteKey, turnstileSecretKey: alwaysPassSecretKey });
  await saveSettings(page);
}

// Turns the challenge off and removes both keys, which a save does only with the removal ticked.
async function turnOff(page: Page) {
  await page.goto(`${env.adminUrl}${turnstile}`);
  const hasSecretKey = (await page.locator("#clearTurnstileSecretKey").count()) > 0;
  const enabled = await page.locator("#turnstileEnabled").isChecked();
  const storedSiteKey = await page.locator("#turnstileSiteKey").inputValue();
  if (!hasSecretKey && !enabled && storedSiteKey === "") return;
  await fillSettingsForm(page, {
    turnstileEnabled: false,
    turnstileSiteKey: "",
    ...(hasSecretKey ? { clearTurnstileSecretKey: true } : {}),
  });
  await saveSettings(page);
}

// Opens url in a browser of its own, signed in nowhere, as a visitor would.
async function openAsVisitor(browser: Browser, url: string) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const visitor = await context.newPage();
  await visitor.goto(url);
  return { context, visitor };
}

// The widget, inside the form so its token is submitted with it, and the hidden field it writes
// the token into once it has run.
function widget(page: Page, action: string) {
  return page.locator(`form .cf-turnstile[data-action="${action}"]`);
}
function token(page: Page) {
  return page.locator('form input[name="cf-turnstile-response"]');
}

test.beforeEach(async ({ page }) => {
  await turnOff(page);
});

test.afterEach(async ({ page }) => {
  await turnOff(page);
});

test("sign-in: the always-pass widget solves itself and the sign-in goes on", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await turnOn(page, alwaysPassSiteKey);

  const { context, page: signIn } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(widget(signIn, "login")).toHaveAttribute("data-sitekey", alwaysPassSiteKey);
  await expect(token(signIn)).toHaveValue(/.+/);

  await submitPassword(signIn, user.email, user.password);
  await signIn.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/consent");
  await context.close();
});

test("sign-in: the always-block widget leaves no token, and the refusal keeps the address typed", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await turnOn(page, alwaysBlockSiteKey);

  const { context, page: signIn } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(widget(signIn, "login")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
  await expect(token(signIn)).toBeAttached();

  await submitPassword(signIn, user.email, user.password);
  await expect(signIn.getByRole("alert")).toHaveText(refusal);
  expect(new URL(signIn.url()).pathname).toBe("/auth/pwd");
  await expect(signIn.locator('input[name="email"]')).toHaveValue(user.email.toLowerCase());
  // The form is drawn again with a fresh widget.
  await expect(widget(signIn, "login")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
  await context.close();
});

test("sign-in: with the challenge off, the form loads nothing from Cloudflare", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);

  const { context, page: signIn } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signIn.locator('input[name="email"]')).toBeVisible();
  await expect(signIn.locator(".cf-turnstile")).toHaveCount(0);
  await expect(signIn.locator('script[src^="https://challenges.cloudflare.com"]')).toHaveCount(0);
  await context.close();
});

test("forgot-password: the always-pass widget solves itself and the request is answered", async ({ page, browser }) => {
  await turnOn(page, alwaysPassSiteKey);
  const address = `${uniqueIdentifier("t")}@example.com`;

  const { context, visitor } = await openAsVisitor(browser, forgotPasswordUrl);
  await expect(widget(visitor, "forgot-password")).toHaveAttribute("data-sitekey", alwaysPassSiteKey);
  await expect(token(visitor)).toHaveValue(/.+/);

  await visitor.locator("#email").fill(address);
  await visitor.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(visitor.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await expect(visitor.locator("code.auth-address")).toHaveText(address);
  await context.close();
});

test("forgot-password: the always-block widget leaves no token, and the refusal keeps the address typed", async ({ page, browser }) => {
  await turnOn(page, alwaysBlockSiteKey);
  const address = `${uniqueIdentifier("t")}@example.com`;

  const { context, visitor } = await openAsVisitor(browser, forgotPasswordUrl);
  await expect(widget(visitor, "forgot-password")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
  await expect(token(visitor)).toBeAttached();

  await visitor.locator("#email").fill(address);
  await visitor.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(visitor.getByRole("alert")).toHaveText(refusal);
  expect(new URL(visitor.url()).pathname).toBe("/forgot-password");
  await expect(visitor.locator("#email")).toHaveValue(address);
  // The form is drawn again with a fresh widget.
  await expect(widget(visitor, "forgot-password")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
  await context.close();
});

test("registration: the always-pass widget solves itself and the address is registered", async ({ page, browser }) => {
  await withSettingsRestored(page, general, async () => {
    // Self-registration on, with email verification as seeded: the address alone is asked for.
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
    await saveSettings(page);
    await turnOn(page, alwaysPassSiteKey);
    const address = `${uniqueIdentifier("t")}@example.com`;

    const { context, visitor } = await openAsVisitor(browser, registerUrl);
    await expect(widget(visitor, "register")).toHaveAttribute("data-sitekey", alwaysPassSiteKey);
    await expect(token(visitor)).toHaveValue(/.+/);

    await visitor.locator("#email").fill(address);
    await visitor.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(visitor.getByRole("heading", { name: "Check your email" })).toBeVisible();
    await expect(visitor.locator("code.auth-address")).toHaveText(address);
    await context.close();
  });
});

test("registration: the always-block widget leaves no token, and the refusal keeps the address typed", async ({ page, browser }) => {
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
    await saveSettings(page);
    await turnOn(page, alwaysBlockSiteKey);
    const address = `${uniqueIdentifier("t")}@example.com`;

    const { context, visitor } = await openAsVisitor(browser, registerUrl);
    await expect(widget(visitor, "register")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
    await expect(token(visitor)).toBeAttached();

    await visitor.locator("#email").fill(address);
    await visitor.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(visitor.getByRole("alert")).toHaveText(refusal);
    expect(new URL(visitor.url()).pathname).toBe("/account/register");
    await expect(visitor.locator("#email")).toHaveValue(address);
    await expect(widget(visitor, "register")).toHaveAttribute("data-sitekey", alwaysBlockSiteKey);
    await context.close();
  });
});

test("forgot-password: with the challenge off, the form loads nothing from Cloudflare", async ({ browser }) => {
  const { context, visitor } = await openAsVisitor(browser, forgotPasswordUrl);
  await expect(visitor.locator("#email")).toBeVisible();
  await expect(visitor.locator(".cf-turnstile")).toHaveCount(0);
  await expect(visitor.locator('script[src^="https://challenges.cloudflare.com"]')).toHaveCount(0);
  await context.close();
});
