// A user other than the administrator, signed in to the admin console in a browser of their own.
import { expect, type Browser, type Page } from "@playwright/test";
import { submitPassword } from "./browser-sign-in";
import { env } from "./environment";
import { freshTotp } from "./totp";

export interface ConsoleUser {
  email: string;
  password: string;
  // The user's authenticator secret, once they have enrolled one.
  otpSecret?: string;
}

// Opens the console at path in a new browser as the user, signing in on the way, with a code when
// the user has an authenticator. The caller closes the context.
export async function signInToConsole(browser: Browser, user: ConsoleUser, path = "/account/profile") {
  // An explicit empty state: inside a test, browser.newContext() starts from the test's options, which
  // carry the administrator's signed-in state.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(`${env.adminUrl}${path}`);
  await submitPassword(page, user.email, user.password);
  if (user.otpSecret) {
    await expect(page).toHaveURL(/\/auth\/otp/);
    await page.locator('input[name="otp"]').fill(await freshTotp(user.otpSecret));
    await page.getByRole("button", { name: "Verify" }).click();
  }
  await page.waitForURL((url) => url.origin === env.adminUrl);
  return { context, page };
}

// Turns on two-factor authentication from the user's own account page, in a browser of their own,
// and returns the authenticator's secret and the ten recovery codes the page shows once.
export async function turnOnTwoFactor(browser: Browser, user: ConsoleUser): Promise<{ secret: string; recoveryCodes: string[] }> {
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("#otp-secret").innerText()).trim();
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();
  const recoveryCodes = (await own.page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts())
    .map((code) => code.trim());
  expect(recoveryCodes).toHaveLength(10);
  await own.context.close();
  return { secret, recoveryCodes };
}

// The refusal the recovery-code form shows for a wrong code, one of a replaced set and a used one alike.
export const recoveryCodeRefused = "That recovery code isn't right, or it was already used.";

// At the page asking for a code, follows "Use a recovery code instead" and sends code from the
// recovery-code form.
export async function enterRecoveryCode(page: Page, code: string) {
  await expect(page).toHaveURL(/\/auth\/otp/);
  if ((await page.locator('input[name="recoveryCode"]').count()) === 0) {
    await page.getByRole("link", { name: "Use a recovery code instead" }).click();
  }
  await page.getByLabel("Recovery code").fill(code);
  await page.getByRole("button", { name: "Verify" }).click();
}
