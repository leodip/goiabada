// A user other than the administrator, signed in to the admin console in a browser of their own.
import { expect, type Browser } from "@playwright/test";
import { submitPassword } from "./browser-sign-in";
import { env } from "./environment";
import { userAgentFor } from "./devices";
import { freshTotp } from "./totp";

export interface ConsoleUser {
  email: string;
  password: string;
  // The user's authenticator secret, once they have enrolled one.
  otpSecret?: string;
}

// Opens the console at path in a new browser as the user, signing in on the way, with a code when
// the user has an authenticator. The caller closes the context.
export async function signInToConsole(browser: Browser, user: ConsoleUser, device: string, path = "/account/profile") {
  // An explicit empty state: inside a test, browser.newContext() starts from the test's options, which
  // carry the administrator's signed-in state.
  const context = await browser.newContext({ userAgent: userAgentFor(device), storageState: { cookies: [], origins: [] } });
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
