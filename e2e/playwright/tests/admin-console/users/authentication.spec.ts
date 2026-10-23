import type { Browser } from "@playwright/test";
import { cancelDialog, confirmDialog, expectRefusal, userUrl } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { freshTotp } from "../../../lib/totp";

const notSetUp = "The user hasn't set up two-factor authentication. Only they can, from their account.";

// The user sets up an authenticator from their own account page, in a browser of their own.
async function enrolAuthenticator(browser: Browser, user: { email: string; password: string }) {
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("#otp-secret").innerText()).trim();
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();
  await own.context.close();
}

test("a password set here replaces the old one", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const signIn = (password: string) => passwordToken(request, client.identifier, secret, user.email, password, "openid");

  await page.goto(userUrl(user.id, "authentication"));
  // A new user has no authenticator: there is no switch, and it cannot be turned on from here.
  await expect(page.getByText(notSetUp)).toBeVisible();
  await expect(page.locator("#otpEnabled")).toHaveCount(0);
  await page.locator("#newPassword").fill("a-brand-new-password");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Changes saved.")).toBeVisible();
  // The field is never filled back in.
  await expect(page.locator("#newPassword")).toHaveValue("");

  expect((await signIn("a-brand-new-password")).status).toBe(200);
  const old = await signIn(user.password);
  expect(old.body.error).toBe("invalid_grant");
});

test("a password under the policy is refused, and the old one still works", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "authentication"));
  await page.locator("#newPassword").fill("abc");
  await page.locator("#btnSave").click();
  await expectRefusal(page, "authentication-error", "newPassword", "Use at least 15 characters for the password.");

  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await passwordToken(request, client.identifier, secret, user.email, user.password, "openid")).status).toBe(200);
});

test("turning off a user's two-factor authentication asks first: Cancel keeps it, Save turns it off", async ({ page, browser, users }) => {
  const user = await users.create();
  await enrolAuthenticator(browser, user);
  const warning = "You're turning off the user's two-factor authentication";

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator("#otpEnabled")).toBeChecked();
  await page.locator("#otpEnabled").uncheck();
  await page.locator("#btnSave").click();
  await cancelDialog(page, warning);
  // Opened afresh, so the browser restores nothing of the form.
  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator("#otpEnabled")).toBeChecked();

  await page.locator("#otpEnabled").uncheck();
  await page.locator("#btnSave").click();
  await confirmDialog(page, warning);
  await expect(page.getByText("Changes saved.")).toBeVisible();
  await expect(page.getByText(notSetUp)).toBeVisible();

  // Signing in no longer asks for a code.
  const again = await signInToConsole(browser, user);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

// The recovery the docs give for a disabled authenticator: a new password and two-factor turned off,
// in one save. An enrolled authenticator takes the same save, so the disable need not be reached.
test("a new password and two-factor turned off in one save: the old password no longer signs in", async ({ page, browser, users }) => {
  const user = await users.create();
  await enrolAuthenticator(browser, user);

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator("#otpEnabled")).toBeChecked();
  await page.locator("#newPassword").fill("a-brand-new-password");
  await page.locator("#otpEnabled").uncheck();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're turning off the user's two-factor authentication");
  await expect(page.getByText("Changes saved.")).toBeVisible();
  await expect(page.getByText(notSetUp)).toBeVisible();

  // The old password is refused at the password page, with no session at the console.
  const old = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const oldPage = await old.newPage();
  await oldPage.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(oldPage, user.email, user.password);
  await expect(oldPage).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(oldPage.locator("#pwd-error")).toHaveText("Authentication failed.");
  await old.close();

  // The new one signs in, and no code is asked.
  const again = await signInToConsole(browser, { email: user.email, password: "a-brand-new-password" });
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});
