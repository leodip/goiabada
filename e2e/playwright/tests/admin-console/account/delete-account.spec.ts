// A user deleting their own account from Account, Delete account (#783): with the password alone,
// with an authentication code and with a recovery code, each asked first in a confirmation dialog,
// landing on /account/deleted, sending "Your account was deleted", and leaving nothing to sign in
// with. A wrong password is refused on the form, with nothing deleted.
import type { APIRequestContext, Browser, Page } from "@playwright/test";
import { cancelDialog, confirmDialog } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { signInToConsole, turnOnTwoFactor, type ConsoleUser } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { mailTo } from "../../../lib/mailpit";
import { freshTotp } from "../../../lib/totp";

// Presses Delete my account and answers the dialog, which asks first.
async function deleteMyAccount(page: Page) {
  await page.getByRole("button", { name: "Delete my account" }).click();
  await confirmDialog(page, "This can't be undone.");
}

// The page the deletion lands on, the same for anyone, with no menu.
async function expectDeleted(page: Page) {
  await expect(page).toHaveURL(`${env.adminUrl}/account/deleted`);
  await expect(page.getByRole("heading", { name: "Your account is deleted" })).toBeVisible();
  await expect(page.getByText("account is gone, and you're signed out everywhere.")).toBeVisible();
  await expect(page.locator("nav.sidebar")).toHaveCount(0);
  // A reload resubmits nothing and draws the same page.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Your account is deleted" })).toBeVisible();
}

// The deletion notice, in Mailpit, sent after the response.
async function expectDeletionNotice(request: APIRequestContext, address: string) {
  await expect
    .poll(async () => (await mailTo(request, address)).map((message) => message.Subject), {
      message: `the deletion notice to ${address}`,
      timeout: 30_000,
    })
    .toContain("Your account was deleted");
}

// Nothing is left to sign in with: the password page refuses the address and password.
async function expectSignInRefused(browser: Browser, user: ConsoleUser) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(page, user.email, user.password);
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(page.locator("#pwd-error")).toBeVisible();
  await context.close();
}

test("the page says what is deleted and what isn't, and Cancel deletes nothing", async ({ browser, users }) => {
  const user = await users.create({ emailVerified: true });
  const own = await signInToConsole(browser, user, "/account/delete");
  const page = own.page;

  await expect(page).toHaveTitle(/^Delete your account – /);
  await expect(page.getByRole("heading", { name: "Delete your account", level: 1 })).toBeVisible();
  await expect(page.getByText("account is deleted at once. This can't be undone.")).toBeVisible();
  await expect(page.getByText("What's deleted:")).toBeVisible();
  await expect(page.getByText("What isn't:")).toBeVisible();
  // Without two-factor authentication the page asks for the password alone.
  await expect(page.locator('input[name="otp"]')).toHaveCount(0);

  await page.getByLabel("Password", { exact: true }).fill(user.password);
  await page.getByRole("button", { name: "Delete my account" }).click();
  await cancelDialog(page, "Delete your account?");
  await expect(page).toHaveURL(`${env.adminUrl}/account/delete`);
  await own.context.close();

  // Still there: the user signs in again.
  const again = await signInToConsole(browser, user);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("a wrong password is refused on the form, with nothing deleted", async ({ browser, users }) => {
  const user = await users.create({ emailVerified: true });
  const own = await signInToConsole(browser, user, "/account/delete");

  await own.page.getByLabel("Password", { exact: true }).fill("not-the-password");
  await deleteMyAccount(own.page);
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/delete`);
  await expect(own.page.locator("#delete-error")).toHaveText("That password isn't right. Try again.");
  await expect(own.page.locator("#password")).toHaveAttribute("aria-invalid", "true");
  await own.context.close();

  const again = await signInToConsole(browser, user);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("a deletion with the password lands on /account/deleted, mails the user and ends the account", async ({
  browser,
  request,
  users,
}) => {
  const user = await users.create({ emailVerified: true });
  const own = await signInToConsole(browser, user, "/account/delete");

  await own.page.getByLabel("Password", { exact: true }).fill(user.password);
  await deleteMyAccount(own.page);
  user.markDeleted();
  await expectDeleted(own.page);

  // The console's session is gone: an account page sends the browser to sign in.
  await own.page.goto(`${env.adminUrl}/account/profile`);
  await expect(own.page).toHaveURL(new RegExp(`^${env.authUrl}/auth/`));
  await own.context.close();

  await expectDeletionNotice(request, user.email);
  await expectSignInRefused(browser, user);
});

test("with two-factor authentication on, a deletion with the authentication code", async ({ browser, request, users }) => {
  const user = await users.create({ emailVerified: true });
  const { secret } = await turnOnTwoFactor(browser, user);
  const own = await signInToConsole(browser, { ...user, otpSecret: secret }, "/account/delete");

  await own.page.getByLabel("Password", { exact: true }).fill(user.password);
  await own.page.getByLabel("Authentication code").fill(await freshTotp(secret));
  await deleteMyAccount(own.page);
  user.markDeleted();
  await expectDeleted(own.page);
  await own.context.close();

  await expectDeletionNotice(request, user.email);
  await expectSignInRefused(browser, user);
});

test("with two-factor authentication on, a deletion with a recovery code instead", async ({ browser, request, users }) => {
  const user = await users.create({ emailVerified: true });
  const { secret, recoveryCodes } = await turnOnTwoFactor(browser, user);
  const own = await signInToConsole(browser, { ...user, otpSecret: secret }, "/account/delete");
  const page = own.page;

  // The choice swaps the authentication code for the recovery code, and back.
  await page.getByRole("button", { name: "Use a recovery code instead" }).click();
  await expect(page.getByLabel("Authentication code")).toBeHidden();
  await page.getByRole("button", { name: "Use your authenticator app instead" }).click();
  await expect(page.getByLabel("Recovery code")).toBeHidden();
  await page.getByRole("button", { name: "Use a recovery code instead" }).click();

  // A wrong code is refused on its field, and the recovery code stays the one asked for.
  await page.getByLabel("Password", { exact: true }).fill(user.password);
  await page.getByLabel("Recovery code").fill("0000-0000-0000-0000-0000-0000");
  await deleteMyAccount(page);
  await expect(page.locator("#delete-error")).toHaveText("That recovery code isn't right, or it was already used.");
  await expect(page.getByLabel("Recovery code")).toHaveAttribute("aria-invalid", "true");

  await page.getByLabel("Password", { exact: true }).fill(user.password);
  await page.getByLabel("Recovery code").fill(recoveryCodes[0]);
  await deleteMyAccount(page);
  user.markDeleted();
  await expectDeleted(page);
  await own.context.close();

  await expectDeletionNotice(request, user.email);
  // One notice: the deletion's, with no "recovery code used" notice beside it (#783 decision 2).
  const subjects = (await mailTo(request, user.email)).map((message) => message.Subject);
  expect(subjects).not.toContain("A recovery code was used to sign in");
  await expectSignInRefused(browser, user);
});
