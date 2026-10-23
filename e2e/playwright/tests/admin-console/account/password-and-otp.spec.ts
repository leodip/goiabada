// The user's own password and authenticator, and what each changes at sign-in.
import type { Page } from "@playwright/test";
import { expectRefusal, userUrl } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { freshTotp, totp } from "../../../lib/totp";

const wrongPassword = "That password isn't right. Try again.";
const wrongCode = "That code isn't right. Codes change every 30 seconds, so enter the one your app shows now.";
const noCode = "Enter the 6-digit code from your authenticator app.";

// Turns two-factor authentication on from the account page open on page, with the key the page
// shows, which it returns.
async function turnOn(page: Page, password: string): Promise<string> {
  const secret = (await page.locator("#otp-secret").innerText()).trim();
  await page.locator("#password").fill(password);
  await page.locator("#otp").fill(await freshTotp(secret));
  await page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(page.getByText("Two-factor authentication is on.")).toBeVisible();
  return secret;
}

test("the user changes their password: the current one must be right, and the new one confirmed", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const submit = async (current: string, next: string, confirmation: string) => {
    await own.page.locator("#currentPassword").fill(current);
    await own.page.locator("#newPassword").fill(next);
    await own.page.locator("#newPasswordConfirmation").fill(confirmation);
    await own.page.getByRole("button", { name: "Change password" }).click();
  };

  await submit(user.password, "a-new-passphrase", "a-different-one");
  await expectRefusal(own.page, "password-error", "newPasswordConfirmation", "The passwords don't match.", { focused: false });
  await submit("", "a-new-passphrase", "a-new-passphrase");
  await expectRefusal(own.page, "password-error", "currentPassword", "Current password is required.");
  await submit("not-the-password", "a-new-passphrase", "a-new-passphrase");
  await expectRefusal(own.page, "password-error", "currentPassword", wrongPassword);
  await submit(user.password, "abc", "abc");
  await expectRefusal(own.page, "password-error", "newPassword", "Use at least 15 characters for the password.", { focused: false });
  await submit(user.password, "a-new-passphrase", "a-new-passphrase");
  await expect(own.page.getByText("Password changed.")).toBeVisible();
  await own.context.close();

  // The new password signs in.
  const again = await signInToConsole(browser, { ...user, password: "a-new-passphrase" });
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("a password of bcrypt's whole bound, 72 bytes, is set and signs in, and nothing appended to it does", async ({ browser, users }) => {
  const user = await users.create();
  // As long as the first administrator's may be, and every policy's character classes in it (#550).
  const longest = "Aa1!" + "a".repeat(68);
  expect(Buffer.byteLength(longest)).toBe(72);

  const own = await signInToConsole(browser, user, "/account/change-password");
  await own.page.locator("#currentPassword").fill(user.password);
  await own.page.locator("#newPassword").fill(longest);
  await own.page.locator("#newPasswordConfirmation").fill(longest);
  await own.page.getByRole("button", { name: "Change password" }).click();
  await expect(own.page.getByText("Password changed.")).toBeVisible();
  await own.context.close();

  // bcrypt alone reads no further than 72 bytes, so the password with anything after it would
  // match; the auth server compares the whole submission and refuses it. A throwaway user's one
  // wrong password.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const signIn = await context.newPage();
  await signIn.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(signIn, user.email, longest + "x");
  await expect(signIn).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(signIn.locator("#pwd-error")).toHaveText("Authentication failed.");
  await context.close();

  const again = await signInToConsole(browser, { ...user, password: longest });
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("the user enrols an authenticator, is asked for its code at sign-in, and turns it off", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  await expect(own.page.getByText("Two-factor authentication is off.")).toBeVisible();
  await expect(own.page.getByRole("img", { name: "QR code to scan with your authenticator app" })).toBeVisible();
  const scanned = (await own.page.locator("#otp-secret").innerText()).trim();
  const enable = own.page.getByRole("button", { name: "Turn on two-factor authentication" });

  // A missing or wrong code is refused, and so is a wrong password, which is checked first.
  await own.page.locator("#password").fill(user.password);
  await enable.click();
  await expectRefusal(own.page, "otp-error", "otp", noCode, { focused: false });
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill("000000");
  await enable.click();
  await expectRefusal(own.page, "otp-error", "otp", wrongCode, { focused: false });
  await own.page.locator("#password").fill("not-the-password");
  await own.page.locator("#otp").fill("000000");
  await enable.click();
  await expectRefusal(own.page, "otp-error", "password", wrongPassword);

  // Each refusal drew the same enrolment again, so the key already scanned is the one that works.
  await expect(own.page.locator("#otp-secret")).toHaveText(scanned);
  const secret = await turnOn(own.page, user.password);
  await own.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator("#otpEnabled")).toBeChecked();

  // Signing in now takes a code, which signInToConsole enters.
  const withOtp = await signInToConsole(browser, { ...user, otpSecret: secret }, "/account/otp");
  await expect(withOtp.page).toHaveURL(`${env.adminUrl}/account/otp`);
  await expect(withOtp.page.getByText("Two-factor authentication is on.")).toBeVisible();
  await withOtp.page.locator("#password").fill(user.password);
  await withOtp.page.getByRole("button", { name: "Turn off two-factor authentication" }).click();
  await expect(withOtp.page.getByText("Two-factor authentication is off.")).toBeVisible();
  await withOtp.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.getByText("The user hasn't set up two-factor authentication. Only they can, from their account.")).toBeVisible();
});

test("the enrolment key's Copy key button copies it", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  await own.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: env.adminUrl });
  const secret = (await own.page.locator("#otp-secret").innerText()).trim();
  await own.page.getByRole("button", { name: "Copy key" }).click();
  // The button says so for a moment.
  await expect(own.page.getByRole("button", { name: "Key copied" })).toBeVisible();
  expect(await own.page.evaluate(() => navigator.clipboard.readText())).toBe(secret);
  await own.context.close();
});

test("a missing or wrong code at sign-in is refused", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  await turnOn(own.page, user.password);
  await own.context.close();

  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const signIn = await context.newPage();
  await signIn.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(signIn, user.email, user.password);
  await expect(signIn).toHaveURL(/\/auth\/otp/);
  await expect(signIn.getByRole("heading", { name: "Two-factor authentication" })).toBeVisible();
  await signIn.getByRole("button", { name: "Verify" }).click();
  await expectRefusal(signIn, "otp-error", "otp", noCode);
  await signIn.locator("#otp").fill("000000");
  await signIn.getByRole("button", { name: "Verify" }).click();
  await expectRefusal(signIn, "otp-error", "otp", wrongCode);
  await context.close();
});

// The console's own sentence for the auth server's 429, in the page's language, where the API's is
// English only.
const tooManyAttempts = "Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again.";

test("too many wrong current passwords are refused on the form, and on the OTP page, which shares the budget", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const currentPassword = own.page.locator("#currentPassword");
  const submitWrong = async () => {
    await currentPassword.fill("not-the-password");
    await own.page.locator("#newPassword").fill("a-new-passphrase");
    await own.page.locator("#newPasswordConfirmation").fill("a-new-passphrase");
    await own.page.getByRole("button", { name: "Change password" }).click();
    // The form is drawn again empty, so an empty field is the answer's page and not the one submitted.
    await expect(currentPassword).toHaveValue("");
  };

  // Five wrong passwords per user per 15 minutes, counted by the user whatever the rate limiter
  // switch says: this throwaway user spends nothing an address or another test counts.
  for (let attempt = 1; attempt <= 5; attempt++) {
    await submitWrong();
    await expect(own.page.locator("#password-error")).toContainText(wrongPassword);
  }
  // The sixth is refused before the password is compared, and drawn on the form, not the error page.
  await submitWrong();
  await expect(own.page.locator("#password-error")).toContainText(tooManyAttempts);
  await expect(own.page.getByText(wrongPassword)).toHaveCount(0);
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/change-password`);
  await expect(own.page.getByRole("heading", { name: "Something went wrong" })).toHaveCount(0);
  await expect(own.page.getByRole("button", { name: "Change password" })).toBeVisible();

  // The OTP page checks the same password against the same budget, so it refuses even the right one,
  // and draws the enrolment form again with its QR code.
  await own.page.goto(`${env.adminUrl}/account/otp`);
  const qrCode = own.page.getByRole("img", { name: "QR code to scan with your authenticator app" });
  await expect(qrCode).toBeVisible();
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill("000000");
  await own.page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(own.page.locator("#otp-error")).toContainText(tooManyAttempts);
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/otp`);
  await expect(own.page.getByRole("heading", { name: "Something went wrong" })).toHaveCount(0);
  await expect(own.page.getByText("Two-factor authentication is off.")).toBeVisible();
  await expect(qrCode).toBeVisible();
  await own.context.close();
});

test("an enrolment form left open while OTP is enabled in another tab leaves it enabled", async ({ page, browser, users }) => {
  const user = await users.create();
  // Tab A draws the enrolment form and is left open.
  const own = await signInToConsole(browser, user, "/account/otp");
  const stale = own.page;
  await expect(stale.getByRole("button", { name: "Turn on two-factor authentication" })).toBeVisible();
  const staleSecret = (await stale.locator("#otp-secret").innerText()).trim();

  // Tab B, the same browser, enrols.
  const other = await own.context.newPage();
  await other.goto(`${env.adminUrl}/account/otp`);
  await turnOn(other, user.password);

  // Tab A's form asks to enable, with the right password: the auth server refuses it as already
  // enabled, and the page is drawn as the account is now. It used to ask for the inverse of the stored
  // state, so this post turned the second factor off.
  await stale.locator("#password").fill(user.password);
  await stale.locator("#otp").fill(totp(staleSecret));
  await stale.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(stale.getByText("Two-factor authentication is on.")).toBeVisible();
  await expect(stale).toHaveURL(`${env.adminUrl}/account/otp`);
  await expect(stale.getByRole("button", { name: "Turn off two-factor authentication" })).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator("#otpEnabled")).toBeChecked();
});
