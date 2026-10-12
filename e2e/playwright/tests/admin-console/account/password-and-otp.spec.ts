// The user's own password and authenticator, and what each changes at sign-in.
import { userUrl } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { freshTotp, totp } from "../../../lib/totp";

test("the user changes their password: the current one must be right, and the new one confirmed", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const submit = async (current: string, next: string, confirmation: string) => {
    await own.page.locator('input[name="currentPassword"]').fill(current);
    await own.page.locator('input[name="newPassword"]').fill(next);
    await own.page.locator('input[name="newPasswordConfirmation"]').fill(confirmation);
    await own.page.getByRole("button", { name: "Change password" }).click();
  };

  await submit(user.password, "a-new-password", "a-different-one");
  await expect(own.page.getByText("The password confirmation does not match the password.")).toBeVisible();
  await submit("not-the-password", "a-new-password", "a-new-password");
  await expect(own.page.getByText("Authentication failed. Check your current password and try again.")).toBeVisible();
  await submit(user.password, "abc", "abc");
  await expect(own.page.getByText("The minimum length for the password is 6 characters")).toBeVisible();
  await submit(user.password, "a-new-password", "a-new-password");
  await expect(own.page.getByText("Password changed successfully")).toBeVisible();
  await own.context.close();

  // The new password signs in.
  const again = await signInToConsole(browser, { ...user, password: "a-new-password" });
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("the user enrols an authenticator, is asked for its code at sign-in, and turns it off", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  await expect(own.page.getByText("One-time password (OTP) is currently disabled for your account")).toBeVisible();
  await expect(own.page.getByRole("img", { name: "OTP QR code" })).toBeVisible();
  const secret = (await own.page.locator("pre").innerText()).trim();

  // A wrong code is refused, and so is a wrong password.
  await own.page.locator('input[name="password"]').fill(user.password);
  await own.page.locator('input[name="otp"]').fill("000000");
  await own.page.getByRole("button", { name: "Enable OTP" }).click();
  await expect(own.page.getByText(/Invalid OTP code|Incorrect OTP Code/)).toBeVisible();

  await own.page.locator('input[name="password"]').fill(user.password);
  await own.page.locator('input[name="otp"]').fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Enable OTP" }).click();
  await expect(own.page.getByText("One-time password (OTP) is enabled for your account")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator('input[name="otpEnabled"]')).toBeChecked();

  // Signing in now takes a code. A wrong one is refused first.
  const withOtp = await signInToConsole(browser, { ...user, otpSecret: secret }, "/account/otp");
  await expect(withOtp.page).toHaveURL(`${env.adminUrl}/account/otp`);
  await withOtp.page.locator('input[name="password"]').fill(user.password);
  await withOtp.page.getByRole("button", { name: "Disable OTP" }).click();
  await expect(withOtp.page.getByText("One-time password (OTP) is currently disabled for your account")).toBeVisible();
  await withOtp.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.getByText("Two-factor authentication is not enabled for this user")).toBeVisible();
});

test("a wrong code at sign-in is refused", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("pre").innerText()).trim();
  await own.page.locator('input[name="password"]').fill(user.password);
  await own.page.locator('input[name="otp"]').fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Enable OTP" }).click();
  await expect(own.page.getByText("One-time password (OTP) is enabled for your account")).toBeVisible();
  await own.context.close();

  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const signIn = await context.newPage();
  await signIn.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(signIn, user.email, user.password);
  await expect(signIn).toHaveURL(/\/auth\/otp/);
  await signIn.locator('input[name="otp"]').fill("000000");
  await signIn.getByRole("button", { name: "Verify" }).click();
  await expect(signIn.getByText("Incorrect OTP Code.")).toBeVisible();
  await context.close();
});

test("the administrator turns off a user's authenticator", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("pre").innerText()).trim();
  await own.page.locator('input[name="password"]').fill(user.password);
  await own.page.locator('input[name="otp"]').fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Enable OTP" }).click();
  await expect(own.page.getByText("One-time password (OTP) is enabled for your account")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await page.locator('input[name="otpEnabled"]').uncheck();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Saved successfully")).toBeVisible();
  await expect(page.getByText("Two-factor authentication is not enabled for this user")).toBeVisible();

  // Signing in no longer asks for a code.
  const again = await signInToConsole(browser, user);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

// The console's own sentence for the auth server's 429, in the page's language, where the API's is
// English only.
const tooManyAttempts = "Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again.";

test("too many wrong current passwords are refused on the form, and on the OTP page, which shares the budget", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const currentPassword = own.page.locator('input[name="currentPassword"]');
  const submitWrong = async () => {
    await currentPassword.fill("not-the-password");
    await own.page.locator('input[name="newPassword"]').fill("a-new-password");
    await own.page.locator('input[name="newPasswordConfirmation"]').fill("a-new-password");
    await own.page.getByRole("button", { name: "Change password" }).click();
    // The form is drawn again empty, so an empty field is the answer's page and not the one submitted.
    await expect(currentPassword).toHaveValue("");
  };

  // Five wrong passwords per user per 15 minutes, counted by the user whatever the rate limiter
  // switch says: this throwaway user spends nothing an address or another test counts.
  for (let attempt = 1; attempt <= 5; attempt++) {
    await submitWrong();
    await expect(own.page.getByText("Authentication failed. Check your current password and try again.")).toBeVisible();
  }
  // The sixth is refused before the password is compared, and drawn on the form, not the error page.
  await submitWrong();
  await expect(own.page.getByText(tooManyAttempts)).toBeVisible();
  await expect(own.page.getByText("Authentication failed. Check your current password and try again.")).toHaveCount(0);
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/change-password`);
  await expect(own.page.getByRole("heading", { name: "Server error" })).toHaveCount(0);
  await expect(own.page.getByRole("button", { name: "Change password" })).toBeVisible();

  // The OTP page checks the same password against the same budget, so it refuses even the right one,
  // and draws the enrolment form again with its QR code.
  await own.page.goto(`${env.adminUrl}/account/otp`);
  await expect(own.page.getByRole("img", { name: "OTP QR code" })).toBeVisible();
  await own.page.locator('input[name="password"]').fill(user.password);
  await own.page.locator('input[name="otp"]').fill("000000");
  await own.page.getByRole("button", { name: "Enable OTP" }).click();
  await expect(own.page.getByText(tooManyAttempts)).toBeVisible();
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/otp`);
  await expect(own.page.getByRole("heading", { name: "Server error" })).toHaveCount(0);
  await expect(own.page.getByText("One-time password (OTP) is currently disabled for your account")).toBeVisible();
  await expect(own.page.getByRole("img", { name: "OTP QR code" })).toBeVisible();
  await own.context.close();
});

test("an enrolment form left open while OTP is enabled in another tab leaves it enabled", async ({ page, browser, users }) => {
  const user = await users.create();
  // Tab A draws the enrolment form and is left open.
  const own = await signInToConsole(browser, user, "/account/otp");
  const stale = own.page;
  await expect(stale.getByRole("button", { name: "Enable OTP" })).toBeVisible();
  const staleSecret = (await stale.locator("pre").innerText()).trim();

  // Tab B, the same browser, enrols.
  const other = await own.context.newPage();
  await other.goto(`${env.adminUrl}/account/otp`);
  const secret = (await other.locator("pre").innerText()).trim();
  await other.locator('input[name="password"]').fill(user.password);
  await other.locator('input[name="otp"]').fill(await freshTotp(secret));
  await other.getByRole("button", { name: "Enable OTP" }).click();
  await expect(other.getByText("One-time password (OTP) is enabled for your account")).toBeVisible();

  // Tab A's form asks to enable, with the right password: the auth server refuses it as already
  // enabled, and the page is drawn as the account is now. It used to ask for the inverse of the stored
  // state, so this post turned the second factor off.
  await stale.locator('input[name="password"]').fill(user.password);
  await stale.locator('input[name="otp"]').fill(totp(staleSecret));
  await stale.getByRole("button", { name: "Enable OTP" }).click();
  await expect(stale.getByText("One-time password (OTP) is enabled for your account")).toBeVisible();
  await expect(stale).toHaveURL(`${env.adminUrl}/account/otp`);
  await expect(stale.getByRole("button", { name: "Disable OTP" })).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator('input[name="otpEnabled"]')).toBeChecked();
});
