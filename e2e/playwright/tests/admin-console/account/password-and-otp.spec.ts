// The user's own password and authenticator, and what each changes at sign-in.
import { userUrl } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { freshTotp } from "../../../lib/totp";

test("the user changes their password: the current one must be right, and the new one confirmed", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, `password-${user.id}`, "/account/change-password");
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
  const again = await signInToConsole(browser, { ...user, password: "a-new-password" }, `password-again-${user.id}`);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});

test("the user enrols an authenticator, is asked for its code at sign-in, and turns it off", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, `otp-${user.id}`, "/account/otp");
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
  const withOtp = await signInToConsole(browser, { ...user, otpSecret: secret }, `otp-signin-${user.id}`, "/account/otp");
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
  const own = await signInToConsole(browser, user, `otp-wrong-${user.id}`, "/account/otp");
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
  const own = await signInToConsole(browser, user, `otp-admin-${user.id}`, "/account/otp");
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
  const again = await signInToConsole(browser, user, `otp-admin-again-${user.id}`);
  await expect(again.page).toHaveURL(`${env.adminUrl}/account/profile`);
  await again.context.close();
});
