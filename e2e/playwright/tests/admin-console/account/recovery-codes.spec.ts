// The user's recovery codes: the set of ten that comes with every new authenticator, each of which
// signs in once in place of an authenticator code, through "Use a recovery code instead".
import { cancelDialog, confirmDialog } from "../../../lib/admin-console";
import { submitPassword } from "../../../lib/browser-sign-in";
import { enterRecoveryCode, recoveryCodeRefused, signInToConsole, turnOnTwoFactor } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { freshTotp } from "../../../lib/totp";

// 24 characters of Crockford's base32 alphabet, which leaves out i, l, o and u, in six groups of
// four.
const codeShape = /^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$/;

test("turning on two-factor authentication shows ten recovery codes, once", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("#otp-secret").innerText()).trim();
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();

  await expect(own.page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  await expect(own.page.getByText("They are not shown again.")).toBeVisible();
  const codes = (await own.page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts())
    .map((code) => code.trim());
  expect(codes).toHaveLength(10);
  for (const code of codes) {
    expect(code).toMatch(codeShape);
  }
  expect(new Set(codes).size).toBe(10);

  // Copy codes copies the list, one code per line.
  await own.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: env.adminUrl });
  await own.page.getByRole("button", { name: "Copy codes" }).click();
  await expect(own.page.getByRole("button", { name: "Codes copied" })).toBeVisible();
  expect((await own.page.evaluate(() => navigator.clipboard.readText())).split("\n")).toEqual(codes);

  // The page drawn again shows the account, and not the codes.
  await own.page.goto(`${env.adminUrl}/account/otp`);
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();
  await expect(own.page.getByRole("heading", { name: "Save your recovery codes" })).toHaveCount(0);
  await expect(own.page.getByText(codes[0])).toHaveCount(0);
  await own.context.close();
});

test("signing in with a recovery code: a wrong code is refused, a saved one signs in once", async ({ browser, users }) => {
  const user = await users.create();
  const { recoveryCodes } = await turnOnTwoFactor(browser, user);

  // The console asks a user with an authenticator for its code, and links to the recovery-code form.
  const first = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await first.newPage();
  await page.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(page, user.email, user.password);
  await expect(page).toHaveURL(/\/auth\/otp/);
  await page.getByRole("link", { name: "Use a recovery code instead" }).click();
  await expect(page.getByRole("heading", { name: "Use a recovery code" })).toBeVisible();

  await enterRecoveryCode(page, "0000-0000-0000-0000-0000-0000");
  await expect(page.locator("#recovery-code-error")).toHaveText(recoveryCodeRefused);
  await expect(page.getByLabel("Recovery code")).toHaveAttribute("aria-invalid", "true");

  // Capitals and spaces don't matter.
  await enterRecoveryCode(page, recoveryCodes[0].toUpperCase().replaceAll("-", " "));
  await page.waitForURL(`${env.adminUrl}/account/profile`);
  await first.close();

  // The same code is refused at the next sign-in, with the answer a wrong one gets.
  const second = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const again = await second.newPage();
  await again.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(again, user.email, user.password);
  await enterRecoveryCode(again, recoveryCodes[0]);
  await expect(again.locator("#recovery-code-error")).toHaveText(recoveryCodeRefused);

  // The form links back to the code form, which still takes the app's code.
  await again.getByRole("link", { name: "Use your authenticator app instead" }).click();
  await expect(again.locator('input[name="otp"]')).toBeVisible();
  await enterRecoveryCode(again, recoveryCodes[1]);
  await again.waitForURL(`${env.adminUrl}/account/profile`);
  await second.close();
});

test("the count, and a new set behind the password and a confirmation, after which an old code is refused", async ({ browser, users }) => {
  const user = await users.create();
  const { recoveryCodes } = await turnOnTwoFactor(browser, user);

  // Signing in with a recovery code leaves nine of the ten unused, which the account page says.
  const own = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await own.newPage();
  await page.goto(`${env.adminUrl}/account/otp`);
  await submitPassword(page, user.email, user.password);
  await enterRecoveryCode(page, recoveryCodes[0]);
  await page.waitForURL(`${env.adminUrl}/account/otp`);
  await expect(page.getByRole("heading", { name: "Recovery codes", exact: true })).toBeVisible();
  await expect(page.getByText("9 of your 10 recovery codes are unused.")).toBeVisible();

  // The new set asks first; Cancel sends nothing.
  const section = page.locator("form", { has: page.getByRole("heading", { name: "Recovery codes", exact: true }) });
  await section.getByLabel("Password").fill(user.password);
  await section.getByRole("button", { name: "Get new recovery codes" }).click();
  await cancelDialog(page, "Your current recovery codes stop working as soon as you get new ones");
  await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toHaveCount(0);

  // A wrong password is refused on the form, with nothing replaced.
  await section.getByLabel("Password").fill("not-the-password");
  await section.getByRole("button", { name: "Get new recovery codes" }).click();
  await confirmDialog(page, "Get new recovery codes?");
  await expect(page.locator("#recovery-codes-error")).toHaveText("That password isn't right. Try again.");
  await expect(page.locator("#recovery-codes-password")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByText("9 of your 10 recovery codes are unused.")).toBeVisible();

  // With the password, the page shows the ten new codes once, and all ten are unused.
  await section.getByLabel("Password").fill(user.password);
  await section.getByRole("button", { name: "Get new recovery codes" }).click();
  await confirmDialog(page, "Get new recovery codes?");
  await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  const newCodes = (await page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts())
    .map((code) => code.trim());
  expect(newCodes).toHaveLength(10);
  for (const code of newCodes) {
    expect(code).toMatch(codeShape);
    expect(recoveryCodes).not.toContain(code);
  }
  await expect(page.getByText("10 of your 10 recovery codes are unused.")).toBeVisible();

  // Drawn again, the page shows the count and not the codes; the session the user is in goes on.
  await page.goto(`${env.adminUrl}/account/otp`);
  await expect(page.getByText("10 of your 10 recovery codes are unused.")).toBeVisible();
  await expect(page.getByText(newCodes[0])).toHaveCount(0);
  await own.close();

  // An unused code of the old set is refused at sign-in; one of the new set signs in.
  const next = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const again = await next.newPage();
  await again.goto(`${env.adminUrl}/account/profile`);
  await submitPassword(again, user.email, user.password);
  await enterRecoveryCode(again, recoveryCodes[1]);
  await expect(again.locator("#recovery-code-error")).toHaveText(recoveryCodeRefused);
  await enterRecoveryCode(again, newCodes[0]);
  await again.waitForURL(`${env.adminUrl}/account/profile`);
  await next.close();
});
