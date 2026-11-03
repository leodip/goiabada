// The registration and activation forms by keyboard alone (#722): Tab reaches each password field
// and then its Show button, named after the field, "Show password" and "Show password
// confirmation", and Enter shows that field alone. Registration is a setting, so this runs alone, as
// a system test, and puts the settings back. No account is created: the registration with the
// emailed link is left unactivated, and the one with a password is never sent.
import type { Page } from "@playwright/test";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectFocused } from "../../lib/focus";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

// From the focused password field, Tab reaches its Show button, the confirmation, and its Show
// button, which Enter presses; then the form's own button.
async function tabThroughPasswordFields(page: Page, submitName: string) {
  await expectFocused(page.locator("#password"));
  await page.keyboard.press("Tab");
  const showPassword = page.getByRole("button", { name: "Show password", exact: true });
  await expectFocused(showPassword);
  await expect(showPassword).toHaveText("Show");
  await expect(showPassword).toHaveAttribute("aria-controls", "password");
  await page.keyboard.press("Tab");
  await expectFocused(page.locator("#passwordConfirmation"));
  await page.keyboard.press("Tab");
  const showConfirmation = page.getByRole("button", { name: "Show password confirmation", exact: true });
  await expectFocused(showConfirmation);
  await expect(showConfirmation).toHaveText("Show");
  await expect(showConfirmation).toHaveAttribute("aria-controls", "passwordConfirmation");

  await page.keyboard.press("Enter");
  await expect(page.locator("#passwordConfirmation")).toHaveAttribute("type", "text");
  await expect(page.locator("#password")).toHaveAttribute("type", "password");
  await expectFocused(page.getByRole("button", { name: "Hide password confirmation", exact: true }));
  await expect(page.locator('.input-row:has(#passwordConfirmation) + [role="status"]')).toHaveText("Shown");
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("button", { name: submitName, exact: true }));
}

test("the registration and activation forms' password fields each have their Show button, reached by Tab", async ({
  page,
  browser,
  request,
}) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const own = await context.newPage();
  const register = `${env.authUrl}/account/register`;
  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      // With email verification, the password is chosen on the form the mailed link opens.
      await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
      await saveSettings(page);
      const address = `${uniqueIdentifier("u")}@example.com`;
      await own.goto(register);
      await own.locator("#email").fill(address);
      await own.getByRole("button", { name: "Create account", exact: true }).click();
      await expect(own.getByRole("heading", { level: 1, name: "Check your email" })).toBeVisible();
      await own.goto(linksIn(await waitForMail(request, address)).find((link) => link.includes("/account/activate"))!);
      await expect(own.getByRole("heading", { level: 1, name: "Choose your password", exact: true })).toBeVisible();
      await tabThroughPasswordFields(own, "Create account");

      // Without it, the registration form asks for the password itself, after the address.
      await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
      await saveSettings(page);
      await own.goto(register);
      await expectFocused(own.locator("#email"));
      await own.keyboard.press("Tab");
      await tabThroughPasswordFields(own, "Create account");
    });
  } finally {
    await context.close();
  }
});
