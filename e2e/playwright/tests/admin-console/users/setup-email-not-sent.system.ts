// A new user whose setup email cannot be sent is created and shown with a warning that says what to
// do (#725). The relay is Mailpit asked for SSL/TLS on its plain port: the save's connection check
// passes, and every send then fails. Runs alone, and puts the email settings back.
import { deleteUser } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { uniqueIdentifier } from "../../../lib/unique";

const notSent = "The setup email couldn't be sent, so the user can't sign in yet.";
const setPassword = "Set a password for them on the Authentication tab.";
const forgotPassword = 'Or, once email works, ask them to select "Forgot your password?" on the sign-in page.';

for (const { name, emailVerified } of [
  { name: "an unverified address is told to set a password", emailVerified: false },
  { name: "a verified address is also told to use Forgot your password?", emailVerified: true },
]) {
  test(`a setup email the relay refuses: the user is created, and ${name}`, async ({ page }) => {
    await withSettingsRestored(page, "/admin/settings/email", async () => {
      await page.goto(`${env.adminUrl}/admin/settings/email`);
      await fillSettingsForm(page, { smtpEncryption: "ssltls" });
      await saveSettings(page);

      const email = `${uniqueIdentifier("setup")}@example.com`;
      await page.goto(`${env.adminUrl}/admin/users/new`);
      await page.locator("#email").fill(email);
      await page.locator('input[name="emailVerified"]').setChecked(emailVerified);
      await page.getByRole("radio", { name: "Email a link to set it" }).check();
      await page.locator("#btnCreate").click();

      await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
      const id = Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]);
      try {
        await expect(page.getByText("User created.")).toBeVisible();
        await expect(page.getByRole("heading", { level: 1, name: email, exact: true })).toBeVisible();
        const warning = page.locator("#setupEmailNotSent");
        await expect(warning).toContainText(notSent);
        await expect(warning).toContainText(setPassword);
        if (emailVerified) await expect(warning).toContainText(forgotPassword);
        else await expect(warning).not.toContainText("Forgot your password?");

        // The warning is shown once.
        await page.reload();
        await expect(page.locator("#setupEmailNotSent")).toHaveCount(0);
      } finally {
        await deleteUser(page, id);
      }
    });
  });
}
