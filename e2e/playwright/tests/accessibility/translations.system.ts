// Registration is a global setting, so this check runs in the serial system project and restores it,
// for every row of the table in lib/translations.ts.
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsIn, translations } from "../../lib/translations";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

for (const translation of translations) {
  const wording = translation.registration;
  for (const theme of ["light", "dark"] as const) {
    test(`${translation.name} registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
      test.setTimeout(120_000);
      const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: translation.regionalTag, viewport: { width: 320, height: 740 }, colorScheme: theme });
      const own = await context.newPage();
      const password = `${uniqueIdentifier("password")}-Aa1`;
      const created: string[] = [];
      try {
        await withSettingsRestored(page, "/admin/settings/general", async () => {
          await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
          await saveSettings(page);
          const email = `${uniqueIdentifier("u")}@example.com`;
          await own.goto(`${env.authUrl}/account/register`);
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.title);
          await fitsIn(own, translation);
          await own.locator("#email").fill(email);
          await own.getByRole("button", { name: wording.register, exact: true }).click();
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.checkEmail);
          await fitsIn(own, translation);
          const mail = await waitForMail(request, email);
          expect(mail.subject).toContain(wording.activationSubject);
          expect(mail.html).toContain(`<html lang="${translation.tag}">`);
          await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.choosePassword);
          await fitsIn(own, translation);
          await own.locator("#password").fill(password);
          await own.locator("#passwordConfirmation").fill(password);
          await own.getByRole("button", { name: wording.activate, exact: true }).click();
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.accountActivated);
          created.push(email);
          await fitsIn(own, translation);

          await page.goto(`${env.adminUrl}/admin/settings/general`);
          await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
          await saveSettings(page);
          const secondEmail = `${uniqueIdentifier("u")}@example.com`;
          await own.goto(`${env.authUrl}/account/register`);
          await own.locator("#email").fill(secondEmail);
          await own.locator("#password").fill(password);
          await own.locator("#passwordConfirmation").fill(password);
          await own.getByRole("button", { name: wording.register, exact: true }).click();
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.accountCreated);
          created.push(secondEmail);
          await fitsIn(own, translation);
        });
      } finally {
        await context.close();
        for (const email of created) {
          const id = await idFromListLink(page, `${env.adminUrl}/admin/users?query=${encodeURIComponent(email)}`, email);
          await deleteUser(page, id);
        }
      }
    });
  }
}
