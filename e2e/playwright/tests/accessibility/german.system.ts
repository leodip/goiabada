// Registration is a global setting, so this check runs in the serial system project and restores it.
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsInGerman } from "../../lib/german";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

for (const theme of ["light", "dark"] as const) {
  test(`German registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "de-AT", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    const password = `${uniqueIdentifier("password")}-Aa1`;
    const created: string[] = [];
    try {
      await withSettingsRestored(page, "/admin/settings/general", async () => {
        await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
        await saveSettings(page);
        const email = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Konto erstellen");
        await fitsInGerman(own);
        await own.locator("#email").fill(email);
        await own.getByRole("button", { name: "Konto erstellen", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("E-Mails prüfen");
        await fitsInGerman(own);
        const mail = await waitForMail(request, email);
        expect(mail.subject).toContain("Aktivieren Sie Ihr Konto");
        expect(mail.html).toContain('<html lang="de">');
        await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Passwort wählen");
        await fitsInGerman(own);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Konto erstellen", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Konto aktiviert");
        created.push(email);
        await fitsInGerman(own);

        await page.goto(`${env.adminUrl}/admin/settings/general`);
        await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
        await saveSettings(page);
        const secondEmail = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await own.locator("#email").fill(secondEmail);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Konto erstellen", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Konto erstellt");
        created.push(secondEmail);
        await fitsInGerman(own);
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
