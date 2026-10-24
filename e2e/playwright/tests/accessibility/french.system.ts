// Registration is a global setting, so this check runs in the serial system project and restores it.
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsInFrench } from "../../lib/french";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

for (const theme of ["light", "dark"] as const) {
  test(`French registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "fr-CA", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    const password = `${uniqueIdentifier("password")}-Aa1`;
    const created: string[] = [];
    try {
      await withSettingsRestored(page, "/admin/settings/general", async () => {
        await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
        await saveSettings(page);
        const email = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Créer un compte");
        await fitsInFrench(own);
        await own.locator("#email").fill(email);
        await own.getByRole("button", { name: "Créer le compte", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Consultez vos e-mails");
        await fitsInFrench(own);
        const mail = await waitForMail(request, email);
        expect(mail.subject).toContain("Activez votre compte");
        expect(mail.html).toContain('<html lang="fr">');
        await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Choisir votre mot de passe");
        await fitsInFrench(own);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Créer le compte", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Compte activé");
        created.push(email);
        await fitsInFrench(own);

        await page.goto(`${env.adminUrl}/admin/settings/general`);
        await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
        await saveSettings(page);
        const secondEmail = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await own.locator("#email").fill(secondEmail);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Créer le compte", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Compte créé");
        created.push(secondEmail);
        await fitsInFrench(own);
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
