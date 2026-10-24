// Registration is a global setting, so this check runs in the serial system project and restores it.
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsInItalian } from "../../lib/italian";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

for (const theme of ["light", "dark"] as const) {
  test(`Italian registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "it-CH", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    const password = `${uniqueIdentifier("password")}-Aa1`;
    const created: string[] = [];
    try {
      await withSettingsRestored(page, "/admin/settings/general", async () => {
        await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
        await saveSettings(page);
        const email = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Crea un account");
        await fitsInItalian(own);
        await own.locator("#email").fill(email);
        await own.getByRole("button", { name: "Crea account", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Controlla la tua email");
        await fitsInItalian(own);
        const mail = await waitForMail(request, email);
        expect(mail.subject).toContain("Attiva il tuo account");
        expect(mail.html).toContain('<html lang="it">');
        await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Scegli la password");
        await fitsInItalian(own);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Crea account", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Account attivato");
        created.push(email);
        await fitsInItalian(own);

        await page.goto(`${env.adminUrl}/admin/settings/general`);
        await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
        await saveSettings(page);
        const secondEmail = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await own.locator("#email").fill(secondEmail);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        await own.getByRole("button", { name: "Crea account", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Account creato");
        created.push(secondEmail);
        await fitsInItalian(own);
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
