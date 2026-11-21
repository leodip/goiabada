// Registration is a global setting, so this check runs in the serial system project and restores it.
import { deleteUser, userIdIfListed } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsInPolish } from "../../lib/polish";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

for (const theme of ["light", "dark"] as const) {
  test(`Polish registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "pl-PL", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    const password = `${uniqueIdentifier("password")}-Aa1`;
    const created: string[] = [];
    try {
      await withSettingsRestored(page, "/admin/settings/general", async () => {
        await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
        await saveSettings(page);
        const email = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Utwórz konto");
        await fitsInPolish(own);
        await own.locator("#email").fill(email);
        await own.getByRole("button", { name: "Utwórz konto", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Sprawdź skrzynkę e-mail");
        await fitsInPolish(own);
        const mail = await waitForMail(request, email);
        expect(mail.subject).toContain("Aktywuj konto");
        expect(mail.html).toContain('<html lang="pl">');
        await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Ustaw hasło");
        await fitsInPolish(own);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        // The account exists once this submit commits, so cleanup looks for it however the check after goes.
        created.push(email);
        await own.getByRole("button", { name: "Utwórz konto", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Aktywowano konto");
        await fitsInPolish(own);

        await page.goto(`${env.adminUrl}/admin/settings/general`);
        await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
        await saveSettings(page);
        const secondEmail = `${uniqueIdentifier("u")}@example.com`;
        await own.goto(`${env.authUrl}/account/register`);
        await own.locator("#email").fill(secondEmail);
        await own.locator("#password").fill(password);
        await own.locator("#passwordConfirmation").fill(password);
        created.push(secondEmail);
        await own.getByRole("button", { name: "Utwórz konto", exact: true }).click();
        await expect(own.getByRole("heading", { level: 1 })).toHaveText("Utworzono konto");
        await fitsInPolish(own);
      });
    } finally {
      await context.close();
      // A submit that failed before its account was committed leaves no user to delete.
      for (const email of created) {
        const id = await userIdIfListed(page, email);
        if (id !== undefined) await deleteUser(page, id);
      }
    }
  });
}
