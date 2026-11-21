// Registration is a global setting, so this check runs in the serial system project and restores it,
// for every row of the table in lib/translations.ts.
import type { Page } from "@playwright/test";
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { fitsIn, translations } from "../../lib/translations";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";

// The id of the user the users list shows with exactly this email, or none when there is no such
// user. Only the users list itself, rendered with its table or its empty state, answers none: a
// refused or failed lookup, or one that lands on another page, throws, so the test fails rather than
// leave a user it could not look for. A row is found by the email it shows rather than by its link's
// name, so a listed user whose link is named otherwise fails idFromListLink instead of being skipped.
async function listedUserId(page: Page, email: string): Promise<number | undefined> {
  const listUrl = `${env.adminUrl}/admin/users?query=${encodeURIComponent(email)}`;
  const response = await page.goto(listUrl);
  if (response?.status() !== 200 || !new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`).test(page.url())) {
    throw new Error(`the users list at ${listUrl} answered ${response?.status() ?? "nothing"} at ${page.url()}`);
  }
  await expect(page.locator("#usersTable, .empty-state").first(), `the users list at ${listUrl}`).toBeVisible();
  const rows = page.locator("#usersTable tbody tr").filter({ has: page.getByText(email, { exact: true }) });
  if ((await rows.count()) === 0) return undefined;
  return idFromListLink(page, listUrl, email);
}

for (const translation of translations) {
  const wording = translation.registration;
  for (const theme of ["light", "dark"] as const) {
    test(`${translation.name} registration and activation pages fit a phone in ${theme}`, async ({ page, browser, request }) => {
      test.setTimeout(120_000);
      const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: translation.regionalTag, viewport: { width: 320, height: 740 }, colorScheme: theme });
      const own = await context.newPage();
      const password = `${uniqueIdentifier("password")}-Aa1`;
      // Each address is recorded before the submission that can create its user, so a check failing
      // after the user exists still leaves it to the cleanup; one never created is skipped there.
      const submitted: string[] = [];
      try {
        await withSettingsRestored(page, "/admin/settings/general", async () => {
          await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
          await saveSettings(page);
          const email = `${uniqueIdentifier("u")}@example.com`;
          submitted.push(email);
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
          await fitsIn(own, translation);

          await page.goto(`${env.adminUrl}/admin/settings/general`);
          await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
          await saveSettings(page);
          const secondEmail = `${uniqueIdentifier("u")}@example.com`;
          submitted.push(secondEmail);
          await own.goto(`${env.authUrl}/account/register`);
          await own.locator("#email").fill(secondEmail);
          await own.locator("#password").fill(password);
          await own.locator("#passwordConfirmation").fill(password);
          await own.getByRole("button", { name: wording.register, exact: true }).click();
          await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.accountCreated);
          await fitsIn(own, translation);
        });
      } finally {
        await context.close();
        for (const email of submitted) {
          const id = await listedUserId(page, email);
          if (id !== undefined) await deleteUser(page, id);
        }
      }
    });
  }
}
