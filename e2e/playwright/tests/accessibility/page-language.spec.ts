// Every page is marked with the language it is written in, the catalog's, whatever the first
// language asked for (WCAG 2.2 SC 3.1.1, Language of Page): a screen reader chooses its voice from
// <html lang>. A language with no catalog (de) reads an English page, marked en; fr then pt-BR reads
// a pt-BR page, marked pt-BR, not fr. The console's country names follow the page too, so an English
// page asked for in German names Germany in English.
import { userUrl } from "../../lib/admin-console";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";

const asked = [
  { uiLocales: "de", lang: "en" },
  { uiLocales: "fr pt-BR", lang: "pt-BR" },
];

for (const { uiLocales, lang } of asked) {
  test(`a console page asked for in "${uiLocales}" is marked ${lang}`, async ({ page }) => {
    await page.goto(`${env.adminUrl}/admin/clients?${new URLSearchParams({ ui_locales: uiLocales })}`);
    await expect(page.locator("html")).toHaveAttribute("lang", lang);
    await expect(page.locator("html")).toHaveAttribute("data-catalog-lang", lang);
  });
}

test("the sign-in page is marked with the language of its catalog", async ({ page, browser, clients }) => {
  const web = await browserSignInClient(page, clients);
  for (const { uiLocales, lang } of asked) {
    const signIn = await openSignIn(browser, { clientId: web.client.identifier, scope: "openid", params: { ui_locales: uiLocales } });
    await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
    await expect(signIn.page.locator("html")).toHaveAttribute("lang", lang);
    await signIn.context.close();
  }
});

test("the phone country list on an English page asked for in German names Germany in English", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(`${userUrl(user.id, "phone")}?ui_locales=de`);
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  const countries = page.locator('select[name="phoneCountryUniqueId"] option');
  await expect(countries.filter({ hasText: "Germany (+49)" })).toHaveCount(1);
  await expect(countries.filter({ hasText: "Deutschland" })).toHaveCount(0);
});
