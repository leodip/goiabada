// Every page is marked with the language it is written in, the catalog's, whatever the first
// language asked for (WCAG 2.2 SC 3.1.1, Language of Page): a screen reader chooses its voice from
// <html lang>. A language with no catalog (sv) reads an English page, marked en; nl then pt-BR reads
// a pt-BR page, marked pt-BR, not nl. The console's country names follow the page too, so an English
// page asked for in Swedish names Germany in English.
import { userUrl } from "../../lib/admin-console";
import { openSignIn, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";

const asked = [
  { uiLocales: "es", lang: "es" },
  { uiLocales: "es-MX", lang: "es" },
  { uiLocales: "gl", lang: "en" },
  { uiLocales: "eu", lang: "en" },
  { uiLocales: "sv", lang: "en" },
  { uiLocales: "de", lang: "de" },
  { uiLocales: "de-AT", lang: "de" },
  { uiLocales: "gsw", lang: "en" },
  { uiLocales: "lb", lang: "en" },
  { uiLocales: "nl pt-BR", lang: "pt-BR" },
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

test("the phone country list on an English page asked for in Swedish names Germany in English", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(`${userUrl(user.id, "phone")}?ui_locales=sv`);
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  const countries = page.locator('select[name="phoneCountryUniqueId"] option');
  await expect(countries.filter({ hasText: "Germany (+49)" })).toHaveCount(1);
  await expect(countries.filter({ hasText: "Deutschland" })).toHaveCount(0);
});

// A user's page language, set here by an administrator on their Profile page, is the language of
// every auth server page drawn once the user is known, over the client's ui_locales and the
// browser's English; the password page, before the user is known, keeps the client's (#631).
test("a user whose page language is pt-BR signs in through a client asking for Spanish", async ({ page, browser, clients, users }) => {
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const user = await users.create();
  await page.goto(userUrl(user.id, "profile"));
  await page.getByLabel("Page language", { exact: true }).selectOption("pt-BR");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();

  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid", params: { ui_locales: "es" } });
  const own = signIn.page;
  await own.setExtraHTTPHeaders({ "Accept-Language": "en-US" });
  const html = own.locator("html");
  await expect(own).toHaveURL(/\/auth\/pwd/);
  await expect(html).toHaveAttribute("lang", "es");
  await expect(own.getByRole("heading", { level: 1 })).toHaveText("Iniciar sesión");
  await own.locator("#email").fill(user.email);
  await own.locator("#password").fill(user.password);
  await own.getByRole("button", { name: "Iniciar sesión", exact: true }).click();

  await expect(own).toHaveURL(/\/auth\/consent/);
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(own.getByRole("heading", { level: 1 })).toHaveText("Permitir acesso");
  await own.getByRole("button", { name: "Permitir", exact: true }).click();
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));

  await own.goto(`${env.authUrl}/auth/logout?ui_locales=es`);
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(own.getByRole("heading", { level: 1 })).toHaveText("Sair");
  await own.getByRole("button", { name: "Sair", exact: true }).click();
  await expect(html).toHaveAttribute("lang", "pt-BR");
  await expect(own.getByRole("heading", { level: 1 })).toHaveText("Sessão encerrada");
  await signIn.context.close();
});
