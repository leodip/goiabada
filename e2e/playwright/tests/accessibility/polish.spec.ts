// Polish uses the same responsive components as the other catalogs. Exercise the rendered
// wording at the smallest supported phone width, including tabs, tables, dialogs and refusals.
import { addGroupAttribute, addRedirectUri, choose, clientUrl, confirmDialog, groupUrl, resourceUrl, userUrl } from "../../lib/admin-console";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { signInToConsole } from "../../lib/console-user";
import { brandUrl, defaultBrand } from "../../lib/brands";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { fitsInPolish } from "../../lib/polish";
import { solidPng } from "../../lib/images";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";


for (const theme of ["light", "dark"] as const) {
  test(`Polish console pages fit a phone in ${theme}`, async ({ page, clients, groups, resources, users }) => {
    test.setTimeout(180_000);
    // Fixture helpers run on English tabs; only the tab under inspection speaks Polish.
    const client = await clients.create();
    const group = await groups.create();
    const resource = await resources.create({ permissions: ["read"] });
    const user = await users.create();
    await addGroupAttribute(page, group.id, { key: "department", value: "Badania" });
    const groupEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(`${userUrl(user.id, "attributes")}/add`);
    await page.locator("#attributeKey").fill("department");
    await page.locator('[name="attributeValue"]').fill("Badania");
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(?:\\?|$)`));
    const userEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(resourceUrl(resource.id, "users-with-permission"));
    const grant = await page.locator('a[href*="/users-with-permission/add/"]').getAttribute("href");
    const seededBrand = await defaultBrand(page);

    await page.setViewportSize({ width: 320, height: 740 });
    page.setDefaultTimeout(10_000);
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setExtraHTTPHeaders({ "Accept-Language": "pl-PL" });
    const urls = [
      `${env.adminUrl}/`,
      ...["clients", "groups", "resources", "users"].flatMap((kind) => [`${env.adminUrl}/admin/${kind}`, `${env.adminUrl}/admin/${kind}/new`]),
      ...(["settings", "logo", "tokens", "authentication", "oauth2-flows", "redirect-uris", "sign-out-redirect-uris", "backchannel-logout", "web-origins", "user-sessions", "permissions", "introspection", "delete"] as const).map((tab) => clientUrl(client.id, tab)),
      ...(["settings", "attributes", "members", "permissions", "delete"] as const).map((tab) => groupUrl(group.id, tab)),
      `${groupUrl(group.id, "attributes")}/add`, `${groupUrl(group.id, "members")}/add`, new URL(groupEdit!, env.adminUrl).href,
      ...(["details", "profile", "picture", "email", "phone", "address", "authentication", "connected-clients", "legal-documents", "sessions", "attributes", "permissions", "groups", "delete"] as const).map((tab) => userUrl(user.id, tab)),
      `${userUrl(user.id, "attributes")}/add`, new URL(userEdit!, env.adminUrl).href,
      ...(["settings", "permissions", "users-with-permission", "groups-with-permission", "delete"] as const).map((tab) => resourceUrl(resource.id, tab)),
      new URL(grant!, env.adminUrl).href,
      ...["general", "branding", "branding/new", "sessions", "tokens", "keys", "email", "email/send-test-email", "audit-logs", "audit-log-viewer"].map((tab) => `${env.adminUrl}/admin/settings/${tab}`),
      brandUrl(seededBrand.id, "edit"), brandUrl(seededBrand.id, "delete"),
      ...["profile", "picture", "email", "email-verification", "phone", "address", "change-password", "otp", "applications", "legal-documents", "sessions", "data", "delete", "deleted"].map((tab) => `${env.adminUrl}/account/${tab}`),
      `${env.adminUrl}/missing-polish-page`, `${env.adminUrl}/auth/callback`, `${env.adminUrl}/auth/logout`,
    ];
    for (const url of urls) {
      await test.step(url, async () => {
        const response = await page.goto(`${url}${url.includes("?") ? "&" : "?"}ui_locales=pl`);
        expect(response?.status()).toBe(url.includes("missing-polish-page") ? 404 : url.endsWith("/auth/callback") ? 405 : 200);
        await fitsInPolish(page);
        if (url === `${env.adminUrl}/`) {
          expect((await page.locator(".identity-row-who").boundingBox())!.width).toBeGreaterThanOrEqual(128);
        }
      });
    }

    await page.goto(`${clientUrl(client.id, "settings")}?ui_locales=pl`);
    await page.locator("#clientIdentifier").fill(`${client.identifier}-nowy`);
    await page.locator("#btnSave").click();
    await expect(page.locator("dialog[open]")).toBeVisible();
    await fitsInPolish(page);
    await page.getByRole("button", { name: "Anuluj", exact: true }).click();

    await page.goto(`${env.adminUrl}/admin/settings/keys?ui_locales=pl`);
    await page.locator('button[data-format="pem"]').first().click();
    await expect(page.locator("#publicKeyDialog")).toBeVisible();
    await fitsInPolish(page);
    await page.keyboard.press("Escape");

    await page.goto(`${clientUrl(client.id, "logo")}?ui_locales=pl`);
    await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(600, 600, [50, 120, 180]) });
    await expect(page.locator("#confirmCropBtn")).toBeEnabled();
    await fitsInPolish(page);
    await page.locator("#cancelCropBtn").click();

    await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=pl`);
    const lifetime = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
    await page.locator("#tokenExpirationInSeconds").fill("5400");
    await expect(lifetime).toHaveText("1 godzina i 30 minut");
    await page.locator("#tokenExpirationInSeconds").fill("x");
    await expect(lifetime).toHaveText("Wpisz całkowitą liczbę sekund.");
    await fitsInPolish(page);

    await page.goto(`${resourceUrl(resource.id, "delete")}?ui_locales=pl`);
    await page.locator('[name="resourceIdentifier"]').fill("incorrect");
    await page.getByRole("button", { name: "Usuń zasób", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("To nie jest identyfikator tego zasobu.");
    await fitsInPolish(page);
    // Keep fixture cleanup in its original language.
    await page.setExtraHTTPHeaders({});
  });

  test(`Polish sign-in, two-factor, consent and public pages fit a phone in ${theme}`, async ({ page, browser, clients, users }) => {
    test.setTimeout(120_000);
    const { client } = await browserSignInClient(page, clients, { consentRequired: true });
    const user = await users.create();
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid profile email", params: { ui_locales: "pl", acr_values: "urn:goiabada:level2_mandatory" } });
    const own = signIn.page;
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.setExtraHTTPHeaders({ "Accept-Language": "pl-PL" });
    await fitsInPolish(own);
    await own.getByRole("button", { name: "Zaloguj się", exact: true }).click();
    await expect(own.getByRole("alert")).toContainText("Podaj adres e-mail.");
    await fitsInPolish(own);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Zaloguj się", exact: true }).click();
    await expect(own.locator("#otp-secret")).toBeVisible();
    await fitsInPolish(own);
    await own.locator("#otp").fill("incorrect");
    await own.getByRole("button", { name: "Zweryfikuj", exact: true }).click();
    await fitsInPolish(own);
    await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
    await own.getByRole("button", { name: "Zweryfikuj", exact: true }).click();
    // The new authenticator's recovery codes, shown once, then the page a reload draws.
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Zapisz kody odzyskiwania");
    await fitsInPolish(own);
    await own.reload();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Kody odzyskiwania zostały już pokazane");
    await fitsInPolish(own);
    await own.getByRole("button", { name: "Kontynuuj", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Zezwól na dostęp");
    await fitsInPolish(own);
    await page.goto(clientUrl(client.id, "redirect-uris"));
    await page.getByRole("button", { name: `Remove ${env.webtest1Url}/callback`, exact: true }).click();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Redirect URIs saved.", { exact: true })).toBeVisible();
    await own.getByRole("button", { name: "Zezwól", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Nie nastąpiło żadne przekierowanie");
    await fitsInPolish(own);
    await addRedirectUri(page, client.id, `${env.webtest1Url}/callback`);
    // No code is redeemed. Keep the form-post page on screen for its fallback button.
    await own.route("**/static/form-post.js*", (route) => route.abort());
    await own.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ client_id: client.identifier, response_type: "code", response_mode: "form_post", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", ui_locales: "pl", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" })}`);
    if (new URL(own.url()).pathname === "/auth/consent") await own.getByRole("button", { name: "Zezwól", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Powrót do aplikacji");
    await fitsInPolish(own);
    const repeat = new URLSearchParams({ client_id: client.identifier, response_type: "code", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", prompt: "login", ui_locales: "pl", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
    await own.goto(`${env.authUrl}/auth/authorize?${repeat}`);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Zaloguj się", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Uwierzytelnianie dwuskładnikowe");
    await fitsInPolish(own);
    // The recovery-code form, and its refusal of a wrong code.
    await own.getByRole("link", { name: "Użyj kodu odzyskiwania", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Użyj kodu odzyskiwania");
    await fitsInPolish(own);
    await own.locator("#recoveryCode").fill("0000-0000-0000-0000-0000-0000");
    await own.getByRole("button", { name: "Zweryfikuj", exact: true }).click();
    await expect(own.locator("#recovery-code-error")).toHaveText("Ten kod odzyskiwania jest nieprawidłowy albo został już użyty.");
    await fitsInPolish(own);
    for (const path of ["/forgot-password", "/reset-password?code=invalid", "/account/activate?code=invalid", "/missing-polish-page", "/auth/logout", "/auth/logout/declined"]) {
      await own.goto(`${env.authUrl}${path}`);
      await fitsInPolish(own);
    }
    await own.goto(`${env.authUrl}/auth/logout`);
    await own.getByRole("button", { name: "Wyloguj się", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Wylogowano");
    await fitsInPolish(own);
    await own.goto(`${env.authUrl}/auth/authorize?client_id=missing&ui_locales=pl`);
    await fitsInPolish(own);
    await signIn.context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`Polish account recovery codes fit a phone in ${theme}`, async ({ browser, users }) => {
    test.setTimeout(90_000);
    const user = await users.create();
    // The account page's forms post to an address without ui_locales, so the user chooses the page
    // language in My Account, which every console page they open from then on is drawn in.
    const { context, page: own } = await signInToConsole(browser, user);
    await own.locator("#pageLanguage").selectOption("pl");
    await own.getByRole("button", { name: "Save", exact: true }).click();
    await expect(own.getByText("Zapisano profil.", { exact: true })).toBeVisible();
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.goto(`${env.adminUrl}/account/otp`);
    // Turning on two-factor authentication shows the new authenticator's set once.
    const secret = (await own.locator("#otp-secret").innerText()).trim();
    await own.locator("#password").fill(user.password);
    await own.locator("#otp").fill(await freshTotp(secret));
    await own.locator('button[name="otpAction"]').click();
    await expect(own.getByRole("heading", { name: "Zapisz kody odzyskiwania", exact: true })).toBeVisible();
    await fitsInPolish(own);
    // The count, and a new set behind the password and the confirmation.
    await own.goto(`${env.adminUrl}/account/otp`);
    await expect(own.getByRole("heading", { name: "Kody odzyskiwania", exact: true })).toBeVisible();
    await expect(own.getByText("10 z 10 twoich kodów odzyskiwania pozostaje nieużytych.", { exact: true })).toBeVisible();
    await fitsInPolish(own);
    await own.locator("#recovery-codes-password").fill(user.password);
    await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
    await expect(own.locator("dialog[open]")).toContainText("Wygenerować nowe kody odzyskiwania?");
    await fitsInPolish(own);
    await confirmDialog(own);
    await expect(own.locator("#recovery-codes")).toBeVisible();
    await expect(own.getByRole("heading", { name: "Zapisz kody odzyskiwania", exact: true })).toBeVisible();
    await fitsInPolish(own);
    await context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`Polish regional emails, reset form and verification wait in ${theme}`, async ({ page, browser, request, users }) => {
    test.setTimeout(90_000);
    const user = await users.create({ emailVerified: true });
    await page.goto(userUrl(user.id, "profile"));
    await choose(page, "locale", "Polish (Poland)", /Polish \(Poland\)/);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "pl-PL", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    await own.goto(`${env.authUrl}/forgot-password`);
    await fitsInPolish(own);
    await own.locator("#email").fill(user.email);
    await own.getByRole("button", { name: "Wyślij link", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Sprawdź skrzynkę e-mail");
    await fitsInPolish(own);
    const mail = await waitForMail(request, user.email);
    expect(mail.subject).toContain("Resetowanie hasła");
    expect(mail.html).toContain('<html lang="pl">');
    expect(mail.text).toContain("Aby zresetować hasło");
    await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
    await expect(own.locator("#password")).toBeVisible();
    await fitsInPolish(own);
    await own.locator("#password").fill(user.password);
    await own.locator("#passwordConfirmation").fill(user.password);
    await own.getByRole("button", { name: "Ustaw hasło", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Ustawiono hasło");
    await fitsInPolish(own);
    await context.close();

    // An unverified account reaches the real verification page. Only the reply is held
    // at a fixed wait, so the assertion cannot drift with the machine's clock.
    const unverified = await users.create();
    const signedIn = await signInToConsole(browser, unverified, "/account/email-verification");
    await signedIn.page.setViewportSize({ width: 320, height: 740 });
    await signedIn.page.emulateMedia({ colorScheme: theme });
    await signedIn.page.setExtraHTTPHeaders({ "Accept-Language": "pl-PL" });
    await signedIn.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=pl`);
    await signedIn.page.route("**/account/email-send-verification*", (route) => route.fulfill({ json: { TooManyRequests: true, WaitInSeconds: 90 } }));
    await signedIn.page.getByRole("button", { name: "Wyślij kod", exact: true }).click();
    await expect(signedIn.page.locator("#verification-status")).toHaveText("Czas do wysłania kolejnego kodu: 1 minuta i 30 sekund.");
    await fitsInPolish(signedIn.page);
    await signedIn.page.goto(`${env.adminUrl}/unauthorized?ui_locales=pl`);
    await expect(signedIn.page.getByRole("heading", { level: 1 })).toHaveText("Tylko dla administratorów");
    await fitsInPolish(signedIn.page);
    await signedIn.context.close();
  });
}
