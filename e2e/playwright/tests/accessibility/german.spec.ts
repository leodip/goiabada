// German uses the same responsive components as the other catalogs. Exercise the rendered
// wording at the smallest supported phone width, including tabs, tables, dialogs and refusals.
import { addGroupAttribute, addRedirectUri, choose, clientUrl, confirmDialog, groupUrl, resourceUrl, userUrl } from "../../lib/admin-console";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { signInToConsole } from "../../lib/console-user";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { fitsInGerman } from "../../lib/german";
import { solidPng } from "../../lib/images";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";


for (const theme of ["light", "dark"] as const) {
  test(`German console pages fit a phone in ${theme}`, async ({ page, clients, groups, resources, users }) => {
    test.setTimeout(180_000);
    // Fixture helpers run on English tabs; only the tab under inspection speaks German.
    const client = await clients.create();
    const group = await groups.create();
    const resource = await resources.create({ permissions: ["read"] });
    const user = await users.create();
    await addGroupAttribute(page, group.id, { key: "department", value: "Forschung" });
    const groupEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(`${userUrl(user.id, "attributes")}/add`);
    await page.locator("#attributeKey").fill("department");
    await page.locator('[name="attributeValue"]').fill("Forschung");
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(?:\\?|$)`));
    const userEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(resourceUrl(resource.id, "users-with-permission"));
    const grant = await page.locator('a[href*="/users-with-permission/add/"]').getAttribute("href");

    await page.setViewportSize({ width: 320, height: 740 });
    page.setDefaultTimeout(10_000);
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setExtraHTTPHeaders({ "Accept-Language": "de-AT" });
    const urls = [
      `${env.adminUrl}/`,
      ...["clients", "groups", "resources", "users"].flatMap((kind) => [`${env.adminUrl}/admin/${kind}`, `${env.adminUrl}/admin/${kind}/new`]),
      ...(["settings", "logo", "tokens", "authentication", "oauth2-flows", "redirect-uris", "sign-out-redirect-uris", "web-origins", "user-sessions", "permissions", "introspection", "delete"] as const).map((tab) => clientUrl(client.id, tab)),
      ...(["settings", "attributes", "members", "permissions", "delete"] as const).map((tab) => groupUrl(group.id, tab)),
      `${groupUrl(group.id, "attributes")}/add`, `${groupUrl(group.id, "members")}/add`, new URL(groupEdit!, env.adminUrl).href,
      ...(["details", "profile", "picture", "email", "phone", "address", "authentication", "consents", "sessions", "attributes", "permissions", "groups", "delete"] as const).map((tab) => userUrl(user.id, tab)),
      `${userUrl(user.id, "attributes")}/add`, new URL(userEdit!, env.adminUrl).href,
      ...(["settings", "permissions", "users-with-permission", "groups-with-permission", "delete"] as const).map((tab) => resourceUrl(resource.id, tab)),
      new URL(grant!, env.adminUrl).href,
      ...["general", "ui-theme", "sessions", "tokens", "keys", "email", "email/send-test-email", "audit-logs", "audit-log-viewer"].map((tab) => `${env.adminUrl}/admin/settings/${tab}`),
      ...["profile", "picture", "email", "email-verification", "phone", "address", "change-password", "otp", "manage-consents", "sessions"].map((tab) => `${env.adminUrl}/account/${tab}`),
      `${env.adminUrl}/missing-german-page`, `${env.adminUrl}/auth/callback`, `${env.adminUrl}/auth/logout`,
    ];
    for (const url of urls) {
      await test.step(url, async () => {
        const response = await page.goto(`${url}${url.includes("?") ? "&" : "?"}ui_locales=de`);
        expect(response?.status()).toBe(url.includes("missing-german-page") ? 404 : url.endsWith("/auth/callback") ? 405 : 200);
        await fitsInGerman(page);
        if (url === `${env.adminUrl}/`) {
          expect((await page.locator(".identity-row-who").boundingBox())!.width).toBeGreaterThanOrEqual(128);
        }
      });
    }

    await page.goto(`${clientUrl(client.id, "settings")}?ui_locales=de`);
    await page.locator("#clientIdentifier").fill(`${client.identifier}-neu`);
    await page.locator("#btnSave").click();
    await expect(page.locator("dialog[open]")).toBeVisible();
    await fitsInGerman(page);
    await page.getByRole("button", { name: "Abbrechen", exact: true }).click();

    await page.goto(`${env.adminUrl}/admin/settings/keys?ui_locales=de`);
    await page.locator('button[data-format="pem"]').first().click();
    await expect(page.locator("#publicKeyDialog")).toBeVisible();
    await fitsInGerman(page);
    await page.keyboard.press("Escape");

    await page.goto(`${clientUrl(client.id, "logo")}?ui_locales=de`);
    await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(600, 600, [50, 120, 180]) });
    await expect(page.locator("#confirmCropBtn")).toBeEnabled();
    await fitsInGerman(page);
    await page.locator("#cancelCropBtn").click();

    await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=de`);
    const lifetime = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
    await page.locator("#tokenExpirationInSeconds").fill("5400");
    await expect(lifetime).toHaveText("1 Stunde, 30 Minuten");
    await page.locator("#tokenExpirationInSeconds").fill("x");
    await expect(lifetime).toHaveText("Geben Sie eine ganze Anzahl von Sekunden ein.");
    await fitsInGerman(page);

    await page.goto(`${resourceUrl(resource.id, "delete")}?ui_locales=de`);
    await page.locator('[name="resourceIdentifier"]').fill("incorrect");
    await page.getByRole("button", { name: "Ressource löschen", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Das ist nicht die Kennung dieser Ressource.");
    await fitsInGerman(page);
    // Keep fixture cleanup in its original language.
    await page.setExtraHTTPHeaders({});
  });

  test(`German sign-in, two-factor, consent and public pages fit a phone in ${theme}`, async ({ page, browser, clients, users }) => {
    test.setTimeout(120_000);
    const { client } = await browserSignInClient(page, clients, { consentRequired: true });
    const user = await users.create();
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid profile email", params: { ui_locales: "de", acr_values: "urn:goiabada:level2_mandatory" } });
    const own = signIn.page;
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.setExtraHTTPHeaders({ "Accept-Language": "de-AT" });
    await fitsInGerman(own);
    await own.getByRole("button", { name: "Anmelden", exact: true }).click();
    await expect(own.getByRole("alert")).toContainText("Geben Sie eine E-Mail-Adresse ein.");
    await fitsInGerman(own);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Anmelden", exact: true }).click();
    await expect(own.locator("#otp-secret")).toBeVisible();
    await fitsInGerman(own);
    await own.locator("#otp").fill("incorrect");
    await own.getByRole("button", { name: "Bestätigen", exact: true }).click();
    await fitsInGerman(own);
    await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
    await own.getByRole("button", { name: "Bestätigen", exact: true }).click();
    // The new authenticator's recovery codes, shown once, then the page a reload draws.
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Speichern Sie Ihre Wiederherstellungscodes");
    await fitsInGerman(own);
    await own.reload();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Ihre Wiederherstellungscodes wurden bereits angezeigt");
    await fitsInGerman(own);
    await own.getByRole("button", { name: "Weiter", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Zugriff erlauben");
    await fitsInGerman(own);
    await page.goto(clientUrl(client.id, "redirect-uris"));
    await page.getByRole("button", { name: `Remove ${env.webtest1Url}/callback`, exact: true }).click();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Redirect URIs saved.", { exact: true })).toBeVisible();
    await own.getByRole("button", { name: "Erlauben", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Sie wurden nicht weitergeleitet");
    await fitsInGerman(own);
    await addRedirectUri(page, client.id, `${env.webtest1Url}/callback`);
    // No code is redeemed. Keep the form-post page on screen for its fallback button.
    await own.route("**/static/form-post.js*", (route) => route.abort());
    await own.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ client_id: client.identifier, response_type: "code", response_mode: "form_post", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", ui_locales: "de", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" })}`);
    if (new URL(own.url()).pathname === "/auth/consent") await own.getByRole("button", { name: "Erlauben", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Zurück zur Anwendung");
    await fitsInGerman(own);
    const repeat = new URLSearchParams({ client_id: client.identifier, response_type: "code", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", prompt: "login", ui_locales: "de", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
    await own.goto(`${env.authUrl}/auth/authorize?${repeat}`);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Anmelden", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Zwei-Faktor-Authentifizierung");
    await fitsInGerman(own);
    // The recovery-code form, and its refusal of a wrong code.
    await own.getByRole("link", { name: "Stattdessen einen Wiederherstellungscode verwenden", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Wiederherstellungscode verwenden");
    await fitsInGerman(own);
    await own.locator("#recoveryCode").fill("0000-0000-0000-0000-0000-0000");
    await own.getByRole("button", { name: "Bestätigen", exact: true }).click();
    await expect(own.locator("#recovery-code-error")).toHaveText("Dieser Wiederherstellungscode ist falsch oder wurde bereits verwendet.");
    await fitsInGerman(own);
    for (const path of ["/forgot-password", "/reset-password?code=invalid", "/account/activate?code=invalid", "/missing-german-page", "/auth/logout", "/auth/logout/declined"]) {
      await own.goto(`${env.authUrl}${path}`);
      await fitsInGerman(own);
    }
    await own.goto(`${env.authUrl}/auth/logout`);
    await own.getByRole("button", { name: "Abmelden", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Abgemeldet");
    await fitsInGerman(own);
    await own.goto(`${env.authUrl}/auth/authorize?client_id=missing&ui_locales=de`);
    await fitsInGerman(own);
    await signIn.context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`German account recovery codes fit a phone in ${theme}`, async ({ browser, users }) => {
    test.setTimeout(90_000);
    const user = await users.create();
    // The account page's forms post to an address without ui_locales, so the user chooses the page
    // language in My Account, which every console page they open from then on is drawn in.
    const { context, page: own } = await signInToConsole(browser, user);
    await own.locator("#pageLanguage").selectOption("de");
    await own.getByRole("button", { name: "Save", exact: true }).click();
    await expect(own.getByText("Profil gespeichert.", { exact: true })).toBeVisible();
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.goto(`${env.adminUrl}/account/otp`);
    // Turning on two-factor authentication shows the new authenticator's set once.
    const secret = (await own.locator("#otp-secret").innerText()).trim();
    await own.locator("#password").fill(user.password);
    await own.locator("#otp").fill(await freshTotp(secret));
    await own.locator('button[name="otpAction"]').click();
    await expect(own.getByRole("heading", { name: "Speichern Sie Ihre Wiederherstellungscodes", exact: true })).toBeVisible();
    await fitsInGerman(own);
    // The count, and a new set behind the password and the confirmation.
    await own.goto(`${env.adminUrl}/account/otp`);
    await expect(own.getByRole("heading", { name: "Wiederherstellungscodes", exact: true })).toBeVisible();
    await expect(own.getByText("10 Ihrer 10 Wiederherstellungscodes sind noch unbenutzt.", { exact: true })).toBeVisible();
    await fitsInGerman(own);
    await own.locator("#recovery-codes-password").fill(user.password);
    await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
    await expect(own.locator("dialog[open]")).toContainText("Neue Wiederherstellungscodes anfordern?");
    await fitsInGerman(own);
    await confirmDialog(own);
    await expect(own.locator("#recovery-codes")).toBeVisible();
    await expect(own.getByRole("heading", { name: "Speichern Sie Ihre Wiederherstellungscodes", exact: true })).toBeVisible();
    await fitsInGerman(own);
    await context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`German regional emails, reset form and verification wait in ${theme}`, async ({ page, browser, request, users }) => {
    test.setTimeout(90_000);
    const user = await users.create({ emailVerified: true });
    await page.goto(userUrl(user.id, "profile"));
    await choose(page, "locale", "German (Austria)", /German \(Austria\)/);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "de-AT", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    await own.goto(`${env.authUrl}/forgot-password`);
    await fitsInGerman(own);
    await own.locator("#email").fill(user.email);
    await own.getByRole("button", { name: "Link senden", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("E-Mails prüfen");
    await fitsInGerman(own);
    const mail = await waitForMail(request, user.email);
    expect(mail.subject).toContain("Passwort zurücksetzen");
    expect(mail.html).toContain('<html lang="de">');
    expect(mail.text).toContain("um Ihr Passwort zurückzusetzen");
    await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
    await expect(own.locator("#password")).toBeVisible();
    await fitsInGerman(own);
    await own.locator("#password").fill(user.password);
    await own.locator("#passwordConfirmation").fill(user.password);
    await own.getByRole("button", { name: "Passwort festlegen", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Passwort festgelegt");
    await fitsInGerman(own);
    await context.close();

    // An unverified account reaches the real verification page. Only the reply is held
    // at a fixed wait, so the assertion cannot drift with the machine's clock.
    const unverified = await users.create();
    const signedIn = await signInToConsole(browser, unverified, "/account/email-verification");
    await signedIn.page.setViewportSize({ width: 320, height: 740 });
    await signedIn.page.emulateMedia({ colorScheme: theme });
    await signedIn.page.setExtraHTTPHeaders({ "Accept-Language": "de-AT" });
    await signedIn.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=de`);
    await signedIn.page.route("**/account/email-send-verification*", (route) => route.fulfill({ json: { TooManyRequests: true, WaitInSeconds: 90 } }));
    await signedIn.page.getByRole("button", { name: "Code senden", exact: true }).click();
    await expect(signedIn.page.locator("#verification-status")).toHaveText("Warten Sie 1 Minute, 30 Sekunden, bevor Sie einen neuen Code anfordern.");
    await fitsInGerman(signedIn.page);
    await signedIn.page.goto(`${env.adminUrl}/unauthorized?ui_locales=de`);
    await expect(signedIn.page.getByRole("heading", { level: 1 })).toHaveText("Nur für die Administration");
    await fitsInGerman(signedIn.page);
    await signedIn.context.close();
  });
}
