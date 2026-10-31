// Italian uses the same responsive components as the other catalogs. Exercise the rendered
// wording at the smallest supported phone width, including tabs, tables, dialogs and refusals.
import { addGroupAttribute, addRedirectUri, choose, clientUrl, groupUrl, resourceUrl, userUrl } from "../../lib/admin-console";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { signInToConsole } from "../../lib/console-user";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { fitsInItalian } from "../../lib/italian";
import { solidPng } from "../../lib/images";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";


for (const theme of ["light", "dark"] as const) {
  test(`Italian console pages fit a phone in ${theme}`, async ({ page, clients, groups, resources, users }) => {
    test.setTimeout(180_000);
    // Fixture helpers run on English tabs; only the tab under inspection speaks Italian.
    const client = await clients.create();
    const group = await groups.create();
    const resource = await resources.create({ permissions: ["read"] });
    const user = await users.create();
    await addGroupAttribute(page, group.id, { key: "department", value: "Ricerca" });
    const groupEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(`${userUrl(user.id, "attributes")}/add`);
    await page.locator("#attributeKey").fill("department");
    await page.locator('[name="attributeValue"]').fill("Ricerca");
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(?:\\?|$)`));
    const userEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(resourceUrl(resource.id, "users-with-permission"));
    const grant = await page.locator('a[href*="/users-with-permission/add/"]').getAttribute("href");

    await page.setViewportSize({ width: 320, height: 740 });
    page.setDefaultTimeout(10_000);
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setExtraHTTPHeaders({ "Accept-Language": "it-CH" });
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
      `${env.adminUrl}/missing-italian-page`, `${env.adminUrl}/auth/callback`, `${env.adminUrl}/auth/logout`,
    ];
    for (const url of urls) {
      await test.step(url, async () => {
        const response = await page.goto(`${url}${url.includes("?") ? "&" : "?"}ui_locales=it`);
        expect(response?.status()).toBe(url.includes("missing-italian-page") ? 404 : url.endsWith("/auth/callback") ? 405 : 200);
        await fitsInItalian(page);
        if (url === `${env.adminUrl}/`) {
          expect((await page.locator(".identity-row-who").boundingBox())!.width).toBeGreaterThanOrEqual(128);
        }
      });
    }

    await page.goto(`${clientUrl(client.id, "settings")}?ui_locales=it`);
    await page.locator("#clientIdentifier").fill(`${client.identifier}-nuovo`);
    await page.locator("#btnSave").click();
    await expect(page.locator("dialog[open]")).toBeVisible();
    await fitsInItalian(page);
    await page.getByRole("button", { name: "Annulla", exact: true }).click();

    await page.goto(`${env.adminUrl}/admin/settings/keys?ui_locales=it`);
    await page.locator('button[data-format="pem"]').first().click();
    await expect(page.locator("#publicKeyDialog")).toBeVisible();
    await fitsInItalian(page);
    await page.keyboard.press("Escape");

    await page.goto(`${clientUrl(client.id, "logo")}?ui_locales=it`);
    await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(600, 600, [50, 120, 180]) });
    await expect(page.locator("#confirmCropBtn")).toBeEnabled();
    await fitsInItalian(page);
    await page.locator("#cancelCropBtn").click();

    await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=it`);
    const lifetime = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
    await page.locator("#tokenExpirationInSeconds").fill("5400");
    await expect(lifetime).toHaveText("1 ora e 30 minuti");
    await page.locator("#tokenExpirationInSeconds").fill("x");
    await expect(lifetime).toHaveText("Inserisci un numero intero di secondi.");
    await fitsInItalian(page);

    await page.goto(`${resourceUrl(resource.id, "delete")}?ui_locales=it`);
    await page.locator('[name="resourceIdentifier"]').fill("incorrect");
    await page.getByRole("button", { name: "Elimina risorsa", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Questo non è l'identificatore della risorsa.");
    await fitsInItalian(page);
    // Keep fixture cleanup in its original language.
    await page.setExtraHTTPHeaders({});
  });

  test(`Italian sign-in, two-factor, consent and public pages fit a phone in ${theme}`, async ({ page, browser, clients, users }) => {
    test.setTimeout(120_000);
    const { client } = await browserSignInClient(page, clients, { consentRequired: true });
    const user = await users.create();
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid profile email", params: { ui_locales: "it", acr_values: "urn:goiabada:level2_mandatory" } });
    const own = signIn.page;
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.setExtraHTTPHeaders({ "Accept-Language": "it-CH" });
    await fitsInItalian(own);
    await own.getByRole("button", { name: "Accedi", exact: true }).click();
    await expect(own.getByRole("alert")).toContainText("L'email è obbligatoria");
    await fitsInItalian(own);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Accedi", exact: true }).click();
    await expect(own.locator("#otp-secret")).toBeVisible();
    await fitsInItalian(own);
    await own.locator("#otp").fill("incorrect");
    await own.getByRole("button", { name: "Verifica", exact: true }).click();
    await fitsInItalian(own);
    await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
    await own.getByRole("button", { name: "Verifica", exact: true }).click();
    // The new authenticator's recovery codes, shown once, then the page a reload draws.
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Salva i tuoi codici di recupero");
    await fitsInItalian(own);
    await own.reload();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("I tuoi codici di recupero sono già stati mostrati");
    await fitsInItalian(own);
    await own.getByRole("button", { name: "Continua", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Consenti l'accesso");
    await fitsInItalian(own);
    await page.goto(clientUrl(client.id, "redirect-uris"));
    await page.getByRole("button", { name: `Remove ${env.webtest1Url}/callback`, exact: true }).click();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Redirect URIs saved.", { exact: true })).toBeVisible();
    await own.getByRole("button", { name: "Consenti", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Non è stato effettuato alcun reindirizzamento");
    await fitsInItalian(own);
    await addRedirectUri(page, client.id, `${env.webtest1Url}/callback`);
    // No code is redeemed. Keep the form-post page on screen for its fallback button.
    await own.route("**/static/form-post.js*", (route) => route.abort());
    await own.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ client_id: client.identifier, response_type: "code", response_mode: "form_post", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", ui_locales: "it", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" })}`);
    if (new URL(own.url()).pathname === "/auth/consent") await own.getByRole("button", { name: "Consenti", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Ritorno all'applicazione");
    await fitsInItalian(own);
    const repeat = new URLSearchParams({ client_id: client.identifier, response_type: "code", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", prompt: "login", ui_locales: "it", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
    await own.goto(`${env.authUrl}/auth/authorize?${repeat}`);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Accedi", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Autenticazione a due fattori");
    await fitsInItalian(own);
    for (const path of ["/forgot-password", "/reset-password?code=invalid", "/account/activate?code=invalid", "/missing-italian-page", "/auth/logout", "/auth/logout/declined"]) {
      await own.goto(`${env.authUrl}${path}`);
      await fitsInItalian(own);
    }
    await own.goto(`${env.authUrl}/auth/logout`);
    await own.getByRole("button", { name: "Esci", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Disconnessione completata");
    await fitsInItalian(own);
    await own.goto(`${env.authUrl}/auth/authorize?client_id=missing&ui_locales=it`);
    await fitsInItalian(own);
    await signIn.context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`Italian regional emails, reset form and verification wait in ${theme}`, async ({ page, browser, request, users }) => {
    test.setTimeout(90_000);
    const user = await users.create({ emailVerified: true });
    await page.goto(userUrl(user.id, "profile"));
    await choose(page, "locale", "Italian (Switzerland)", /Italian \(Switzerland\)/);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "it-CH", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    await own.goto(`${env.authUrl}/forgot-password`);
    await fitsInItalian(own);
    await own.locator("#email").fill(user.email);
    await own.getByRole("button", { name: "Invia il link", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Controlla la tua email");
    await fitsInItalian(own);
    const mail = await waitForMail(request, user.email);
    expect(mail.subject).toContain("Reimpostazione della password");
    expect(mail.html).toContain('<html lang="it">');
    expect(mail.text).toContain("Per reimpostare la password");
    await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
    await expect(own.locator("#password")).toBeVisible();
    await fitsInItalian(own);
    await own.locator("#password").fill(user.password);
    await own.locator("#passwordConfirmation").fill(user.password);
    await own.getByRole("button", { name: "Imposta password", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Password impostata");
    await fitsInItalian(own);
    await context.close();

    // An unverified account reaches the real verification page. Only the reply is held
    // at a fixed wait, so the assertion cannot drift with the machine's clock.
    const unverified = await users.create();
    const signedIn = await signInToConsole(browser, unverified, "/account/email-verification");
    await signedIn.page.setViewportSize({ width: 320, height: 740 });
    await signedIn.page.emulateMedia({ colorScheme: theme });
    await signedIn.page.setExtraHTTPHeaders({ "Accept-Language": "it-CH" });
    await signedIn.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=it`);
    await signedIn.page.route("**/account/email-send-verification*", (route) => route.fulfill({ json: { TooManyRequests: true, WaitInSeconds: 90 } }));
    await signedIn.page.getByRole("button", { name: "Invia codice", exact: true }).click();
    await expect(signedIn.page.locator("#verification-status")).toHaveText("Attendi 1 minuto e 30 secondi prima di richiedere un altro codice.");
    await fitsInItalian(signedIn.page);
    await signedIn.page.goto(`${env.adminUrl}/unauthorized?ui_locales=it`);
    await expect(signedIn.page.getByRole("heading", { level: 1 })).toHaveText("Solo amministratori");
    await fitsInItalian(signedIn.page);
    await signedIn.context.close();
  });
}
