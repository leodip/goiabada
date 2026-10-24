// French uses the same responsive components as the other catalogs. Exercise the rendered
// wording at the smallest supported phone width, including tabs, tables, dialogs and refusals.
import { addGroupAttribute, addRedirectUri, choose, clientUrl, groupUrl, resourceUrl, userUrl } from "../../lib/admin-console";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { signInToConsole } from "../../lib/console-user";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { fitsInFrench } from "../../lib/french";
import { solidPng } from "../../lib/images";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";


for (const theme of ["light", "dark"] as const) {
  test(`French console pages fit a phone in ${theme}`, async ({ page, clients, groups, resources, users }) => {
    test.setTimeout(180_000);
    // Fixture helpers run on English tabs; only the tab under inspection speaks French.
    const client = await clients.create();
    const group = await groups.create();
    const resource = await resources.create({ permissions: ["read"] });
    const user = await users.create();
    await addGroupAttribute(page, group.id, { key: "department", value: "Recherche" });
    const groupEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(`${userUrl(user.id, "attributes")}/add`);
    await page.locator("#attributeKey").fill("department");
    await page.locator('[name="attributeValue"]').fill("Recherche");
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(?:\\?|$)`));
    const userEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
    await page.goto(resourceUrl(resource.id, "users-with-permission"));
    const grant = await page.locator('a[href*="/users-with-permission/add/"]').getAttribute("href");

    await page.setViewportSize({ width: 320, height: 740 });
    page.setDefaultTimeout(10_000);
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setExtraHTTPHeaders({ "Accept-Language": "fr-CA" });
    const urls = [
      `${env.adminUrl}/`,
      ...["clients", "groups", "resources", "users"].flatMap((kind) => [`${env.adminUrl}/admin/${kind}`, `${env.adminUrl}/admin/${kind}/new`]),
      ...(["settings", "logo", "tokens", "authentication", "oauth2-flows", "redirect-uris", "web-origins", "user-sessions", "permissions", "delete"] as const).map((tab) => clientUrl(client.id, tab)),
      ...(["settings", "attributes", "members", "permissions", "delete"] as const).map((tab) => groupUrl(group.id, tab)),
      `${groupUrl(group.id, "attributes")}/add`, `${groupUrl(group.id, "members")}/add`, new URL(groupEdit!, env.adminUrl).href,
      ...(["details", "profile", "picture", "email", "phone", "address", "authentication", "consents", "sessions", "attributes", "permissions", "groups", "delete"] as const).map((tab) => userUrl(user.id, tab)),
      `${userUrl(user.id, "attributes")}/add`, new URL(userEdit!, env.adminUrl).href,
      ...(["settings", "permissions", "users-with-permission", "groups-with-permission", "delete"] as const).map((tab) => resourceUrl(resource.id, tab)),
      new URL(grant!, env.adminUrl).href,
      ...["general", "ui-theme", "sessions", "tokens", "keys", "email", "email/send-test-email", "audit-logs", "audit-log-viewer"].map((tab) => `${env.adminUrl}/admin/settings/${tab}`),
      ...["profile", "picture", "email", "email-verification", "phone", "address", "change-password", "otp", "manage-consents", "sessions"].map((tab) => `${env.adminUrl}/account/${tab}`),
      `${env.adminUrl}/missing-french-page`, `${env.adminUrl}/auth/callback`, `${env.adminUrl}/auth/logout`,
    ];
    for (const url of urls) {
      await test.step(url, async () => {
        const response = await page.goto(`${url}${url.includes("?") ? "&" : "?"}ui_locales=fr`);
        expect(response?.status()).toBe(url.includes("missing-french-page") ? 404 : url.endsWith("/auth/callback") ? 405 : 200);
        await fitsInFrench(page);
        if (url === `${env.adminUrl}/`) {
          expect((await page.locator(".identity-row-who").boundingBox())!.width).toBeGreaterThanOrEqual(128);
        }
      });
    }

    await page.goto(`${clientUrl(client.id, "settings")}?ui_locales=fr`);
    await page.locator("#clientIdentifier").fill(`${client.identifier}-nouveau`);
    await page.locator("#btnSave").click();
    await expect(page.locator("dialog[open]")).toBeVisible();
    await fitsInFrench(page);
    await page.getByRole("button", { name: "Annuler", exact: true }).click();

    await page.goto(`${env.adminUrl}/admin/settings/keys?ui_locales=fr`);
    await page.locator('button[data-format="pem"]').first().click();
    await expect(page.locator("#publicKeyDialog")).toBeVisible();
    await fitsInFrench(page);
    await page.keyboard.press("Escape");

    await page.goto(`${clientUrl(client.id, "logo")}?ui_locales=fr`);
    await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(600, 600, [50, 120, 180]) });
    await expect(page.locator("#confirmCropBtn")).toBeEnabled();
    await fitsInFrench(page);
    await page.locator("#cancelCropBtn").click();

    await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=fr`);
    const lifetime = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
    await page.locator("#tokenExpirationInSeconds").fill("5400");
    await expect(lifetime).toHaveText("1\u00a0heure et 30 minutes");
    await page.locator("#tokenExpirationInSeconds").fill("x");
    await expect(lifetime).toHaveText("Saisissez un nombre entier de secondes.");
    await fitsInFrench(page);

    await page.goto(`${resourceUrl(resource.id, "delete")}?ui_locales=fr`);
    await page.locator('[name="resourceIdentifier"]').fill("incorrect");
    await page.getByRole("button", { name: "Supprimer la ressource", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Ce n’est pas l’identifiant de cette ressource.");
    await fitsInFrench(page);
    // Keep fixture cleanup in its original language.
    await page.setExtraHTTPHeaders({});
  });

  test(`French sign-in, two-factor, consent and public pages fit a phone in ${theme}`, async ({ page, browser, clients, users }) => {
    test.setTimeout(120_000);
    const { client } = await browserSignInClient(page, clients, { consentRequired: true });
    const user = await users.create();
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid profile email", params: { ui_locales: "fr", acr_values: "urn:goiabada:level2_mandatory" } });
    const own = signIn.page;
    await own.setViewportSize({ width: 320, height: 740 });
    await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await own.setExtraHTTPHeaders({ "Accept-Language": "fr-CA" });
    await fitsInFrench(own);
    await own.getByRole("button", { name: "Se connecter", exact: true }).click();
    await expect(own.getByRole("alert")).toContainText("L’adresse e-mail est obligatoire.");
    await fitsInFrench(own);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Se connecter", exact: true }).click();
    await expect(own.locator("#otp-secret")).toBeVisible();
    await fitsInFrench(own);
    await own.locator("#otp").fill("incorrect");
    await own.getByRole("button", { name: "Vérifier", exact: true }).click();
    await fitsInFrench(own);
    await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
    await own.getByRole("button", { name: "Vérifier", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Autoriser l’accès");
    await fitsInFrench(own);
    await page.goto(clientUrl(client.id, "redirect-uris"));
    await page.getByRole("button", { name: `Remove ${env.webtest1Url}/callback`, exact: true }).click();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Redirect URIs saved.", { exact: true })).toBeVisible();
    await own.getByRole("button", { name: "Autoriser", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Vous n’avez été redirigé nulle part");
    await fitsInFrench(own);
    await addRedirectUri(page, client.id, `${env.webtest1Url}/callback`);
    // No code is redeemed. Keep the form-post page on screen for its fallback button.
    await own.route("**/static/form-post.js*", (route) => route.abort());
    await own.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ client_id: client.identifier, response_type: "code", response_mode: "form_post", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", ui_locales: "fr", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" })}`);
    if (new URL(own.url()).pathname === "/auth/consent") await own.getByRole("button", { name: "Autoriser", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Retour à l’application");
    await fitsInFrench(own);
    const repeat = new URLSearchParams({ client_id: client.identifier, response_type: "code", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", prompt: "login", ui_locales: "fr", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
    await own.goto(`${env.authUrl}/auth/authorize?${repeat}`);
    await own.locator("#email").fill(user.email);
    await own.locator("#password").fill(user.password);
    await own.getByRole("button", { name: "Se connecter", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Authentification à deux facteurs");
    await fitsInFrench(own);
    for (const path of ["/forgot-password", "/reset-password?code=invalid", "/account/activate?code=invalid", "/missing-french-page", "/auth/logout", "/auth/logout/declined"]) {
      await own.goto(`${env.authUrl}${path}`);
      await fitsInFrench(own);
    }
    await own.goto(`${env.authUrl}/auth/logout`);
    await own.getByRole("button", { name: "Se déconnecter", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Déconnexion effectuée");
    await fitsInFrench(own);
    await own.goto(`${env.authUrl}/auth/authorize?client_id=missing&ui_locales=fr`);
    await fitsInFrench(own);
    await signIn.context.close();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`French regional emails, reset form and verification wait in ${theme}`, async ({ page, browser, request, users }) => {
    test.setTimeout(90_000);
    const user = await users.create({ emailVerified: true });
    await page.goto(userUrl(user.id, "profile"));
    await choose(page, "locale", "French (Canada)", /French \(Canada\)/);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: "fr-CA", viewport: { width: 320, height: 740 }, colorScheme: theme });
    const own = await context.newPage();
    await own.goto(`${env.authUrl}/forgot-password`);
    await fitsInFrench(own);
    await own.locator("#email").fill(user.email);
    await own.getByRole("button", { name: "Envoyer le lien", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Consultez vos e-mails");
    await fitsInFrench(own);
    const mail = await waitForMail(request, user.email);
    expect(mail.subject).toContain("Réinitialisation du mot de passe");
    expect(mail.html).toContain('<html lang="fr">');
    expect(mail.text).toContain("Pour réinitialiser votre mot de passe");
    await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
    await expect(own.locator("#password")).toBeVisible();
    await fitsInFrench(own);
    await own.locator("#password").fill(user.password);
    await own.locator("#passwordConfirmation").fill(user.password);
    await own.getByRole("button", { name: "Définir le mot de passe", exact: true }).click();
    await expect(own.getByRole("heading", { level: 1 })).toHaveText("Mot de passe défini");
    await fitsInFrench(own);
    await context.close();

    // An unverified account reaches the real verification page. Only the reply is held
    // at a fixed wait, so the assertion cannot drift with the machine's clock.
    const unverified = await users.create();
    const signedIn = await signInToConsole(browser, unverified, "/account/email-verification");
    await signedIn.page.setViewportSize({ width: 320, height: 740 });
    await signedIn.page.emulateMedia({ colorScheme: theme });
    await signedIn.page.setExtraHTTPHeaders({ "Accept-Language": "fr-CA" });
    await signedIn.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=fr`);
    await signedIn.page.route("**/account/email-send-verification*", (route) => route.fulfill({ json: { TooManyRequests: true, WaitInSeconds: 90 } }));
    await signedIn.page.getByRole("button", { name: "Envoyer le code", exact: true }).click();
    await expect(signedIn.page.locator("#verification-status")).toHaveText("Patientez 1 minute et 30\u00a0secondes avant de demander un nouveau code.");
    await fitsInFrench(signedIn.page);
    await signedIn.page.goto(`${env.adminUrl}/unauthorized?ui_locales=fr`);
    await expect(signedIn.page.getByRole("heading", { level: 1 })).toHaveText("Accès réservé aux administrateurs");
    await fitsInFrench(signedIn.page);
    await signedIn.context.close();
  });
}
