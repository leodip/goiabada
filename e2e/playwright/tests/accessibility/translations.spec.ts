// Each translation uses the same responsive components as the other catalogs. Exercise its rendered
// wording at the smallest supported phone width, including tabs, tables, dialogs and refusals, for
// every row of the table in lib/translations.ts.
import { addGroupAttribute, addRedirectUri, choose, clientUrl, confirmDialog, groupUrl, legalDocumentUrl, resourceUrl, userUrl } from "../../lib/admin-console";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { signInToConsole } from "../../lib/console-user";
import { brandUrl, defaultBrand } from "../../lib/brands";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { fitsIn, translations } from "../../lib/translations";
import { solidPng } from "../../lib/images";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";

for (const translation of translations) {
  const { name, tag, regionalTag } = translation;
  const missingPage = `missing-${name.toLowerCase()}-page`;

  for (const theme of ["light", "dark"] as const) {
    test(`${name} console pages fit a phone in ${theme}`, async ({ page, clients, groups, resources, users }) => {
      const wording = translation.console;
      test.setTimeout(180_000);
      // Fixture helpers run on English tabs; only the tab under inspection speaks the row's language.
      const client = await clients.create();
      const group = await groups.create();
      const resource = await resources.create({ permissions: ["read"] });
      const user = await users.create();
      await addGroupAttribute(page, group.id, { key: "department", value: wording.attributeValue });
      const groupEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
      await page.goto(`${userUrl(user.id, "attributes")}/add`);
      await page.locator("#attributeKey").fill("department");
      await page.locator('[name="attributeValue"]').fill(wording.attributeValue);
      await page.locator("#btnSave").click();
      await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(?:\\?|$)`));
      const userEdit = await page.locator('a[href*="/attributes/edit/"]').first().getAttribute("href");
      await page.goto(resourceUrl(resource.id, "users-with-permission"));
      const grant = await page.locator('a[href*="/users-with-permission/add/"]').getAttribute("href");
      const seededBrand = await defaultBrand(page);

      await page.setViewportSize({ width: 320, height: 740 });
      page.setDefaultTimeout(10_000);
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.setExtraHTTPHeaders({ "Accept-Language": regionalTag });
      const urls = [
        `${env.adminUrl}/`,
        ...["clients", "groups", "resources", "users"].flatMap((kind) => [`${env.adminUrl}/admin/${kind}`, `${env.adminUrl}/admin/${kind}/new`]),
        ...(["settings", "logo", "tokens", "authentication", "oauth2-flows", "redirect-uris", "sign-out-redirect-uris", "backchannel-logout", "web-origins", "user-sessions", "permissions", "introspection", "legal-documents", "delete"] as const).map((tab) => clientUrl(client.id, tab)),
        ...(["settings", "attributes", "members", "permissions", "delete"] as const).map((tab) => groupUrl(group.id, tab)),
        `${groupUrl(group.id, "attributes")}/add`, `${groupUrl(group.id, "members")}/add`, new URL(groupEdit!, env.adminUrl).href,
        ...(["details", "profile", "picture", "email", "phone", "address", "authentication", "connected-clients", "legal-documents", "sessions", "attributes", "permissions", "groups", "delete"] as const).map((tab) => userUrl(user.id, tab)),
        `${userUrl(user.id, "attributes")}/add`, new URL(userEdit!, env.adminUrl).href,
        ...(["settings", "permissions", "users-with-permission", "groups-with-permission", "delete"] as const).map((tab) => resourceUrl(resource.id, tab)),
        new URL(grant!, env.adminUrl).href,
        ...["general", "branding", "branding/new", "sessions", "tokens", "keys", "email", "email/send-test-email", "email/templates", `email/templates/password_reset_link/${tag}`, "turnstile", "audit-logs", "audit-log-viewer"].map((tab) => `${env.adminUrl}/admin/settings/${tab}`),
        brandUrl(seededBrand.id, "edit"), brandUrl(seededBrand.id, "delete"),
        ...["profile", "picture", "email", "email-verification", "phone", "address", "change-password", "otp", "applications", "legal-documents", "sessions", "data", "delete", "deleted"].map((tab) => `${env.adminUrl}/account/${tab}`),
        `${env.adminUrl}/${missingPage}`, `${env.adminUrl}/auth/callback`, `${env.adminUrl}/auth/logout`,
      ];
      for (const url of urls) {
        await test.step(url, async () => {
          const response = await page.goto(`${url}${url.includes("?") ? "&" : "?"}ui_locales=${tag}`);
          expect(response?.status()).toBe(url.includes(missingPage) ? 404 : url.endsWith("/auth/callback") ? 405 : 200);
          await fitsIn(page, translation);
          if (url === `${env.adminUrl}/`) {
            expect((await page.locator(".identity-row-who").boundingBox())!.width).toBeGreaterThanOrEqual(128);
          }
          if (url === `${env.adminUrl}/admin/settings/branding`) {
            await expect(page.locator(".tag-note").first()).toHaveText(wording.defaultBrandTag);
          }
          if (url === `${env.adminUrl}/admin/settings/turnstile`) {
            await expect(page.locator('label[for="turnstileSiteKey"]')).toHaveText(wording.siteKey);
            await expect(page.locator('label[for="turnstileSecretKey"]')).toContainText(wording.secretKey);
          }
          if (url === `${env.adminUrl}/admin/settings/audit-log-viewer`) {
            await expect(page.locator('button[type="submit"]').filter({ hasText: wording.filter })).toBeVisible();
          }
        });
      }

      await page.goto(`${clientUrl(client.id, "settings")}?ui_locales=${tag}`);
      await page.locator("#clientIdentifier").fill(`${client.identifier}-${wording.renamedSuffix}`);
      await page.locator("#btnSave").click();
      await expect(page.locator("dialog[open]")).toBeVisible();
      await fitsIn(page, translation);
      await page.getByRole("button", { name: wording.cancel, exact: true }).click();

      await page.goto(`${env.adminUrl}/admin/settings/keys?ui_locales=${tag}`);
      await page.locator('button[data-format="pem"]').first().click();
      await expect(page.locator("#publicKeyDialog")).toBeVisible();
      await fitsIn(page, translation);
      await page.keyboard.press("Escape");

      await page.goto(`${clientUrl(client.id, "logo")}?ui_locales=${tag}`);
      await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(600, 600, [50, 120, 180]) });
      await expect(page.locator("#confirmCropBtn")).toBeEnabled();
      await fitsIn(page, translation);
      await page.locator("#cancelCropBtn").click();

      await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=${tag}`);
      const lifetime = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
      await page.locator("#tokenExpirationInSeconds").fill("5400");
      await expect(lifetime).toHaveText(wording.tokenLifetime);
      await page.locator("#tokenExpirationInSeconds").fill("x");
      await expect(lifetime).toHaveText(wording.wholeSecondsRefusal);
      await fitsIn(page, translation);

      await page.goto(`${resourceUrl(resource.id, "delete")}?ui_locales=${tag}`);
      await page.locator('[name="resourceIdentifier"]').fill("incorrect");
      await page.getByRole("button", { name: wording.deleteResource, exact: true }).click();
      await expect(page.getByRole("alert")).toContainText(wording.wrongResourceIdentifier);
      await fitsIn(page, translation);
      // Keep fixture cleanup in its original language.
      await page.setExtraHTTPHeaders({});
    });

    // The documents are the test's own: a draft the fixture deletes, and a notice published to a
    // client of the test's own, so no other test's sign-in shows it, which the fixture retires.
    test(`${name} legal documents pages fit a phone in ${theme}`, async ({ page, clients, legalDocuments }) => {
      test.setTimeout(90_000);
      const client = await clients.create();
      const draft = await legalDocuments.create({ markdown: "# Draft\n\nNot published yet." });
      const published = await legalDocuments.create({ markdown: "# Notice\n\n| Data | Kept for |\n|---|---|\n| Email | A year |", apps: [client.identifier], publish: true });

      await page.setViewportSize({ width: 320, height: 740 });
      page.setDefaultTimeout(10_000);
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.setExtraHTTPHeaders({ "Accept-Language": regionalTag });
      const list = `${env.adminUrl}/admin/legal-documents`;
      for (const url of [
        list,
        `${list}/new`,
        legalDocumentUrl(draft.id, "draft"),
        legalDocumentUrl(draft.id, "apps"),
        legalDocumentUrl(published.id, "versions"),
        `${legalDocumentUrl(published.id, "versions")}/1`,
        legalDocumentUrl(draft.id, "delete"),
      ]) {
        await test.step(url, async () => {
          const response = await page.goto(`${url}?ui_locales=${tag}`);
          expect(response?.status()).toBe(200);
          await fitsIn(page, translation);
        });
      }
      // Keep fixture cleanup in its original language.
      await page.setExtraHTTPHeaders({});
    });

    test(`${name} sign-in, two-factor, consent and public pages fit a phone in ${theme}`, async ({ page, browser, clients, users }) => {
      const wording = translation.signIn;
      test.setTimeout(120_000);
      const { client } = await browserSignInClient(page, clients, { consentRequired: true });
      const user = await users.create();
      const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid profile email", params: { ui_locales: tag, acr_values: "urn:goiabada:level2_mandatory" } });
      const own = signIn.page;
      await own.setViewportSize({ width: 320, height: 740 });
      await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await own.setExtraHTTPHeaders({ "Accept-Language": regionalTag });
      await fitsIn(own, translation);
      await own.getByRole("button", { name: wording.signIn, exact: true }).click();
      await expect(own.getByRole("alert")).toContainText(wording.emailRequired);
      await fitsIn(own, translation);
      await own.locator("#email").fill(user.email);
      await own.locator("#password").fill(user.password);
      await own.getByRole("button", { name: wording.signIn, exact: true }).click();
      await expect(own.locator("#otp-secret")).toBeVisible();
      await fitsIn(own, translation);
      await own.locator("#otp").fill("incorrect");
      await own.getByRole("button", { name: wording.verifyOtp, exact: true }).click();
      await fitsIn(own, translation);
      await own.locator("#otp").fill(await freshTotp((await own.locator("#otp-secret").innerText()).trim()));
      await own.getByRole("button", { name: wording.verifyOtp, exact: true }).click();
      // The new authenticator's recovery codes, shown once, then the page a reload draws.
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.saveRecoveryCodes);
      await fitsIn(own, translation);
      await own.reload();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.recoveryCodesShown);
      await fitsIn(own, translation);
      await own.getByRole("button", { name: wording.continue, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.consentTitle);
      await fitsIn(own, translation);
      await page.goto(clientUrl(client.id, "redirect-uris"));
      await page.getByRole("button", { name: `Remove ${env.webtest1Url}/callback`, exact: true }).click();
      await page.locator("#btnSave").click();
      await expect(page.getByText("Redirect URIs saved.", { exact: true })).toBeVisible();
      await own.getByRole("button", { name: wording.allow, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.notRedirected);
      await fitsIn(own, translation);
      await addRedirectUri(page, client.id, `${env.webtest1Url}/callback`);
      // No code is redeemed. Keep the form-post page on screen for its fallback button.
      await own.route("**/static/form-post.js*", (route) => route.abort());
      await own.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ client_id: client.identifier, response_type: "code", response_mode: "form_post", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", ui_locales: tag, code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" })}`);
      if (new URL(own.url()).pathname === "/auth/consent") await own.getByRole("button", { name: wording.allow, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.backToApplication);
      await fitsIn(own, translation);
      const repeat = new URLSearchParams({ client_id: client.identifier, response_type: "code", redirect_uri: `${env.webtest1Url}/callback`, scope: "openid", prompt: "login", ui_locales: tag, code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
      await own.goto(`${env.authUrl}/auth/authorize?${repeat}`);
      await own.locator("#email").fill(user.email);
      await own.locator("#password").fill(user.password);
      await own.getByRole("button", { name: wording.signIn, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.twoFactor);
      await fitsIn(own, translation);
      // The recovery-code form, and its refusal of a wrong code.
      await own.getByRole("link", { name: wording.useRecoveryCodeLink, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.useRecoveryCodeTitle);
      await fitsIn(own, translation);
      await own.locator("#recoveryCode").fill("0000-0000-0000-0000-0000-0000");
      await own.getByRole("button", { name: wording.verifyRecoveryCode, exact: true }).click();
      await expect(own.locator("#recovery-code-error")).toHaveText(wording.wrongRecoveryCode);
      await fitsIn(own, translation);
      for (const path of ["/forgot-password", "/reset-password?code=invalid", "/account/activate?code=invalid", `/${missingPage}`, "/auth/logout", "/auth/logout/declined"]) {
        await own.goto(`${env.authUrl}${path}`);
        await fitsIn(own, translation);
      }
      await own.goto(`${env.authUrl}/auth/logout`);
      await own.getByRole("button", { name: wording.signOut, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.signedOut);
      await fitsIn(own, translation);
      await own.goto(`${env.authUrl}/auth/authorize?client_id=missing&ui_locales=${tag}`);
      await fitsIn(own, translation);
      await signIn.context.close();
    });
  }

  for (const theme of ["light", "dark"] as const) {
    test(`${name} account recovery codes fit a phone in ${theme}`, async ({ browser, users }) => {
      const wording = translation.accountRecoveryCodes;
      test.setTimeout(90_000);
      const user = await users.create();
      // The account page's forms post to an address without ui_locales, so the user chooses the page
      // language in My Account, which every console page they open from then on is drawn in.
      const { context, page: own } = await signInToConsole(browser, user);
      await own.locator("#pageLanguage").selectOption(tag);
      await own.getByRole("button", { name: "Save", exact: true }).click();
      await expect(own.getByText(wording.profileSaved, { exact: true })).toBeVisible();
      await own.setViewportSize({ width: 320, height: 740 });
      await own.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await own.goto(`${env.adminUrl}/account/otp`);
      // Turning on two-factor authentication shows the new authenticator's set once.
      const secret = (await own.locator("#otp-secret").innerText()).trim();
      await own.locator("#password").fill(user.password);
      await own.locator("#otp").fill(await freshTotp(secret));
      await own.locator('button[name="otpAction"]').click();
      await expect(own.getByRole("heading", { name: wording.saveRecoveryCodes, exact: true })).toBeVisible();
      await fitsIn(own, translation);
      // The count, and a new set behind the password and the confirmation.
      await own.goto(`${env.adminUrl}/account/otp`);
      await expect(own.getByRole("heading", { name: wording.recoveryCodes, exact: true })).toBeVisible();
      await expect(own.getByText(wording.tenOfTenUnused, { exact: true })).toBeVisible();
      await fitsIn(own, translation);
      await own.locator("#recovery-codes-password").fill(user.password);
      await own.locator('button[name="otpAction"][value="recovery-codes"]').click();
      await expect(own.locator("dialog[open]")).toContainText(wording.newRecoveryCodesQuestion);
      await fitsIn(own, translation);
      await confirmDialog(own);
      await expect(own.locator("#recovery-codes")).toBeVisible();
      await expect(own.getByRole("heading", { name: wording.saveRecoveryCodes, exact: true })).toBeVisible();
      await fitsIn(own, translation);
      await context.close();
    });
  }

  for (const theme of ["light", "dark"] as const) {
    test(`${name} regional emails, reset form and verification wait in ${theme}`, async ({ page, browser, request, users }) => {
      const wording = translation.passwordReset;
      test.setTimeout(90_000);
      const user = await users.create({ emailVerified: true });
      await page.goto(userUrl(user.id, "profile"));
      await choose(page, "locale", translation.region.typed, translation.region.option);
      await page.locator("#btnSave").click();
      await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();
      const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, locale: regionalTag, viewport: { width: 320, height: 740 }, colorScheme: theme });
      const own = await context.newPage();
      await own.goto(`${env.authUrl}/forgot-password`);
      await fitsIn(own, translation);
      await own.locator("#email").fill(user.email);
      await own.getByRole("button", { name: wording.sendLink, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.checkEmail);
      await fitsIn(own, translation);
      const mail = await waitForMail(request, user.email);
      expect(mail.subject).toContain(wording.subject);
      expect(mail.html).toContain(`<html lang="${tag}">`);
      expect(mail.text).toContain(wording.sentence);
      await own.goto(linksIn(mail).find((link) => link.includes("/reset-password"))!);
      await expect(own.locator("#password")).toBeVisible();
      await fitsIn(own, translation);
      await own.locator("#password").fill(user.password);
      await own.locator("#passwordConfirmation").fill(user.password);
      await own.getByRole("button", { name: wording.setPassword, exact: true }).click();
      await expect(own.getByRole("heading", { level: 1 })).toHaveText(wording.passwordSet);
      await fitsIn(own, translation);
      await context.close();

      // An unverified account reaches the real verification page. Only the reply is held
      // at a fixed wait, so the assertion cannot drift with the machine's clock.
      const unverified = await users.create();
      const signedIn = await signInToConsole(browser, unverified, "/account/email-verification");
      await signedIn.page.setViewportSize({ width: 320, height: 740 });
      await signedIn.page.emulateMedia({ colorScheme: theme });
      await signedIn.page.setExtraHTTPHeaders({ "Accept-Language": regionalTag });
      await signedIn.page.goto(`${env.adminUrl}/account/email-verification?ui_locales=${tag}`);
      await signedIn.page.route("**/account/email-send-verification*", (route) => route.fulfill({ json: { TooManyRequests: true, WaitInSeconds: 90 } }));
      await signedIn.page.getByRole("button", { name: wording.sendCode, exact: true }).click();
      await expect(signedIn.page.locator("#verification-status")).toHaveText(wording.verificationWait);
      await fitsIn(signedIn.page, translation);
      await signedIn.page.goto(`${env.adminUrl}/unauthorized?ui_locales=${tag}`);
      await expect(signedIn.page.getByRole("heading", { level: 1 })).toHaveText(wording.adminOnly);
      await fitsIn(signedIn.page, translation);
      await signedIn.context.close();
    });
  }
}
