// Settings - General, each switch followed to what it changes. Runs alone, and every test puts the
// settings back (lib/settings.ts).
import { createHash, randomBytes } from "node:crypto";
import { clientUrl, deleteUser, idFromListLink, saveAndExpectSaved, submitNewUser } from "../../../lib/admin-console";
import { authorizeAndLand, redirectParams } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { linksIn, waitForMail } from "../../../lib/mailpit";
import { passwordToken } from "../../../lib/oauth";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const general = "/admin/settings/general";

test("the app name is saved and names the console's and the sign-in pages", async ({ page, browser }) => {
  await withSettingsRestored(page, general, async () => {
    const name = `E2E ${randomBytes(3).toString("hex")}`;
    await fillSettingsForm(page, { appName: name });
    await saveSettings(page);
    await expect(page).toHaveTitle(new RegExp(`^${name} - `));

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const signIn = await context.newPage();
    await signIn.goto(`${env.adminUrl}/account/profile`);
    await expect(signIn.locator('input[name="password"]')).toBeVisible();
    await expect(signIn).toHaveTitle(new RegExp(name));
    await context.close();
  });
});

for (const { name, values, message } of [
  { name: "an app name that is too long", values: { appName: "x".repeat(100) }, message: "App name is too long." },
  { name: "an issuer URI with no host", values: { issuer: "https://" }, message: "Invalid issuer. Please enter a valid URI." },
  { name: "an issuer identifier with a space", values: { issuer: "not an identifier" }, message: "Invalid issuer. It must start with a letter" },
]) {
  test(`${name} is refused`, async ({ page }) => {
    await withSettingsRestored(page, general, async () => {
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      // Changing the issuer asks first; the refusal comes after.
      if ("issuer" in values) await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
      await expect(page.getByText(message)).toBeVisible();
    });
  });
}

test("changing the issuer asks first, and No changes nothing", async ({ page }) => {
  await page.goto(`${env.adminUrl}${general}`);
  const issuer = await page.locator('input[name="issuer"]').inputValue();
  await page.locator('input[name="issuer"]').fill(`${issuer}/changed`);
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("You are changing the issuer");
  await dialog.getByRole("button", { name: "No" }).click();
  await page.goto(`${env.adminUrl}${general}`);
  await expect(page.locator('input[name="issuer"]')).toHaveValue(issuer);
});

test("a refused save keeps comparing against the stored issuer, so saving it again asks again", async ({ page }) => {
  await withSettingsRestored(page, general, async () => {
    const issuer = await page.locator('input[name="issuer"]').inputValue();
    const changed = `${issuer}/changed`;
    // The app name is refused before the issuer is looked at, so nothing is saved and no one is signed out.
    await fillSettingsForm(page, { appName: "x".repeat(100), issuer: changed });
    await page.locator("#btnSave").click();
    const dialog = page.locator("dialog[open]");
    await expect(dialog).toContainText("You are changing the issuer");
    await dialog.getByRole("button", { name: "Yes" }).click();
    await expect(page.getByText("App name is too long. The maximum length is 30 characters.")).toBeVisible();
    // The inputs keep what was submitted; the issuer they are compared against is the stored one.
    await expect(page.locator('input[name="issuer"]')).toHaveValue(changed);

    await page.locator("#btnSave").click();
    await expect(dialog).toContainText("You are changing the issuer");
    await dialog.getByRole("button", { name: "No" }).click();
    await expect(dialog).toHaveCount(0);
    await page.goto(`${env.adminUrl}${general}`);
    await expect(page.locator('input[name="issuer"]')).toHaveValue(issuer);
  });
});

test("the password policy applies to passwords set from then on", async ({ page }) => {
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { passwordPolicy: "medium" });
    await saveSettings(page);

    const email = `${uniqueIdentifier("u")}@example.com`;
    await submitNewUser(page, { email, password: "alllowercase" });
    await expect(page.getByText("As per our policy, an uppercase character is required in the password.")).toBeVisible();
    await submitNewUser(page, { email, password: "Medium1Pass" });
    await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
    await deleteUser(page, Number(page.url().match(/\/admin\/users\/(\d+)\//)![1]));
  });
});

test("self-registration opens the register page; without email verification it creates the account", async ({ page }) => {
  const registerUrl = `${env.authUrl}/account/register`;
  // Off, as seeded: the page is not offered.
  expect((await page.request.get(registerUrl, { maxRedirects: 0 })).status()).not.toBe(200);

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);

    const email = `${uniqueIdentifier("u")}@example.com`;
    const context = await page.context().browser()!.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    await register.goto(registerUrl);
    await register.locator('input[name="email"]').fill(email);
    await register.locator('input[name="password"]').fill("a-good-password");
    await register.locator('input[name="passwordConfirmation"]').fill("a-good-password");
    await register.getByRole("button", { name: "Register" }).click();
    await expect(register.getByText("Your account has been created.")).toBeVisible();
    await context.close();

    const users = `${env.adminUrl}/admin/users?query=${email.split("@")[0]}`;
    await deleteUser(page, await idFromListLink(page, users, email, "Manage"));
  });
});

test("self-registration that requires email verification warns while email is not set up", async ({ page }) => {
  await withSettingsRestored(page, "/admin/settings/email", async () => {
    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);
    await withSettingsRestored(page, general, async () => {
      await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
      await saveSettings(page);
      await expect(page.getByText("Email isn't set up, so registration is unavailable.")).toBeVisible();
      // And the register page is not offered.
      expect((await page.request.get(`${env.authUrl}/account/register`, { maxRedirects: 0 })).status()).toBe(404);
    });
  });
});

test("self-registration with email verification: the mailed link activates the account", async ({ page, browser, request }) => {
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
    await saveSettings(page);

    const email = `${uniqueIdentifier("u")}@example.com`;
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    // The sign-in page now offers it.
    await register.goto(`${env.adminUrl}/account/profile`);
    await register.getByRole("link", { name: /register/i }).click();
    await register.locator('input[name="email"]').fill(email);
    await register.getByRole("button", { name: "Register" }).click();
    await expect(register.getByText("Check your email")).toBeVisible();

    const mail = await waitForMail(request, email);
    const link = linksIn(mail).find((l) => l.startsWith(env.authUrl))!;
    await register.goto(link);
    await register.locator('input[name="password"]').fill("a-registered-password");
    await register.locator('input[name="passwordConfirmation"]').fill("a-registered-password");
    await register.getByRole("button", { name: "Create account" }).click();
    await expect(register.getByText("Congratulations! Your account has been activated.")).toBeVisible();
    await context.close();

    const users = `${env.adminUrl}/admin/users?query=${email.split("@")[0]}`;
    const id = await idFromListLink(page, users, email, "Manage");
    await page.goto(`${env.adminUrl}/admin/users/${id}/email`);
    // Activated through the mailed link: the address is verified.
    await expect(page.locator('input[name="emailVerified"]')).toBeChecked();
    await deleteUser(page, id);
  });
});

test("dynamic client registration opens the registration endpoint, and closes it again", async ({ page, request }) => {
  const discovery = async () => (await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  const register = () =>
    request.post(`${env.authUrl}/connect/register`, {
      // A loopback redirect, as a native or MCP client registers: a public client may not register https.
      data: { redirect_uris: ["http://127.0.0.1:8765/callback"], client_name: "e2e dcr", token_endpoint_auth_method: "none" },
      failOnStatusCode: false,
    });
  expect((await discovery()).registration_endpoint).toBeUndefined();
  expect((await register()).status()).not.toBe(201);

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { dynamicClientRegistrationEnabled: true });
    await saveSettings(page);
    expect((await discovery()).registration_endpoint).toBe(`${env.authUrl}/connect/register`);
    const response = await register();
    expect(response.status(), await response.text()).toBe(201);
    const { client_id } = (await response.json()) as { client_id: string };

    // The registered client is listed, read-only identifier and all, and removed again here.
    const clients = `${env.adminUrl}/admin/clients`;
    const id = await idFromListLink(page, clients, client_id, "Manage");
    await page.goto(clientUrl(id, "settings"));
    await expect(page.locator('input[name="clientIdentifier"]')).toHaveAttribute("readonly", "");
    // Registered with the global setting for the ID token, as a client created here is, so its Tokens
    // tab has a choice checked and saves as loaded.
    await page.goto(clientUrl(id, "tokens"));
    await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
    await saveAndExpectSaved(page, "Client settings saved successfully");
    await page.goto(clientUrl(id, "delete"));
    await page.locator('input[name="clientIdentifier"]').fill(client_id);
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(page).toHaveURL(clients);
  });
  expect((await discovery()).registration_endpoint).toBeUndefined();
});

test("the global password grant switch applies to clients that follow it", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  const secret = await page.locator("#clientSecret").inputValue();
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await expect(page.locator('input[name="ropcEnabled"][value="global"]')).toBeChecked();
  const grant = () => passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect((await grant()).body.error).toBe("unauthorized_client");

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { ropcFlowEnabled: true });
    await saveSettings(page);
    expect((await grant()).status).toBe(200);
  });
  expect((await grant()).body.error).toBe("unauthorized_client");
});

test("the global implicit flow switch applies to clients that follow it", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const implicit = () =>
    authorizeAndLand(browser, { client_id: client.identifier, response_type: "token", scope: "openid", state: "s" }, user);

  let params = redirectParams(await implicit());
  expect(params.get("error")).toBe("unauthorized_client");

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { implicitFlowEnabled: true });
    await saveSettings(page);
    params = redirectParams(await implicit());
    expect(params.get("access_token"), params.toString()).toBeTruthy();
    expect(params.get("token_type")).toBe("Bearer");
  });
});

test("with PKCE no longer required, a confidential client may leave it out", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const withoutPkce = () =>
    authorizeAndLand(browser, { client_id: client.identifier, response_type: "code", scope: "openid", state: "s" }, user);

  let params = redirectParams(await withoutPkce());
  expect(params.get("error")).toBe("invalid_request");

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { pkceRequired: false });
    await saveSettings(page);
    params = redirectParams(await withoutPkce());
    expect(params.get("code"), params.toString()).toBeTruthy();
  });

  // And with PKCE on, a challenge is accepted as always.
  const verifier = randomBytes(32).toString("base64url");
  params = redirectParams(
    await authorizeAndLand(
      browser,
      {
        client_id: client.identifier,
        response_type: "code",
        scope: "openid",
        state: "s",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
      },
      user,
    ),
  );
  expect(params.get("code")).toBeTruthy();
});
