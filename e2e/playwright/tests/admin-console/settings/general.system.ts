// Settings - General, each switch followed to what it changes. Runs alone, and every test puts the
// settings back (lib/settings.ts).
import { createHash, randomBytes } from "node:crypto";
import {
  cancelDialog,
  clientRow,
  clientUrl,
  confirmDialog,
  deleteClient,
  deleteUser,
  expectRefusal,
  idFromListLink,
  readClientSecret,
  saveAndExpectSaved,
  submitNewUser,
} from "../../../lib/admin-console";
import { authorizeAndLand, redirectParams } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { linksIn, waitForMail } from "../../../lib/mailpit";
import { passwordToken } from "../../../lib/oauth";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { browserSignInClient } from "../../../lib/test-clients";
import { testPrefix, uniqueIdentifier } from "../../../lib/unique";

const general = "/admin/settings/general";
const registerUrl = `${env.authUrl}/account/register`;
const issuerRule = "Invalid issuer. Enter an https URL with no query, fragment or user info, or the auth server's base URL.";
const issuerChange = "You're changing the issuer";

test("the app name is saved and names the console's and the sign-in pages", async ({ page, browser }) => {
  await withSettingsRestored(page, general, async () => {
    const name = `E2E ${randomBytes(3).toString("hex")}`;
    await fillSettingsForm(page, { appName: name });
    await saveSettings(page);
    await expect(page).toHaveTitle(`General settings – ${name}`);
    await expect(page.locator("a.sidebar-brand")).toHaveText(name);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const signIn = await context.newPage();
    await signIn.goto(`${env.adminUrl}/account/profile`);
    await expect(signIn.locator('input[name="password"]')).toBeVisible();
    await expect(signIn).toHaveTitle(`Sign in – ${name}`);
    await expect(signIn.locator("p.auth-brand")).toHaveText(name);
    await context.close();
  });
});

for (const { name, values, field, message } of [
  { name: "an app name that is too long", values: { appName: "x".repeat(100) }, field: "appName", message: "App name is too long. The maximum length is 30 characters." },
  // The issuer is an https URL with no query, fragment or user info, or exactly the auth server's
  // base URL (#576 decision 3); every other value gets the one sentence stating that rule.
  { name: "an issuer URI with no host", values: { issuer: "https://" }, field: "issuer", message: issuerRule },
  { name: "an issuer with a space", values: { issuer: "not an identifier" }, field: "issuer", message: issuerRule },
  { name: "an issuer that is a plain name", values: { issuer: "goiabada" }, field: "issuer", message: issuerRule },
  { name: "an http issuer other than the base URL", values: { issuer: "http://auth.example.com" }, field: "issuer", message: issuerRule },
]) {
  test(`${name} is refused`, async ({ page }) => {
    await withSettingsRestored(page, general, async () => {
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      // Changing the issuer asks first; the refusal comes after.
      if ("issuer" in values) await confirmDialog(page, issuerChange);
      await expectRefusal(page, "general-error", field, message);
    });
  });
}

test("changing the issuer asks first, and Cancel changes nothing", async ({ page }) => {
  await page.goto(`${env.adminUrl}${general}`);
  const issuer = await page.locator("#issuer").inputValue();
  await page.locator("#issuer").fill(`${issuer}/changed`);
  await page.locator("#btnSave").click();
  await expect(page.locator("dialog[open]")).toContainText("Save these changes?");
  await cancelDialog(page, issuerChange);
  await expect(page.getByText("Settings saved.", { exact: true })).toHaveCount(0);
  await page.goto(`${env.adminUrl}${general}`);
  await expect(page.locator("#issuer")).toHaveValue(issuer);
});

test("a refused save keeps comparing against the stored issuer, so saving it again asks again", async ({ page }) => {
  await withSettingsRestored(page, general, async () => {
    const issuer = await page.locator("#issuer").inputValue();
    const changed = `${issuer}/changed`;
    // The app name is refused before the issuer is looked at, so nothing is saved and no one is signed out.
    await fillSettingsForm(page, { appName: "x".repeat(100), issuer: changed });
    await page.locator("#btnSave").click();
    await confirmDialog(page, issuerChange);
    await expectRefusal(page, "general-error", "appName", "App name is too long. The maximum length is 30 characters.");
    // The inputs keep what was submitted; the issuer they are compared against is the stored one.
    await expect(page.locator("#issuer")).toHaveValue(changed);

    await page.locator("#btnSave").click();
    await cancelDialog(page, issuerChange);
    await expect(page.locator("dialog[open]")).toHaveCount(0);
    await page.goto(`${env.adminUrl}${general}`);
    await expect(page.locator("#issuer")).toHaveValue(issuer);
  });
});

test("the page's cautions and the email verification choice follow the boxes, before any save", async ({ page }) => {
  // Nothing is saved: the page shows and hides these itself.
  await page.goto(`${env.adminUrl}${general}`);
  // Registration off, as seeded: whether it would need email verification is not asked.
  const verificationRow = page.locator("#emailVerificationRow");
  await expect(verificationRow).toBeHidden();
  await page.locator("#selfRegistrationEnabled").check();
  await expect(verificationRow).toBeVisible();
  await page.locator("#selfRegistrationEnabled").uncheck();
  await expect(verificationRow).toBeHidden();

  for (const { box, on, caution } of [
    { box: "#pkceRequired", on: false, caution: "#pkceWarning" },
    { box: "#implicitFlowEnabled", on: true, caution: "#implicitFlowWarning" },
    { box: "#ropcFlowEnabled", on: true, caution: "#ropcFlowWarning" },
  ]) {
    await expect(page.locator(caution)).toBeHidden();
    await page.locator(box).setChecked(on);
    await expect(page.locator(caution)).toBeVisible();
    await page.locator(box).setChecked(!on);
    await expect(page.locator(caution)).toBeHidden();
  }
});

test("the password policy applies to passwords set from then on", async ({ page }) => {
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { passwordPolicy: "medium" });
    await saveSettings(page);
    await expect(page.getByRole("radio", { name: "Medium", exact: true })).toBeChecked();

    const email = `${uniqueIdentifier("u")}@example.com`;
    await submitNewUser(page, { email, password: "alllowercase" });
    await expectRefusal(page, "user-error", "password", "Add an uppercase letter to the password.");
    await submitNewUser(page, { email, password: "Medium1Pass" });
    await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
    await deleteUser(page, Number(page.url().match(/\/admin\/users\/(\d+)\//)![1]));
  });
});

test("the NIST SP 800-63B card says what it asks, and registration holds a password to it", async ({ page, browser }) => {
  await withSettingsRestored(page, general, async () => {
    const nist = page.getByRole("radio", { name: "NIST SP 800-63B", exact: true });
    await expect(page.locator('input[name="passwordPolicy"]').first()).toHaveAttribute("value", "nist");
    await expect(nist).toHaveAccessibleDescription(/^At least 15 characters, any characters at all\..* Recommended\. It follows the US National Institute of Standards and Technology's guideline/);
    await expect(page.getByRole("radio", { name: "Low", exact: true })).toHaveAccessibleDescription("At least 6 characters. Falls short of NIST SP 800-63B.");
    await nist.check();
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);
    await expect(nist).toBeChecked();

    // A local part of 10 characters, so the address's own, padded with a year and a symbol, is 15.
    const local = `${testPrefix}${randomBytes(3).toString("hex")}`;
    const email = `${local}@example.com`;
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    await register.goto(registerUrl);
    await expect(register.locator("#password-rules")).toHaveText(
      "At least 15 characters. A few unrelated words make a long password that's easy to remember. Common passwords, and the account's email address or the app's name, are refused.",
    );
    const submit = async (password: string) => {
      await register.locator("#email").fill(email);
      await register.locator("#password").fill(password);
      await register.locator("#passwordConfirmation").fill(password);
      await register.getByRole("button", { name: "Create account", exact: true }).click();
    };

    await submit("passwordpassword");
    await expect(register.locator("#register-error")).toHaveText(
      "This password is one attackers try first. Choose another: a few unrelated words make a long password that's easy to remember.",
    );
    await expect(register.locator("#password")).toHaveAttribute("aria-invalid", "true");

    const padded = local.padEnd(15, "2026!");
    expect(padded).toHaveLength(15);
    await submit(padded);
    await expect(register.locator("#register-error")).toHaveText(
      "This password is too close to the account's email address, username or the app's name. Choose another.",
    );

    await submit("amber lantern drifts over a quiet harbor");
    await expect(register.getByRole("heading", { name: "Account created" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(email);
    await context.close();

    await deleteUser(page, await idFromListLink(page, `${env.adminUrl}/admin/users?query=${local}`, email));
  });
});

test("self-registration opens the register page; without email verification it creates the account", async ({ page, browser }) => {
  // Off, as seeded: the page is not offered.
  expect((await page.request.get(registerUrl, { maxRedirects: 0 })).status()).not.toBe(200);

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);

    const email = `${uniqueIdentifier("u")}@example.com`;
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    await register.goto(registerUrl);
    await expect(register).toHaveTitle(/^Create an account – /);
    // The password's rules, under the seeded policy, are said under its field.
    await expect(register.locator("#password-rules")).toHaveText("At least 6 characters.");
    await register.locator("#email").fill(email);
    await register.locator("#password").fill("a-good-password");
    await register.locator("#passwordConfirmation").fill("a-good-password");
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(register.getByRole("heading", { name: "Account created" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(email);
    await expect(register.getByRole("link", { name: "Sign in to your account" })).toHaveAttribute("href", `${env.adminUrl}/account/profile`);
    await context.close();

    const users = `${env.adminUrl}/admin/users?query=${email.split("@")[0]}`;
    await deleteUser(page, await idFromListLink(page, users, email));
  });
});

test("registration refuses passwords that don't match, and an address that already has an account", async ({ page, browser, users }) => {
  const existing = await users.create();
  const email = `${uniqueIdentifier("u")}@example.com`;
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    await register.goto(registerUrl);
    await register.locator("#email").fill(email);
    await register.locator("#password").fill("a-good-password");
    await register.locator("#passwordConfirmation").fill("another-password");
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(register.locator("#register-error")).toHaveText("The passwords don't match.");
    await expect(register.locator("#passwordConfirmation")).toHaveAttribute("aria-invalid", "true");
    // The address stays in the form for the retry.
    await expect(register.locator("#email")).toHaveValue(email);

    await register.locator("#email").fill(existing.email);
    await register.locator("#password").fill("a-good-password");
    await register.locator("#passwordConfirmation").fill("a-good-password");
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(register.locator("#register-error")).toHaveText("Apologies, but this email address is already registered.");
    await expect(register.locator("#email")).toHaveAttribute("aria-invalid", "true");
    await context.close();
  });
  // Neither refusal registered anyone.
  await page.goto(`${env.adminUrl}/admin/users?query=${email.split("@")[0]}`);
  await expect(page.getByText("No users found.", { exact: true })).toBeVisible();
});

test("self-registration that requires email verification warns while email is not set up", async ({ page }) => {
  await withSettingsRestored(page, "/admin/settings/email", async () => {
    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);
    await withSettingsRestored(page, general, async () => {
      await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
      await saveSettings(page);
      const warning = page.locator("#selfRegistrationEmailWarning");
      await expect(warning).toBeVisible();
      await expect(warning).toContainText("Email isn't set up, so nobody can register: set it up, or stop requiring email verification.");
      await expect(warning.getByRole("link", { name: "Email settings" })).toHaveAttribute("href", "/admin/settings/email");
      // And the register page is not offered.
      expect((await page.request.get(registerUrl, { maxRedirects: 0 })).status()).toBe(404);
      // Without verification, registration needs no email, and the warning goes.
      await page.locator("#selfRegistrationRequiresEmailVerification").uncheck();
      await expect(warning).toBeHidden();
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
    // The sign-in page now offers it. The password is chosen later, on the page the mailed link opens.
    await register.goto(`${env.adminUrl}/account/profile`);
    await register.getByRole("link", { name: "Create an account" }).click();
    await expect(register.getByText("We'll email you a link to choose your password.")).toBeVisible();
    await expect(register.locator("#password")).toHaveCount(0);
    await register.locator("#email").fill(email);
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(register.getByRole("heading", { name: "Check your email" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(email);

    const mail = await waitForMail(request, email);
    const link = linksIn(mail).find((l) => l.startsWith(env.authUrl))!;
    await register.goto(link);
    await expect(register.getByRole("heading", { name: "Choose your password" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(email);
    await register.locator("#password").fill("a-registered-password");
    await register.locator("#passwordConfirmation").fill("a-registered-password");
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(register.getByRole("heading", { name: "Account activated" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(email);

    // A link works once: followed again, it says so and offers to register again.
    await register.goto(link);
    await expect(register.getByRole("heading", { name: "This link can't be used" })).toBeVisible();
    await expect(register.getByRole("link", { name: "Register again" })).toHaveAttribute("href", "/account/register");
    await context.close();

    const users = `${env.adminUrl}/admin/users?query=${email.split("@")[0]}`;
    const id = await idFromListLink(page, users, email);
    await page.goto(`${env.adminUrl}/admin/users/${id}/email`);
    // Activated through the mailed link: the address is verified.
    await expect(page.locator("#emailVerified")).toBeChecked();
    await deleteUser(page, id);
  });
});

test("registering an address that already has an account answers the same, and mails the account a notice", async ({
  page,
  browser,
  request,
  users,
}) => {
  // A verified address, the only kind the notice goes to, as forgot password mails only those.
  const existing = await users.create({ emailVerified: true });
  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
    await saveSettings(page);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const register = await context.newPage();
    await register.goto(registerUrl);
    await register.locator("#email").fill(existing.email);
    await register.getByRole("button", { name: "Create account", exact: true }).click();
    // The page a new address gets, so it tells nobody the address has an account.
    await expect(register.getByRole("heading", { name: "Check your email" })).toBeVisible();
    await expect(register.locator("code.auth-address")).toHaveText(existing.email);
    await context.close();

    const notice = await waitForMail(request, existing.email);
    expect(notice.subject).toContain("You already have an account");
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

    // The registered client is listed as self-registered, read-only identifier and all, and removed
    // again here, pass or fail: its identifier is the server's, which the next run's sweep would not
    // know for a test's.
    const id = await idFromListLink(page, `${env.adminUrl}/admin/clients`, client_id);
    try {
      await expect(clientRow(page, client_id).getByText("Self-registered", { exact: true })).toBeVisible();
      await page.goto(clientUrl(id, "settings"));
      await expect(page.locator("#clientIdentifier")).toHaveAttribute("readonly", "");
      // Registered with the global setting for the ID token, as a client created here is, so its Tokens
      // tab has a choice checked and saves as loaded.
      await page.goto(clientUrl(id, "tokens"));
      await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
      await saveAndExpectSaved(page, "Token settings saved.");
    } finally {
      await deleteClient(page, id);
    }
  });
  expect((await discovery()).registration_endpoint).toBeUndefined();
});

test("the global password grant switch applies to clients that follow it", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
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
