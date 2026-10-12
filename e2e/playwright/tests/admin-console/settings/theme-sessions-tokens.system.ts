// Settings - UI theme, Sessions and Tokens. Runs alone, and every test puts the settings back.
import { expect, test } from "../../../lib/fixtures";
import { env } from "../../../lib/environment";
import { clientUrl, grantClientPermission, readClientSecret } from "../../../lib/admin-console";
import { signInThroughClient, type BrowserSignIn } from "../../../lib/browser-sign-in";
import { clientCredentialsToken, userTokens } from "../../../lib/oauth";
import { fillSettingsForm, readSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { authorizeAgain, expectSessionDeleted, sessionIds } from "../../../lib/sessions";
import { browserSignInClient, passwordGrantClient } from "../../../lib/test-clients";

test("a UI theme chosen here themes the console and the sign-in pages", async ({ page, browser }) => {
  await withSettingsRestored(page, "/admin/settings/ui-theme", async () => {
    const themes = await page.locator('select[name="themeSelection"] option').evaluateAll((o) => o.map((x) => (x as HTMLOptionElement).value));
    const theme = themes.find((t) => t && t !== "dark")!;
    await fillSettingsForm(page, { themeSelection: theme });
    await saveSettings(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const signIn = await context.newPage();
    await signIn.goto(`${env.adminUrl}/account/profile`);
    await expect(signIn.locator('input[name="password"]')).toBeVisible();
    await expect(signIn.locator("html")).toHaveAttribute("data-theme", theme);
    await context.close();
  });
});

test("session timeouts are saved, and refused when out of range or inconsistent", async ({ page }) => {
  const path = "/admin/settings/sessions";
  await withSettingsRestored(page, path, async () => {
    for (const { values, message } of [
      { values: { userSessionIdleTimeoutInSeconds: "0" }, message: "User session - idle timeout in seconds must be greater than zero." },
      { values: { userSessionIdleTimeoutInSeconds: "90000", userSessionMaxLifetimeInSeconds: "86400" }, message: "User session - the idle timeout cannot be greater than the max lifetime." },
      { values: { userSessionMaxLifetimeInSeconds: "abc" }, message: /Invalid|number|positive/ },
    ]) {
      await page.goto(`${env.adminUrl}${path}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expect(page.getByText(message).first()).toBeVisible();
    }

    await page.goto(`${env.adminUrl}${path}`);
    await fillSettingsForm(page, { userSessionIdleTimeoutInSeconds: "3600", userSessionMaxLifetimeInSeconds: "43200" });
    await saveSettings(page);
    expect(await readSettingsForm(page, path)).toMatchObject({ userSessionIdleTimeoutInSeconds: "3600", userSessionMaxLifetimeInSeconds: "43200" });
  });
});

test("the session cap is refused out of range, and past it a sign-in ends the user's least recently used session", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const path = "/admin/settings/sessions";
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await withSettingsRestored(page, path, async () => {
    for (const value of ["1001", "-1", "abc"]) {
      await page.goto(`${env.adminUrl}${path}`);
      await fillSettingsForm(page, { maxUserSessionsPerUser: value });
      await page.locator("#btnSave").click();
      await expect(page.getByText("User session - max sessions per user must be between 0 and 1000.")).toBeVisible();
    }
    await page.goto(`${env.adminUrl}${path}`);
    await fillSettingsForm(page, { maxUserSessionsPerUser: "2" });
    await saveSettings(page);
    expect(await readSettingsForm(page, path)).toMatchObject({ maxUserSessionsPerUser: "2" });

    // Three browsers, each signing the user in after the one before: the third sign-in ends the first's
    // session, and the first browser is asked for the password again.
    const signIns: BrowserSignIn[] = [];
    const signInAgain = async () =>
      signIns.push(await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" }));
    try {
      await signInAgain();
      const [first] = await sessionIds(page, user.id);
      await signInAgain();
      await signInAgain();
      const left = await sessionIds(page, user.id);
      expect(left).toHaveLength(2);
      expect(left).not.toContain(first);
      expect((await authorizeAgain(signIns[0].context, client.identifier)).landed).toBe("password");
      expect((await authorizeAgain(signIns[2].context, client.identifier)).landed).toBe("client");
      await expectSessionDeleted(page, first, "session_cap");
    } finally {
      for (const signIn of signIns) await signIn.context.close();
    }
  });
});

test("the global token expiration is the lifetime of a client that sets none", async ({ page, request, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const secret = await readClientSecret(page, client.id);
  await page.goto(clientUrl(client.id, "tokens"));
  await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("0");

  await withSettingsRestored(page, "/admin/settings/tokens", async () => {
    await fillSettingsForm(page, { tokenExpirationInSeconds: "321" });
    await saveSettings(page);
    const answer = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
    expect(answer.body.expires_in).toBe(321);
  });
});

test("the global switch for OpenID Connect claims in the access token applies to clients that follow it", async ({
  page,
  request,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const accessTokenEmail = async () =>
    (await userTokens(request, client.identifier, secret, user, "openid email")).access.email;
  // Off, as seeded: the access token carries no profile or email claims.
  expect(await accessTokenEmail()).toBeUndefined();

  await withSettingsRestored(page, "/admin/settings/tokens", async () => {
    await fillSettingsForm(page, { includeOpenIDConnectClaimsInAccessToken: true });
    await saveSettings(page);
    expect(await accessTokenEmail()).toBe(user.email);
  });
  expect(await accessTokenEmail()).toBeUndefined();
});

test("token durations out of range or inconsistent are refused", async ({ page }) => {
  const path = "/admin/settings/tokens";
  await withSettingsRestored(page, path, async () => {
    for (const { values, message } of [
      { values: { tokenExpirationInSeconds: "0" }, message: "Token expiration in seconds must be greater than zero." },
      {
        values: { refreshTokenOfflineIdleTimeoutInSeconds: "7200", refreshTokenOfflineMaxLifetimeInSeconds: "3600" },
        message: "Refresh token offline - idle timeout cannot be greater than max lifetime.",
      },
    ]) {
      await page.goto(`${env.adminUrl}${path}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expect(page.getByText(message)).toBeVisible();
    }
  });
});
