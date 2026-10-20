// Settings - Theme, Sessions and Tokens. Runs alone, and every test puts the settings back.
import type { Page } from "@playwright/test";
import { expect, test } from "../../../lib/fixtures";
import { env } from "../../../lib/environment";
import { clientUrl, expectRefusal, grantClientPermission, readClientSecret } from "../../../lib/admin-console";
import { signInThroughClient, type BrowserSignIn } from "../../../lib/browser-sign-in";
import { clientCredentialsToken, userTokens } from "../../../lib/oauth";
import { fillSettingsForm, readSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { authorizeAgain, expectSessionDeleted, sessionIds } from "../../../lib/sessions";
import { browserSignInClient, passwordGrantClient } from "../../../lib/test-clients";

const themePath = "/admin/settings/ui-theme";
const sessionsPath = "/admin/settings/sessions";
const tokensPath = "/admin/settings/tokens";

type Theme = "" | "light" | "dark";

// What a page's root element says about its theme: Light and Dark name themselves, and Automatic
// names none, leaving it to the device, as the color-scheme meta's "light dark" says. And what the
// page draws: its background under a device asking for light and for dark, which Light and Dark keep
// whatever the device asks, and Automatic follows.
async function expectTheme(page: Page, theme: Theme) {
  const html = page.locator("html");
  if (theme) await expect(html).toHaveAttribute("data-theme", theme);
  else await expect(html).not.toHaveAttribute("data-theme");
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute("content", theme || "light dark");

  const background = async (colorScheme: "light" | "dark") => {
    // Reduced motion, so no transition is caught half way between the two.
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  };
  const onLight = await background("light");
  const onDark = await background("dark");
  await page.emulateMedia({ colorScheme: null, reducedMotion: null });
  if (theme) expect(onDark, `${themeLabels[theme]} keeps its background on a dark device`).toBe(onLight);
  else expect(onDark, "Automatic draws a dark device's page darker").not.toBe(onLight);
}

const themeLabels: Record<Theme, string> = { "": "Automatic", light: "Light", dark: "Dark" };

test("a theme chosen here themes the console and the sign-in pages, and Automatic follows the device", async ({ page, browser }) => {
  await withSettingsRestored(page, themePath, async () => {
    // Automatic, Light and Dark, and no other.
    await expect(page.getByRole("radio")).toHaveCount(3);
    for (const theme of ["light", "dark", ""] as const) {
      await page.goto(`${env.adminUrl}${themePath}`);
      await page.getByRole("radio", { name: themeLabels[theme], exact: true }).check();
      await saveSettings(page);
      await expect(page.getByRole("radio", { name: themeLabels[theme], exact: true })).toBeChecked();
      await expectTheme(page, theme);

      const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const signIn = await context.newPage();
      await signIn.goto(`${env.adminUrl}/account/profile`);
      await expect(signIn.locator('input[name="password"]')).toBeVisible();
      await expectTheme(signIn, theme);
      await context.close();
    }
  });
});

test("choosing a theme shows it at once, and leaving without saving keeps the saved one", async ({ page }) => {
  const saved = (await readSettingsForm(page, themePath)).themeSelection as Theme;
  const other: Theme = saved === "dark" ? "light" : "dark";
  await page.getByRole("radio", { name: themeLabels[other], exact: true }).check();
  await expectTheme(page, other);

  // Nothing was saved: the page drawn again shows the saved theme, chosen.
  expect(await readSettingsForm(page, themePath)).toMatchObject({ themeSelection: saved });
  await expectTheme(page, saved);
});

test("session timeouts are saved, and refused when out of range or inconsistent", async ({ page }) => {
  await withSettingsRestored(page, sessionsPath, async () => {
    for (const { values, field, message } of [
      { values: { userSessionIdleTimeoutInSeconds: "0" }, field: "userSessionIdleTimeoutInSeconds", message: "The idle timeout must be greater than zero." },
      {
        values: { userSessionIdleTimeoutInSeconds: "90000", userSessionMaxLifetimeInSeconds: "86400" },
        field: "userSessionIdleTimeoutInSeconds",
        message: "The idle timeout can't be longer than the maximum lifetime.",
      },
      // Not a whole number: refused by the console itself, at its field.
      {
        values: { userSessionMaxLifetimeInSeconds: "abc" },
        field: "userSessionMaxLifetimeInSeconds",
        message: "Enter the maximum lifetime as a whole number of seconds.",
      },
    ]) {
      await page.goto(`${env.adminUrl}${sessionsPath}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expectRefusal(page, "sessions-error", field, message);
    }

    await page.goto(`${env.adminUrl}${sessionsPath}`);
    await fillSettingsForm(page, { userSessionIdleTimeoutInSeconds: "3600", userSessionMaxLifetimeInSeconds: "43200" });
    await saveSettings(page);
    expect(await readSettingsForm(page, sessionsPath)).toMatchObject({ userSessionIdleTimeoutInSeconds: "3600", userSessionMaxLifetimeInSeconds: "43200" });
  });
});

test("a duration is read out in words under its field as it is typed", async ({ page }) => {
  // Nothing is saved: the readout is the page's own.
  await page.goto(`${env.adminUrl}${sessionsPath}`);
  const idleTimeout = page.locator("#userSessionIdleTimeoutInSeconds");
  const readout = page.locator('[data-duration-for="userSessionIdleTimeoutInSeconds"]');
  for (const [value, words] of [
    ["5400", "1 hour, 30 minutes"],
    ["abc", "Enter a whole number of seconds."],
    ["999999999", "That's too long. Enter a shorter duration."],
  ]) {
    await idleTimeout.fill(value);
    await expect(readout).toHaveText(words);
  }
});

test("the session cap is refused out of range, and past it a sign-in ends the user's least recently used session", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await withSettingsRestored(page, sessionsPath, async () => {
    for (const { value, message } of [
      { value: "1001", message: "The maximum sessions per user must be between 0 and 1000." },
      { value: "-1", message: "The maximum sessions per user must be between 0 and 1000." },
      // Not a whole number: refused by the console itself, rather than sent as 0, which means no limit.
      { value: "abc", message: "Enter the maximum sessions per user as a whole number, from 0 to 1000." },
    ]) {
      await page.goto(`${env.adminUrl}${sessionsPath}`);
      await fillSettingsForm(page, { maxUserSessionsPerUser: value });
      await page.locator("#btnSave").click();
      await expectRefusal(page, "sessions-error", "maxUserSessionsPerUser", message);
    }
    await page.goto(`${env.adminUrl}${sessionsPath}`);
    await fillSettingsForm(page, { maxUserSessionsPerUser: "2" });
    await saveSettings(page);
    expect(await readSettingsForm(page, sessionsPath)).toMatchObject({ maxUserSessionsPerUser: "2" });

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

  await withSettingsRestored(page, tokensPath, async () => {
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

  await withSettingsRestored(page, tokensPath, async () => {
    await fillSettingsForm(page, { includeOpenIDConnectClaimsInAccessToken: true });
    await saveSettings(page);
    expect(await accessTokenEmail()).toBe(user.email);
  });
  expect(await accessTokenEmail()).toBeUndefined();
});

test("token durations out of range, inconsistent or not whole numbers are refused", async ({ page }) => {
  await withSettingsRestored(page, tokensPath, async () => {
    for (const { values, field, message } of [
      { values: { tokenExpirationInSeconds: "0" }, field: "tokenExpirationInSeconds", message: "The token lifetime must be greater than zero." },
      {
        values: { refreshTokenOfflineIdleTimeoutInSeconds: "7200", refreshTokenOfflineMaxLifetimeInSeconds: "3600" },
        field: "refreshTokenOfflineIdleTimeoutInSeconds",
        message: "The offline idle timeout can't be longer than the offline maximum lifetime.",
      },
      // Not a whole number: refused by the console itself, rather than sent as 0.
      {
        values: { refreshTokenOfflineMaxLifetimeInSeconds: "1.5" },
        field: "refreshTokenOfflineMaxLifetimeInSeconds",
        message: "Enter the offline maximum lifetime as a whole number of seconds.",
      },
    ]) {
      await page.goto(`${env.adminUrl}${tokensPath}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expectRefusal(page, "tokens-error", field, message);
    }
  });
});
