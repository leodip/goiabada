// What only a browser sign-in leaves behind: a session, and the consent given on the consent screen.
import type { Page } from "@playwright/test";
import { clientUrl, rowWithCell, userUrl } from "../../../lib/admin-console";
import { openSignIn, signInThroughClient, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { codeToken, jwtClaims } from "../../../lib/oauth";
import { browserSignInClient } from "../../../lib/test-clients";

// Starts another sign-in in the same browser and says where it lands: straight back at the client
// (the session signed the user in), or on the password form.
async function signInAgainLandsOn(page: Page, clientId: string): Promise<"client" | "password"> {
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: "openid",
    state: "again",
    // RFC 7636's example challenge: this sign-in's code is never redeemed.
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  });
  await page.goto(`${env.authUrl}/auth/authorize?${query}`);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/pwd");
  return page.url().startsWith(testRedirectUri) ? "client" : "password";
}

test("a browser sign-in is listed as a session, signs the user in again, and ends from the user's page", async ({
  page,
  request,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, {
    clientId: client.identifier,
    email: user.email,
    password: user.password,
    scope: "openid email",
  });

  // The code is good for tokens naming the user.
  const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  expect(jwtClaims(tokens.body.id_token as string).email).toBe(user.email);

  await page.goto(userUrl(user.id, "sessions"));
  const sessions = page.locator("table tbody tr");
  await expect(sessions).toHaveCount(1);
  await expect(sessions.first()).toContainText(client.identifier);
  await expect(sessions.first()).not.toContainText("Current session");

  const userPage = await signIn.context.newPage();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("client");

  await sessions.first().getByRole("button", { name: "End session" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("No sessions found.")).toBeVisible();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("password");
  await signIn.context.close();
});

test("a session ends from the client's User sessions tab", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, {
    clientId: client.identifier,
    email: user.email,
    password: user.password,
    scope: "openid",
  });

  await page.goto(clientUrl(client.id, "user-sessions"));
  const row = page.getByRole("row").filter({ hasText: user.email });
  await expect(row).toHaveCount(1);
  await row.getByRole("button", { name: "End session" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText(user.email);
  await dialog.getByRole("button", { name: "Yes" }).click();
  // This tab marks the row in place, where the user's own Sessions tab reloads.
  await expect(row.getByText("Removed")).toBeVisible();
  await page.reload();
  await expect(page.getByText("No sessions found.")).toBeVisible();

  await page.goto(userUrl(user.id, "sessions"));
  await expect(page.getByText("No sessions found.")).toBeVisible();
  const userPage = await signIn.context.newPage();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("password");
  await signIn.context.close();
});

test("consent given on the consent screen is listed, remembered, and revoked", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const options = { clientId: client.identifier, scope: "openid profile" };

  await page.goto(userUrl(user.id, "consents"));
  await expect(page.getByText("No consents have been granted by this user yet.")).toBeVisible();

  // First sign-in: the consent screen asks.
  let attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.page.getByRole("button", { name: "Give consent" }).click();
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  await page.reload();
  const row = rowWithCell(page, "openid profile");
  await expect(row).toContainText(client.identifier);

  // Another browser, same scope: no consent screen, the stored consent covers it.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  await row.getByRole("button", { name: "Revoke" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText(client.identifier);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(row.getByText("Removed")).toBeVisible();
  await page.reload();
  await expect(page.getByText("No consents have been granted by this user yet.")).toBeVisible();

  // Revoked: the consent screen asks again.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.context.close();
});
