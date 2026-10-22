// What only a browser sign-in leaves behind: a session, and the consent given on the consent screen.
import type { Page } from "@playwright/test";
import { cancelDialog, clientUrl, confirmDialog, idFromListLink, rowWithCell, userUrl } from "../../../lib/admin-console";
import { openSignIn, signInThroughClient, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { codeToken, jwtClaims } from "../../../lib/oauth";
import { browserSignInClient } from "../../../lib/test-clients";

const noUserSessions = "This user isn't signed in anywhere.";
const noConsents = "This user hasn't given consent to any client.";

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
  const sessions = page.locator("#sessionsTable tbody tr");
  await expect(sessions).toHaveCount(1);
  await expect(sessions.first()).toContainText(client.identifier);
  // The user's browser, not the administrator's.
  await expect(sessions.first().getByText("This device", { exact: true })).toHaveCount(0);

  const userPage = await signIn.context.newPage();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("client");

  // Ending it asks first, and Cancel leaves the user signed in.
  const end = sessions.first().getByRole("button", { name: /^End session/ });
  await end.click();
  await cancelDialog(page, "End this session?");
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("client");

  await end.click();
  await confirmDialog(page, "Clients the user signed in to from it");
  // The row stays until the page is drawn again, its button giving way to a tag.
  await expect(sessions.first().getByText("Ended", { exact: true })).toBeVisible();
  await expect(page.locator("#sessions-status")).toContainText("Session ended.");
  await page.reload();
  await expect(page.getByText(noUserSessions)).toBeVisible();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("password");
  await signIn.context.close();
});

test("a session ends from the client's Sessions tab", async ({ page, browser, clients, users }) => {
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
  await row.getByRole("button", { name: /^End session/ }).click();
  await confirmDialog(page, user.email);
  // As on the user's own Sessions tab, the row is marked in place.
  await expect(row.getByText("Ended", { exact: true })).toBeVisible();
  await expect(page.locator("#sessions-status")).toContainText("Session ended.");
  await page.reload();
  await expect(page.getByText("No one is signed in to this client.")).toBeVisible();

  await page.goto(userUrl(user.id, "sessions"));
  await expect(page.getByText(noUserSessions)).toBeVisible();
  const userPage = await signIn.context.newPage();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("password");
  await signIn.context.close();
});

test("the administrator's own session is listed first as this device, and ending it asks before signing out", async ({ page }) => {
  const id = await idFromListLink(page, `${env.adminUrl}/admin/users?query=${encodeURIComponent(env.adminEmail)}`, env.adminEmail);
  await page.goto(userUrl(id, "sessions"));
  const own = page.locator("#sessionsTable tbody tr").first();
  await expect(own.getByText("This device", { exact: true })).toBeVisible();
  await own.getByRole("button", { name: /^End session/ }).click();
  // Cancel: this worker's administrator stays signed in.
  await cancelDialog(page, "It's your own, on the device you're using, so you'll be signed out.");
  await page.goto(userUrl(id, "sessions"));
  await expect(page.locator("#sessionsTable tbody tr").first().getByText("This device", { exact: true })).toBeVisible();
});

test("consent given on the consent screen is listed, remembered, and revoked", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const options = { clientId: client.identifier, scope: "openid profile" };

  await page.goto(userUrl(user.id, "consents"));
  await expect(page.getByText(noConsents)).toBeVisible();

  // First sign-in: the consent screen asks.
  let attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.page.getByRole("button", { name: "Allow", exact: true }).click();
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  // Listed under the client, one scope a line.
  await page.reload();
  const row = rowWithCell(page, client.identifier);
  await expect(row.getByRole("listitem")).toHaveText(["openid", "profile"]);

  // Another browser, same scope: no consent screen, the stored consent covers it.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  // Revoking asks first, and Cancel keeps the consent.
  const revoke = row.getByRole("button", { name: `Revoke ${client.identifier}`, exact: true });
  await revoke.click();
  await cancelDialog(page, client.identifier);
  await page.reload();
  await expect(revoke).toBeVisible();

  await revoke.click();
  await confirmDialog(page, client.identifier);
  await expect(row.getByText("Revoked", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toContainText("Consent revoked.");
  await page.reload();
  await expect(page.getByText(noConsents)).toBeVisible();

  // Revoked: the consent screen asks again.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.context.close();
});
