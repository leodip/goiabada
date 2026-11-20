// What only a browser sign-in leaves behind: a session, and the clients the user is connected to,
// with the consent given on the consent screen or without one.
import type { Page } from "@playwright/test";
import { cancelDialog, clientUrl, confirmDialog, idFromListLink, rowWithCell, userUrl } from "../../../lib/admin-console";
import { openSignIn, signInThroughClient, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { codeToken, jwtClaims, refreshToken } from "../../../lib/oauth";
import { browserSignInClient } from "../../../lib/test-clients";

const noUserSessions = "This user isn't signed in anywhere.";
const noConnectedClients = "This user isn't connected to any client.";

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

// A client that asked for consent is listed on the user's Connected clients tab with what the user
// consented to, and disconnecting it withdraws the consent with everything else (#135 decisions 1
// and 7): the consent screen asks again.
test("consent given on the consent screen is listed, remembered, and ends with a disconnect", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const options = { clientId: client.identifier, scope: "openid profile" };

  await page.goto(userUrl(user.id, "connected-clients"));
  await expect(page.getByText(noConnectedClients)).toBeVisible();

  // First sign-in: the consent screen asks.
  let attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.page.getByRole("button", { name: "Allow", exact: true }).click();
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  // Listed under the client, what the user consented to one scope a line. Its code was never
  // redeemed, so it holds no grant, and the consent is all the row shows.
  await page.reload();
  const row = rowWithCell(page, client.identifier);
  await expect(row.getByRole("list", { name: "Consented to" }).getByRole("listitem")).toHaveText(["openid", "profile"]);
  await expect(row.getByRole("list", { name: "Holds now" })).toHaveCount(0);
  await expect(row).not.toContainText("Not asked");

  // Another browser, same scope: no consent screen, the stored consent covers it.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await attempt.page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await attempt.context.close();

  // Disconnecting asks first, and Cancel keeps the consent.
  const disconnect = row.getByRole("button", { name: `Disconnect ${client.identifier}`, exact: true });
  const question = `Disconnect ${client.identifier}? Any consent the user gave it will be deleted and the access it holds for the user ` +
    "revoked on every device, offline refresh tokens included, though some access tokens already issued can keep " +
    "working until they expire. The auth server will try to tell it to sign the user out. " +
    "It can still ask the user to sign in again.";
  await disconnect.click();
  await cancelDialog(page, question);
  await page.reload();
  await expect(disconnect).toBeVisible();

  await disconnect.click();
  await confirmDialog(page, question);
  await expect(row.getByText("Disconnected", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toContainText("Client disconnected.");
  await page.reload();
  await expect(page.getByText(noConnectedClients)).toBeVisible();

  // Disconnected: the consent screen asks again.
  attempt = await openSignIn(browser, options);
  await submitPassword(attempt.page, user.email, user.password);
  await expect(attempt.page).toHaveURL(/\/auth\/consent/);
  await attempt.context.close();
});

// A client with Consent required off never asks, and still holds a grant: it is listed with what
// its grant holds and as never asked, and a disconnect refuses its refresh token at once while the
// user's session goes on signing them in, since a disconnect is not a ban (#135 decisions 1, 3, 4
// and 7).
test("a client that never asked for consent is listed with what it holds, and disconnected", async ({
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
    scope: "openid profile",
  });
  const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);

  await page.goto(userUrl(user.id, "connected-clients"));
  const row = rowWithCell(page, client.identifier);
  await expect(row.getByRole("list", { name: "Holds now" }).getByRole("listitem")).toHaveText(["openid", "profile"]);
  await expect(row.getByRole("list", { name: "Consented to" })).toHaveCount(0);
  await expect(row).toContainText("Not asked");

  await row.getByRole("button", { name: `Disconnect ${client.identifier}`, exact: true }).click();
  await confirmDialog(page, `Disconnect ${client.identifier}?`);
  await expect(row.getByText("Disconnected", { exact: true })).toBeVisible();

  const refused = await refreshToken(request, client.identifier, secret, tokens.body.refresh_token as string);
  expect(refused.status, JSON.stringify(refused.body)).toBe(400);
  expect(refused.body.error).toBe("invalid_grant");
  await page.reload();
  await expect(page.getByText(noConnectedClients)).toBeVisible();

  // The user's session stays: the same browser is signed straight back in to the client.
  const userPage = await signIn.context.newPage();
  expect(await signInAgainLandsOn(userPage, client.identifier)).toBe("client");
  await signIn.context.close();
});

// The console's own client, on the administrator's own user, is tagged rather than offered a
// Disconnect: disconnecting it from inside it would only send them through sign-in again (#135
// decision 5).
test("the administrator's own user lists the console as this client, with nothing to press", async ({ page }) => {
  const id = await idFromListLink(page, `${env.adminUrl}/admin/users?query=${encodeURIComponent(env.adminEmail)}`, env.adminEmail);
  await page.goto(userUrl(id, "connected-clients"));
  const own = rowWithCell(page, "admin-console-client");
  await expect(own.getByText("This client", { exact: true })).toBeVisible();
  await expect(own.getByRole("button")).toHaveCount(0);
});
