// Sign users out, through the test app's web app: RP-initiated logout with and without the ID token,
// and the difference between ending the app's session and ending the auth server's. The app revokes
// its refresh token at /auth/revoke before it signs out, and answers "Sign-out failed" when the
// revocation is refused, so each "Signed out" below is a revocation that succeeded too (RFC 7009).
// The last test signs in through two clients of its own instead, to show what the sign-out itself
// revokes when no revocation comes before it.
import { createHash, randomBytes } from "node:crypto";
import type { BrowserContext } from "@playwright/test";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken, jwtClaims, refreshToken, userinfo } from "../../lib/oauth";
import { browserSignInClient } from "../../lib/test-clients";
import { expectResult, resultBody, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

test("signing out with the ID token returns to the app with its state, and the next sign-in asks for the password", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed out");
  const body = await resultBody(app);
  expect(body.state).toBe("matches the one sent");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  await context.close();
});

test("signing out with no ID token asks first, then ends the session", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  await expect(app.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  expect(new URL(app.url()).origin).toBe(env.authUrl);
  await expect(app).toHaveTitle(/^Sign out – /);
  await expect(app.getByText("Do you want to sign out?")).toBeVisible();
  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed out");
  expect((await resultBody(app)).state).toBe("matches the one sent");

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});

// Declining on the confirmation page (#152). Stay signed in is a link to the "still signed in" page,
// which the page's script turns into a step back when there is somewhere to go back to. Each case
// checks the session survived by signing in again without being asked for the password.
test("declining the sign-out goes back to the app, and the session survives", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  await expect(app.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await app.getByRole("link", { name: "Stay signed in", exact: true }).click();
  await app.waitForURL(testapp.web.url);

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  await context.close();
});

test("declining the sign-out with nowhere to go back to says the user is still signed in, in their language", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  // The app opens sign-out in a new tab, whose first entry is the confirmation page. A page opened with
  // context.newPage() would not do: it starts on about:blank, which leaves a step back.
  const [tab] = await Promise.all([
    context.waitForEvent("page"),
    app.evaluate((url) => { window.open(url); }, `${env.authUrl}/auth/logout?ui_locales=pt-BR`),
  ]);
  await tab.waitForLoadState();
  expect(await tab.evaluate(() => history.length)).toBe(1);
  await tab.getByRole("link", { name: "Continuar conectado", exact: true }).click();
  await tab.waitForURL((url) => url.pathname === "/auth/logout/declined");
  expect(new URL(tab.url()).searchParams.get("ui_locales")).toBe("pt-BR");
  await expect(tab.getByRole("heading", { name: "Sessão mantida" })).toBeVisible();
  await expect(tab.getByText("Você continua conectado. Pode fechar esta página.")).toBeVisible();
  await tab.close();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  await context.close();
});

test("declining the sign-out without JavaScript says the user is still signed in, and the session survives", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  // The same browser's cookies, in a context that runs no script, so the link is followed as it is.
  const noScript = await browser.newContext({ storageState: await context.storageState(), javaScriptEnabled: false });
  const page = await noScript.newPage();
  await page.goto(`${env.authUrl}/auth/logout`);
  await page.getByRole("link", { name: "Stay signed in", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/auth/logout/declined");
  await expect(page.getByRole("heading", { name: "Still signed in" })).toBeVisible();
  await expect(page.getByText("You're still signed in. You can close this page.")).toBeVisible();
  await noScript.close();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  await context.close();
});

test("forgetting only the app's session leaves the auth server's: signing in again asks for nothing", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Forget this app's session only" }).click();
  await expectResult(app, "Forgot this app's session");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");
  await context.close();
});

// Logout, "Where the user lands": with no hint, the post-logout redirect URI is honoured only beside the
// client_id it is registered on. Without one the sign-out still happens.
test("signing out with no ID token and no client_id signs out, but leaves the user on the auth server's page", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.goto(`${env.authUrl}/auth/logout?${new URLSearchParams({ post_logout_redirect_uri: `${testapp.web.url}/signed-out`, state: "s" })}`);
  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(app.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await expect(app.getByText("You're signed out. Any application that signs you in here will ask you to sign in again.")).toBeVisible();
  await expect(app.getByText("We couldn't take you back to the application you signed out from.")).toBeVisible();
  expect(new URL(app.url()).origin).toBe(env.authUrl);

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});

// Logout, "Where the user lands": a sign-out returns only to a sign-out redirect URI. The app's callback
// is one of its redirect URIs and not one of its sign-out redirect URIs, so even beside the client_id it
// is registered on, the user is signed out and stays on the auth server's page.
test("signing out to a redirect URI that isn't a sign-out redirect URI signs out, but leaves the user on the auth server's page", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.goto(`${env.authUrl}/auth/logout?${new URLSearchParams({
    post_logout_redirect_uri: `${testapp.web.url}/callback`,
    client_id: testapp.web.clientId,
    state: "s",
  })}`);
  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(app.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await expect(app.getByText("We couldn't take you back to the application you signed out from.")).toBeVisible();
  expect(new URL(app.url()).origin).toBe(env.authUrl);

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});

// Signs in through the client on the browser's session, which asks for nothing, and returns the code
// and its verifier.
async function codeOnTheSession(context: BrowserContext, clientId: string) {
  const page = await context.newPage();
  const codeVerifier = randomBytes(32).toString("base64url");
  await page.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({
    client_id: clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: "openid",
    state: randomBytes(8).toString("hex"),
    code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
    code_challenge_method: "S256",
  })}`);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const code = new URL(page.url()).searchParams.get("code");
  if (!code) throw new Error(`no code in ${page.url()}`);
  await page.close();
  return { code, codeVerifier };
}

// Ending sessions, "Signing out": a sign-out with the ID token revokes the departing app's refresh
// token tied to the session, even while another app keeps the session. The app keeps its refresh
// token and doesn't revoke it at /auth/revoke first, unlike the test app's own Sign out button, so
// only the sign-out can have ended it. The other app's token on the same session still refreshes.
test("signing out with the ID token revokes the app's refresh token from the session, and leaves another app's working", async ({ page, browser, request, clients, users }) => {
  const user = await users.create();
  const departing = await browserSignInClient(page, clients);
  const staying = await browserSignInClient(page, clients);

  const signIn = await signInThroughClient(browser, {
    clientId: departing.client.identifier, email: user.email, password: user.password, scope: "openid",
  });
  const departingTokens = await codeToken(request, departing.client.identifier, departing.secret, signIn.code,
    signIn.codeVerifier, testRedirectUri);
  expect(departingTokens.status, JSON.stringify(departingTokens.body)).toBe(200);
  const kept = departingTokens.body.refresh_token as string;
  expect(jwtClaims(kept).typ).toBe("Refresh");

  const second = await codeOnTheSession(signIn.context, staying.client.identifier);
  const stayingTokens = await codeToken(request, staying.client.identifier, staying.secret, second.code,
    second.codeVerifier, testRedirectUri);
  expect(stayingTokens.status, JSON.stringify(stayingTokens.body)).toBe(200);
  expect(jwtClaims(stayingTokens.body.access_token as string).sid).toBe(jwtClaims(departingTokens.body.id_token as string).sid);

  const signOut = await signIn.context.newPage();
  await signOut.goto(`${env.authUrl}/auth/logout?${new URLSearchParams({ id_token_hint: departingTokens.body.id_token as string })}`);
  await expect(signOut.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await signIn.context.close();

  const refused = await refreshToken(request, departing.client.identifier, departing.secret, kept);
  expect(refused.status).toBe(400);
  expect(refused.body).toMatchObject({ error: "invalid_grant", error_description: "This refresh token has been revoked." });
  expect((await userinfo(request, departingTokens.body.access_token as string)).status).toBe(401);

  const refreshed = await refreshToken(request, staying.client.identifier, staying.secret,
    stayingTokens.body.refresh_token as string);
  expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
});
