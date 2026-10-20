// RFC 6749 section 4.1.2, the authorization code grant's answer at the redirect URI: the code and the
// state on success, an error code from 4.1.2.1 otherwise, what the user decides on the consent screen
// (3.3, 10.2), and the auth server's own defences around the decision, CSRF (10.12) and clickjacking
// (10.13). Where RFC 9700 section 4.11.2 overrides 4.1.2.1, an error is redirected only once the user
// has signed in.
import type { Browser, Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken, jwtClaims } from "../../lib/oauth";
import { authorizeEndpoint, codeRequest, emptyBrowser, expectAuthorizeError, followAuthorize, getAuthorize } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

const consentUrl = `${env.authUrl}/auth/consent`;

// A user starting a sign-in through the client in a browser of their own, signed in up to its consent
// screen. The caller closes the context.
async function signInToConsent(browser: Browser, clientId: string, user: { email: string; password: string }, scope = "openid") {
  const context = await emptyBrowser(browser);
  const userPage = await context.newPage();
  const { params, verifier } = codeRequest(clientId, { scope });
  await userPage.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
  await submitPassword(userPage, user.email, user.password);
  await expect(userPage).toHaveURL(/\/auth\/consent/);
  return { context, userPage, params, verifier };
}

// The consent screen's row for a scope, which holds its checkbox, the scope in plain words and the
// scope itself.
function consentRow(page: Page, scope: string) {
  return page.locator("label.check-row").filter({ has: page.locator(".code-hint", { hasText: new RegExp(`^${scope}$`) }) });
}

test("a granted request comes back with the code in the query and the state exactly as sent", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  // Every printable character a URL treats specially, which the state must survive untouched.
  const state = `a b+c&d=e%f#g"h\\i~j/k?l`;
  const { params, verifier } = codeRequest(client.identifier, { state });
  const { redirect } = await followAuthorize(signIn.context.request, params);
  expect(redirect, "redirected to the client").toBeDefined();
  expect(`${redirect!.origin}${redirect!.pathname}`).toBe(testRedirectUri);
  expect(redirect!.hash, "nothing in the fragment for response_type=code").toBe("");
  expect(redirect!.searchParams.get("state")).toBe(state);
  const code = redirect!.searchParams.get("code")!;
  expect(code).toMatch(/^[\x20-\x7E]+$/);
  const tokens = await codeToken(request, client.identifier, secret, code, verifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);

  // No state sent, none returned.
  const { redirect: stateless } = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { state: undefined }).params);
  expect(stateless!.searchParams.get("code")).toBeTruthy();
  expect(stateless!.searchParams.has("state")).toBe(false);
  await signIn.context.close();
});

test("the consent screen names the client and the scopes, and Don't allow answers the client access_denied", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const { context, userPage, params } = await signInToConsent(browser, client.identifier, user, "openid email");

  // Section 10.2 SHOULD: the user sees which client asks, and for what: each scope in plain words, with
  // the scope itself beneath them.
  await expect(userPage.locator(".auth-client-name")).toHaveText(client.identifier);
  await expect(consentRow(userPage, "openid")).toContainText("Identify you by an ID unique to your account");
  await expect(consentRow(userPage, "email")).toContainText("Your email address, and whether it's verified");

  await userPage.getByRole("button", { name: "Don't allow", exact: true }).click();
  await userPage.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expectAuthorizeError(new URL(userPage.url()), "access_denied", params.state);
  await context.close();
});

test("a scope the user unticks on the consent screen is left out, and the token answer names the scope granted (section 3.3)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients, { consentRequired: true });
  const { context, userPage, verifier } = await signInToConsent(browser, client.identifier, user, "openid email");

  await consentRow(userPage, "email").getByRole("checkbox").uncheck();
  await userPage.getByRole("button", { name: "Allow", exact: true }).click();
  await userPage.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const code = new URL(userPage.url()).searchParams.get("code")!;
  await context.close();

  // Section 3.3: the server MAY issue less than asked for on the resource owner's instructions, and MUST
  // then name the scope it issued.
  const tokens = await codeToken(request, client.identifier, secret, code, verifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  expect(tokens.body.scope).toBe("openid");
  expect(jwtClaims(tokens.body.id_token as string)).not.toHaveProperty("email");
});

test("Allow with every scope unticked is answered access_denied, as Don't allow is", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const { context, userPage, params } = await signInToConsent(browser, client.identifier, user, "openid email");

  const boxes = userPage.locator(".check-list").getByRole("checkbox");
  await expect(boxes).toHaveCount(2);
  for (const box of await boxes.all()) await box.uncheck();
  await userPage.getByRole("button", { name: "Allow", exact: true }).click();
  await userPage.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expectAuthorizeError(new URL(userPage.url()), "access_denied", params.state);
  await context.close();
});

test("an invalid request is answered at the redirect URI once the user signs in, and at once to a user already signed in", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  // An unknown scope carrying characters error_description may not hold, should it echo it.
  const { params } = codeRequest(client.identifier, { scope: 'openid café:"read"' });

  // RFC 9700 section 4.11.2: nobody signed in, so no redirect yet; the password page instead.
  const context = await emptyBrowser(browser);
  const userPage = await context.newPage();
  await userPage.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
  await expect(userPage).toHaveURL(/\/auth\/pwd/);
  await submitPassword(userPage, user.email, user.password);
  await userPage.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expectAuthorizeError(new URL(userPage.url()), "invalid_scope", params.state);
  await context.close();

  // A browser holding a session (the ceremony above ended without one): answered at once.
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const again = codeRequest(client.identifier, { scope: "openid unknown-resource:read" });
  const { redirect } = await followAuthorize(signIn.context.request, again.params);
  expect(redirect, "answered at the redirect URI").toBeDefined();
  expectAuthorizeError(redirect!, "invalid_scope", again.params.state);
  await signIn.context.close();
});

test("a client not allowed the authorization code flow is answered unauthorized_client at its redirect URI (section 4.1.2.1)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await page.locator('input[name="clientCredentialsEnabled"]').check();
  await page.locator('input[name="authCodeEnabled"]').uncheck();
  await page.locator("#btnSave").click();
  await expect(page.getByText("OAuth2 flows saved.")).toBeVisible();
  const context = await emptyBrowser(browser);
  const { params } = codeRequest(client.identifier);

  const userPage = await context.newPage();
  await userPage.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
  if (new URL(userPage.url()).pathname === "/auth/pwd") await submitPassword(userPage, user.email, user.password);
  await expect(userPage, "answered at the redirect URI, not on the auth server's page").toHaveURL((url) => url.href.startsWith(testRedirectUri));
  expectAuthorizeError(new URL(userPage.url()), "unauthorized_client", params.state);
  await context.close();
});

test("the consent form refuses a forged submission: cross-site, from another browser, or without its ceremony", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const { context, userPage } = await signInToConsent(browser, client.identifier, user);
  const ceremonyId = await userPage.locator('input[name="ceremonyId"]').inputValue();
  const approval = { ceremonyId, consent0: "on", btnSubmit: "submit" };
  const post = (api: typeof context.request, form: Record<string, string>, headers: Record<string, string> = {}) =>
    api.post(consentUrl, { form, headers, failOnStatusCode: false, maxRedirects: 0 });
  // Refused means no answer to the client: not a redirect to its redirect URI, code or no code.
  const expectNothingForTheClient = (response: Awaited<ReturnType<typeof post>>) =>
    expect(response.headers()["location"] ?? "", `status ${response.status()}`).not.toContain(new URL(testRedirectUri).host);

  // A page on another site posting the form in the user's browser: the browser marks it cross-site.
  const crossSite = await post(context.request, approval, { Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site" });
  expect(crossSite.status(), "cross-site submission refused").toBe(403);
  // Another browser, not holding this ceremony: sent to the account page, not to the client.
  const elsewhere = await emptyBrowser(browser);
  expectNothingForTheClient(await post(elsewhere.request, approval));
  await elsewhere.close();
  // The user's own browser, but the form not naming the ceremony it was rendered for.
  const unbound = await post(context.request, { consent0: "on", btnSubmit: "submit" });
  expect(unbound.status()).toBe(400);
  expect(await unbound.text()).toContain("This request is no longer active");
  expectNothingForTheClient(unbound);

  // None of it touched the ceremony: the user's own approval still goes through.
  await userPage.getByRole("button", { name: "Allow", exact: true }).click();
  await userPage.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expect(new URL(userPage.url()).searchParams.get("code")).toBeTruthy();
  await context.close();
});

test("the auth server's pages cannot be framed by another site (section 10.13)", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  const { page: passwordPage, pageUrl } = await followAuthorize(anonymous.request, codeRequest(client.identifier).params);
  expect(pageUrl).toMatch(/\/auth\/pwd/);
  const refusal = await getAuthorize(anonymous.request, codeRequest(client.identifier, { redirect_uri: "https://attacker.example/cb" }).params);
  for (const answer of [passwordPage!, refusal]) {
    expect(answer.headers["x-frame-options"]).toBe("DENY");
    expect(answer.headers["content-security-policy"]).toMatch(/frame-ancestors 'none'/);
  }
  await anonymous.close();
});
