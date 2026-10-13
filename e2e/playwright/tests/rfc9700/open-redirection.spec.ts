// RFC 9700 section 4.11, open redirection. The auth server must authenticate the user before it sends
// the browser to a client, even with an error: with no session, an erroneous request waits for the
// password, so a client registered only to receive errors cannot bounce visitors to itself (4.11.2).
// prompt=none is the one exception. Logout is the other place the server redirects, and the admin
// console, itself a client, must not be an open redirector either (4.11.1). An unknown client or an
// unregistered redirect URI, refused on the page, is in ../rfc6749/redirect-uri.spec.ts; a cancelled
// consent answered access_denied in ../rfc6749/authorization-response.spec.ts.
import type { BrowserContext } from "@playwright/test";
import { addRedirectUri, setImplicitGrant } from "../../lib/admin-console";
import { authorizeAndLand, type BrowserSignIn, signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken } from "../../lib/oauth";
import { codeRequest, emptyBrowser, expectAuthorizeError, followAuthorize, getAuthorize } from "../../lib/rfc6749";
import { browserSignInClient, publicSignInClient } from "../../lib/test-clients";

const elsewhere = "https://evil.example/landing";

// Answers every request to evil.example in this browser, so a redirect there is seen rather than
// failing on a name that does not resolve.
async function catchElsewhere(context: BrowserContext) {
  await context.route("https://evil.example/**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<h1>elsewhere</h1>" }));
}

test("with no session, an erroneous request reaches the client only after the password (section 4.11.2)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client: confidential } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, confidential.id, "off");
  const publicClient = await publicSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  for (const [what, params, error] of [
    ["an unknown response_type", codeRequest(confidential.identifier, { response_type: "foo" }).params, "unsupported_response_type"],
    ["a public client with no code_challenge", codeRequest(publicClient.identifier, { code_challenge: undefined, code_challenge_method: undefined }).params, "invalid_request"],
    [
      "the implicit grant, which the client may not use",
      codeRequest(confidential.identifier, { response_type: "token", code_challenge: undefined, code_challenge_method: undefined }).params,
      "unauthorized_client",
    ],
  ] as const) {
    await test.step(what, async () => {
      const first = await followAuthorize(anonymous.request, params);
      expect(first.redirect?.href, "nothing reaches the client before the password").toBeUndefined();
      expect(new URL(first.pageUrl!).pathname).toBe("/auth/pwd");

      expectAuthorizeError(await authorizeAndLand(browser, params, user), error, params.state);
    });
  }
  await anonymous.close();
});

test("prompt=none is the exception: with no session it is answered login_required at once (section 4.11.2)", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  const { params } = codeRequest(client.identifier, { prompt: "none" });
  const answer = await getAuthorize(anonymous.request, params);
  expect(answer.status).toBe(302);
  const location = new URL(answer.headers["location"]);
  expect(location.href.startsWith(`${testRedirectUri}?`), location.href).toBe(true);
  expectAuthorizeError(location, "login_required", params.state);
  await anonymous.close();
});

test("logout redirects only to a URI registered for the client it names; any other leaves the user on the auth server (section 2.1)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const { client: other } = await browserSignInClient(page, clients);
  const othersUri = `${env.webtest2Url}/callback`;
  await addRedirectUri(page, other.id, othersUri);

  // Signs the user in afresh, signs them out with query, confirming when asked, and returns where the
  // browser ended up and whether it shows the auth server's "Signed out" page.
  type LogoutQuery = (signIn: BrowserSignIn) => Promise<Record<string, string>>;
  const signOut = async (query: LogoutQuery) => {
    const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
    await catchElsewhere(signIn.context);
    const tab = await signIn.context.newPage();
    await tab.goto(`${env.authUrl}/auth/logout?${new URLSearchParams(await query(signIn))}`);
    const yes = tab.getByRole("button", { name: "Yes" });
    if (await yes.isVisible()) {
      await yes.click();
      await tab.waitForLoadState();
    }
    const landed = new URL(tab.url());
    const signedOutPage = await tab.getByRole("heading", { name: "Signed out" }).isVisible();
    await signIn.context.close();
    return { landed, signedOutPage };
  };
  const idToken = async (signIn: BrowserSignIn) =>
    (await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri)).body.id_token as string;

  const refused: [string, LogoutQuery][] = [
    ["a URI nobody registered, beside client_id", async () => ({ client_id: client.identifier, post_logout_redirect_uri: elsewhere, state: "s" })],
    ["another client's URI, beside client_id", async () => ({ client_id: client.identifier, post_logout_redirect_uri: othersUri, state: "s" })],
    ["a URI nobody registered, beside the ID token", async (signIn) => ({ id_token_hint: await idToken(signIn), post_logout_redirect_uri: elsewhere, state: "s" })],
  ];
  for (const [what, query] of refused) {
    await test.step(what, async () => {
      const { landed, signedOutPage } = await signOut(query);
      expect(landed.origin).toBe(env.authUrl);
      expect(signedOutPage, "the auth server's own Signed out page").toBe(true);
    });
  }

  const { landed } = await signOut(async () => ({ client_id: client.identifier, post_logout_redirect_uri: testRedirectUri, state: "s" }));
  expect(landed.href.startsWith(testRedirectUri), landed.href).toBe(true);
  expect(landed.searchParams.get("state")).toBe("s");
});

test("the admin console, a client itself, returns a user only to its own pages after sign-in (section 4.11.1)", async ({ browser, users }) => {
  const user = await users.create();
  const context = await emptyBrowser(browser);
  await catchElsewhere(context);
  const tab = await context.newPage();

  await tab.goto(`${env.adminUrl}/account//evil.example?next=${encodeURIComponent(elsewhere)}`);
  await expect(tab).toHaveURL(/\/auth\/pwd/);
  await submitPassword(tab, user.email, user.password);
  await tab.waitForURL((url) => url.origin !== env.authUrl && url.pathname !== "/auth/callback");
  // The path asked for, on the console's own origin.
  const landed = new URL(tab.url());
  expect(landed.origin).toBe(env.adminUrl);
  expect(landed.pathname).toBe("/account//evil.example");
  await context.close();
});
