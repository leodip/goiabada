// RFC 6749 section 3.1.2, the redirection endpoint. A redirect URI is matched against the client's
// registered ones by simple string comparison (3.1.2.3), and a request whose redirect URI is missing,
// invalid or not registered is answered on the auth server's own page, never by redirect (3.1.2.4).
// RFC 8252 section 7.3 is the one relaxation: any port on a loopback redirect URI.
import { addRedirectUri, clientUrl, expectErrorDialog } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken } from "../../lib/oauth";
import {
  basicAuth,
  codeRequest,
  emptyBrowser,
  expectRefusedOnPage,
  expectTokenError,
  expectTokenResponse,
  followAuthorize,
  getAuthorize,
  postToken,
} from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

test("a redirect URI is matched exactly: the registered one goes on to sign-in, every near miss is refused on the page", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  const exact = await getAuthorize(anonymous.request, codeRequest(client.identifier).params);
  expect(exact.status).toBe(302);
  expect(exact.headers["location"]).toMatch(new RegExp(`^(${env.authUrl})?/auth/level1\\?`));

  const host = new URL(testRedirectUri).host;
  for (const nearMiss of [
    `${testRedirectUri}/`,
    `https://${host}/Callback`,
    `https://${host.toUpperCase()}/callback`,
    `${testRedirectUri}?extra=1`,
    `https://${host}:443/callback`,
    `http://${host}/callback`,
    `${env.webtest2Url}/callback`,
  ]) {
    await test.step(nearMiss, async () => {
      const answer = await getAuthorize(anonymous.request, codeRequest(client.identifier, { redirect_uri: nearMiss }).params);
      expectRefusedOnPage(answer, /The client does not have this redirect URI registered/);
    });
  }
  await anonymous.close();
});

test("a redirect URI with a fragment is refused at the authorization endpoint and at registration", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  const answer = await getAuthorize(anonymous.request, codeRequest(client.identifier, { redirect_uri: `${testRedirectUri}#section` }).params);
  expectRefusedOnPage(answer, /a fragment is not permitted/);
  await anonymous.close();

  await page.goto(clientUrl(client.id, "redirect-uris"));
  await page.locator("#redirectURI").fill(`${testRedirectUri}-other#section`);
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#btnSave").click();
  await expectErrorDialog(page, /a fragment is not permitted/);
  await page.reload();
  await expect(page.locator("#redirectURIsTable")).not.toContainText("#section");
});

test("a client with no redirect URI registered, or with two and none named, is refused on the page", async ({
  page,
  browser,
  clients,
}) => {
  const anonymous = await emptyBrowser(browser);

  const none = await clients.create();
  expectRefusedOnPage(
    await getAuthorize(anonymous.request, codeRequest(none.identifier).params),
    /The client does not have this redirect URI registered/,
  );

  // Section 3.1.2.3: with several registered, the client MUST say which.
  const { client: two } = await browserSignInClient(page, clients);
  await addRedirectUri(page, two.id, `${env.webtest2Url}/callback`);
  expectRefusedOnPage(
    await getAuthorize(anonymous.request, codeRequest(two.identifier, { redirect_uri: undefined }).params),
    /The redirect_uri parameter is missing/,
  );
  await anonymous.close();
});

test("with no redirect_uri, a client with one registered URI is answered at that URI (section 4.1.1: OPTIONAL)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  // A documented deviation: redirect_uri is required on every request (the authorize reference
  // lists it as required). Remove this line if that changes.
  test.fail();
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { params, verifier } = codeRequest(client.identifier, { redirect_uri: undefined });
  const outcome = await followAuthorize(signIn.context.request, params);
  expect(outcome.page?.text.slice(0, 300), "answered at the registered redirect URI").toBeUndefined();
  expect(`${outcome.redirect!.origin}${outcome.redirect!.pathname}`).toBe(testRedirectUri);
  const code = outcome.redirect!.searchParams.get("code")!;

  // Section 4.1.3: redirect_uri is required at the token endpoint only if the request carried one.
  expectTokenResponse(
    await postToken(
      request,
      { grant_type: "authorization_code", code, code_verifier: verifier },
      { headers: { Authorization: basicAuth(client.identifier, secret) } },
    ),
  );
  await signIn.context.close();
});

test("a registered redirect URI's query is kept, and the code and state are added to it", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const withQuery = `${testRedirectUri}?tenant=a`;
  await addRedirectUri(page, client.id, withQuery);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { params, verifier } = codeRequest(client.identifier, { redirect_uri: withQuery });
  const { redirect } = await followAuthorize(signIn.context.request, params);
  expect(redirect, "redirected to the client").toBeDefined();
  expect(`${redirect!.origin}${redirect!.pathname}`).toBe(testRedirectUri);
  expect(redirect!.searchParams.get("tenant")).toBe("a");
  expect(redirect!.searchParams.get("state")).toBe(params.state);
  const code = redirect!.searchParams.get("code")!;
  expect(code).toBeTruthy();

  const tokens = await codeToken(request, client.identifier, secret, code, verifier, withQuery);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  await signIn.context.close();
});

test("a loopback redirect URI takes any port, and the token request must name the same one (RFC 8252 section 7.3)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await addRedirectUri(page, client.id, "http://127.0.0.1/callback");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const loopback = "http://127.0.0.1:53682/callback";

  const first = codeRequest(client.identifier, { redirect_uri: loopback });
  const { redirect: one } = await followAuthorize(signIn.context.request, first.params);
  expect(one?.href.startsWith(`${loopback}?`), one?.href).toBe(true);
  const redeemed = await codeToken(request, client.identifier, secret, one!.searchParams.get("code")!, first.verifier, loopback);
  expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);

  const second = codeRequest(client.identifier, { redirect_uri: loopback });
  const { redirect: two } = await followAuthorize(signIn.context.request, second.params);
  const otherPort = await postToken(
    request,
    {
      grant_type: "authorization_code",
      code: two!.searchParams.get("code")!,
      code_verifier: second.verifier,
      redirect_uri: "http://127.0.0.1:53683/callback",
    },
    { headers: { Authorization: basicAuth(client.identifier, secret) } },
  );
  expectTokenError(otherPort, "invalid_grant");
  await signIn.context.close();
});

test("before sending a code over a registered redirect URI without TLS, the user is warned (section 3.1.2.1 SHOULD)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  // No warning today. #575 refuses such a URI when it is saved, after which this test can no
  // longer register one: delete it then.
  test.fail();
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const plainHttp = `http://${new URL(testRedirectUri).host}/callback`;
  await addRedirectUri(page, client.id, plainHttp);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { redirect, page: warning } = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { redirect_uri: plainHttp }).params);
  expect(redirect?.href, "the code was sent without a warning").toBeUndefined();
  expect(warning?.status).toBe(200);
  await signIn.context.close();
});
