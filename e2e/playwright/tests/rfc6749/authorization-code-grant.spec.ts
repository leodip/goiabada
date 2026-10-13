// RFC 6749 section 4.1.3, redeeming an authorization code at the token endpoint: the code is short
// lived and single use (4.1.2, 10.5), bound to the client it was issued to and to the redirect URI it
// was issued for (4.1.3, 10.6), and the client authenticates when it can (3.2.1).
import type { BrowserContext } from "@playwright/test";
import { addRedirectUri, grantUserPermission } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { userinfo } from "../../lib/oauth";
import {
  basicAuth,
  codeRequest,
  expectInvalidClient,
  expectTokenError,
  expectTokenResponse,
  followAuthorize,
  postToken,
} from "../../lib/rfc6749";
import { browserSignInClient, publicSignInClient } from "../../lib/test-clients";

// Another code for clientId through a browser already signed in: the authorization request rides the
// session, so it needs no password.
async function anotherCode(context: BrowserContext, clientId: string, overrides: Record<string, string | undefined> = {}) {
  const { params, verifier } = codeRequest(clientId, overrides);
  const { redirect, page } = await followAuthorize(context.request, params);
  const code = redirect?.searchParams.get("code");
  if (!code) throw new Error(`no code: ${redirect?.href ?? page?.text.slice(0, 200)}`);
  return { code, verifier, redirectUri: params.redirect_uri };
}

// The redemption form for a code, the redirect URI it was issued for named unless overridden.
function redemption(code: { code: string; verifier: string; redirectUri: string }, overrides: Record<string, string | undefined> = {}) {
  const form: Record<string, string | undefined> = {
    grant_type: "authorization_code",
    code: code.code,
    code_verifier: code.verifier,
    redirect_uri: code.redirectUri,
    ...overrides,
  };
  return Object.fromEntries(Object.entries(form).filter((pair): pair is [string, string] => pair[1] !== undefined));
}

test("a code redeems once, by client_secret_basic or client_secret_post; a second time it is invalid_grant", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const first = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  expectTokenResponse(await postToken(request, redemption(first), basic));
  const second = await anotherCode(signIn.context, client.identifier);
  expectTokenResponse(await postToken(request, { ...redemption(second), client_id: client.identifier, client_secret: secret }));
  await signIn.context.close();

  // Last, because a replay also ends the session the code came from (the next test).
  expectTokenError(await postToken(request, redemption(first), basic), "invalid_grant");
});

test("a code redeemed a second time revokes what its first redemption issued (section 4.1.2 SHOULD)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  await signIn.context.close();
  const code = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const issued = await postToken(request, redemption(code), basic);
  expectTokenResponse(issued);
  const accessToken = issued.body.access_token as string;
  expect((await userinfo(request, accessToken)).status).toBe(200);

  // An attacker replaying the intercepted code with the client's credentials.
  expectTokenError(await postToken(request, redemption(code), basic), "invalid_grant");

  expectTokenError(
    await postToken(request, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token as string }, basic),
    "invalid_grant",
  );
  expect((await userinfo(request, accessToken)).status, "the access token from the first redemption").toBe(401);
});

test("a code is refused when missing, unknown, redeemed by another client, or without client authentication", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const other = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const code = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  expectTokenError(await postToken(request, redemption(code, { code: undefined }), basic), "invalid_request");
  expectTokenError(await postToken(request, redemption(code, { code: "not-a-code-this-server-issued" }), basic), "invalid_grant");
  // Section 4.1.3 MUST: the code was issued to the authenticated client, or it is refused.
  expectTokenError(
    await postToken(request, redemption(code), { headers: { Authorization: basicAuth(other.client.identifier, other.secret) } }),
    "invalid_grant",
  );
  // Section 3.2.1: a confidential client authenticates; naming itself is not enough.
  expectInvalidClient(await postToken(request, { ...redemption(code), client_id: client.identifier }), { viaBasic: false });

  // The rightful client, authenticated, still redeems it.
  expectTokenResponse(await postToken(request, redemption(code), basic));
  await signIn.context.close();
});

test("the token request must name the redirect URI the code was issued for", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const otherRegistered = `${env.webtest2Url}/callback`;
  await addRedirectUri(page, client.id, otherRegistered);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  // Sections 4.1.3 and 10.6: identical to the authorization request's, even when another of the
  // client's registered URIs is named.
  const one = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };
  expectTokenError(await postToken(request, redemption(one, { redirect_uri: otherRegistered }), basic), "invalid_grant");
  const two = await anotherCode(signIn.context, client.identifier);
  expectTokenError(await postToken(request, redemption(two, { redirect_uri: undefined }), basic), ["invalid_request", "invalid_grant"]);

  const three = await anotherCode(signIn.context, client.identifier, { redirect_uri: otherRegistered });
  expectTokenResponse(await postToken(request, redemption(three), basic));
  await signIn.context.close();
});

test("a public client redeems with its client_id alone; without one, or with another public client's, it is refused", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  const other = await publicSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const code = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };

  // Section 3.2.1: an unauthenticated client MUST send its client_id with the code.
  expectTokenError(await postToken(request, redemption(code)), ["invalid_request", "invalid_client"]);
  // Section 4.1.3: for a public client, the code was issued to the client_id in the request.
  expectTokenError(await postToken(request, { ...redemption(code), client_id: other.identifier }), "invalid_grant");
  expectTokenResponse(await postToken(request, { ...redemption(code), client_id: client.identifier }));
  await signIn.context.close();
});

test("when the user is granted less than the client asked for, the token answer names the scope granted (section 3.3)", async ({
  page,
  browser,
  clients,
  resources,
  users,
  request,
}) => {
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read", "write"] });
  await grantUserPermission(page, user.id, resource.identifier, "read");
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const asked = `openid ${resource.identifier}:read ${resource.identifier}:write`;
  const narrowed = await postToken(request, redemption(await anotherCode(signIn.context, client.identifier, { scope: asked })), basic);
  expectTokenResponse(narrowed);
  expect(String(narrowed.body.scope).split(" ").sort()).toEqual(["openid", `${resource.identifier}:read`].sort());
  await signIn.context.close();
});

test("two redemptions racing for one code: exactly one gets tokens", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  await signIn.context.close();
  const code = { code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri };
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const answers = await Promise.all([postToken(request, redemption(code), basic), postToken(request, redemption(code), basic)]);
  expect(answers.map((a) => a.status).sort()).toEqual([200, 400]);
  expectTokenError(answers.find((a) => a.status === 400)!, "invalid_grant");
});

test("a code past its lifetime is invalid_grant (section 4.1.2: short lived, at most 10 minutes recommended)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  // The auth server's codes live 60 seconds.
  test.setTimeout(150_000);
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  await signIn.context.close();

  await page.waitForTimeout(65_000);
  const late = await postToken(
    request,
    redemption({ code: signIn.code, verifier: signIn.codeVerifier, redirectUri: testRedirectUri }),
    { headers: { Authorization: basicAuth(client.identifier, secret) } },
  );
  expectTokenError(late, "invalid_grant");
});
