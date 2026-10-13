// RFC 9700 sections 2.1.1, 4.5.3.1, 4.7.1 and 4.8, PKCE. The auth server must support it and say so,
// must hold a code issued for a challenge to its verifier, which is what defeats an injected code, and
// must refuse a verifier for a code issued with no challenge, the downgrade of 4.8. S256 is the only
// method that keeps the verifier out of the authorization request. A public client must always use
// PKCE, which ./open-redirection.spec.ts sees refused at the redirect URI.
import type { APIRequestContext } from "@playwright/test";
import { setPkceRequired } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, codeRequest, expectAuthorizeError, expectTokenError, expectTokenResponse, followAuthorize, postToken } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

// Redeems code as the client with client_secret_basic, with the verifier when there is one.
function redeemer(request: APIRequestContext, clientId: string, secret: string) {
  return (code: string, verifier?: string) =>
    postToken(
      request,
      { grant_type: "authorization_code", code, redirect_uri: testRedirectUri, ...(verifier === undefined ? {} : { code_verifier: verifier }) },
      { headers: { Authorization: basicAuth(clientId, secret) } },
    );
}

test("the discovery document says PKCE is supported, with S256 alone (sections 2.1.1, 4.7.1)", async ({ request }) => {
  const metadata = await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json();
  expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
});

test("a code issued for a challenge redeems only with its verifier: none, or another transaction's, is refused (sections 2.1.1, 4.5.3.1)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const redeem = redeemer(request, client.identifier, secret);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  // Another transaction of the same client: an attacker injecting the first code holds this verifier.
  const other = codeRequest(client.identifier);
  const { redirect } = await followAuthorize(signIn.context.request, other.params);
  const otherCode = redirect!.searchParams.get("code")!;
  await signIn.context.close();

  expectTokenError(await redeem(signIn.code), "invalid_request");
  expectTokenError(await redeem(signIn.code, other.verifier), "invalid_grant");
  expectTokenResponse(await redeem(signIn.code, signIn.codeVerifier));
  expectTokenResponse(await redeem(otherCode, other.verifier));
});

test("a challenge with the plain method, or with no method, which means plain, is refused (section 2.1.1)", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { params: plain, verifier } = codeRequest(client.identifier, { code_challenge_method: "plain" });
  plain.code_challenge = verifier;
  const { params: noMethod } = codeRequest(client.identifier, { code_challenge_method: undefined });
  for (const [what, params] of [
    ["plain", plain],
    ["no method", noMethod],
  ] as const) {
    await test.step(what, async () => {
      const { redirect } = await followAuthorize(signIn.context.request, params);
      expect(redirect, "answered at the redirect URI").toBeDefined();
      expectAuthorizeError(redirect!, "invalid_request", params.state);
    });
  }
  await signIn.context.close();
});

test("a code issued with no challenge is refused when the token request brings a verifier: no PKCE downgrade (section 4.8.2 MUST)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await setPkceRequired(page, client.id, "off");
  const redeem = redeemer(request, client.identifier, secret);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const codeWithoutChallenge = async () => {
    const { redirect } = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { code_challenge: undefined, code_challenge_method: undefined }).params);
    return redirect!.searchParams.get("code")!;
  };
  const downgraded = await codeWithoutChallenge();
  const plainCode = await codeWithoutChallenge();
  await signIn.context.close();

  expectTokenError(await redeem(downgraded, codeRequest(client.identifier).verifier), "invalid_request");
  // With PKCE off for this client, a code with no challenge redeems with no verifier.
  expectTokenResponse(await redeem(plainCode));
});

test("a confidential client required to use PKCE is answered invalid_request without a challenge, as seeded and when set on (section 4.8.2)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  for (const setting of ["global", "on"] as const) {
    await test.step(setting, async () => {
      await setPkceRequired(page, client.id, setting);
      const { params } = codeRequest(client.identifier, { code_challenge: undefined, code_challenge_method: undefined });
      const { redirect } = await followAuthorize(signIn.context.request, params);
      expect(redirect, "answered at the redirect URI").toBeDefined();
      expectAuthorizeError(redirect!, "invalid_request", params.state);
    });
  }
  await signIn.context.close();
});
