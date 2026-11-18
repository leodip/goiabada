// RFC 9700 sections 4.5.3.2 and 4.6.1, the OpenID Connect defences against injection. A client may
// bind a code to its transaction with a nonce instead of PKCE: the nonce it sent must come back in the
// ID token the token endpoint issues for that code, and no other. No access token carries it, and a
// refreshed ID token has none, as OpenID Connect Core 12.2 recommends. Against an injected access token,
// an ID token issued beside it carries at_hash, its hash, and a nonce, which OpenID Connect Core 3.2.2.1
// requires of every request issuing an ID token from the authorization endpoint. The client checks;
// the server has to issue them.
import { createHash, randomBytes } from "node:crypto";
import { setImplicitGrant } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { codeToken, jwtClaims, refreshToken } from "../../lib/oauth";
import { codeRequest, expectAuthorizeError, followAuthorize, responseParams } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

test("the nonce of the authorization request is in the ID token the token endpoint issues for its code, and in no access token or refreshed ID token (section 4.5.3.2)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const tokensFor = async (nonce: string | undefined) => {
    const { params, verifier } = codeRequest(client.identifier, { nonce });
    const { redirect } = await followAuthorize(signIn.context.request, params);
    const tokens = await codeToken(request, client.identifier, secret, redirect!.searchParams.get("code")!, verifier, testRedirectUri);
    expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
    return tokens.body;
  };

  const nonce = randomBytes(16).toString("base64url");
  const signedIn = await tokensFor(nonce);
  expect(jwtClaims(signedIn.id_token as string).nonce).toBe(nonce);
  expect(jwtClaims(signedIn.access_token as string)).not.toHaveProperty("nonce");

  const refreshed = await refreshToken(request, client.identifier, secret, signedIn.refresh_token as string);
  expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
  expect(refreshed.body.id_token, "a refresh of an openid grant issues an ID token").toBeTruthy();
  expect(jwtClaims(refreshed.body.id_token as string)).not.toHaveProperty("nonce");
  expect(jwtClaims(refreshed.body.access_token as string)).not.toHaveProperty("nonce");

  // A transaction that sent none gets none: no nonce of another transaction is carried over.
  expect(jwtClaims((await tokensFor(undefined)).id_token as string).nonce).toBeUndefined();
  await signIn.context.close();
});

test("an ID token issued beside an access token carries its at_hash, and the request must bring a nonce (section 4.6.1)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const implicit = (extra: Record<string, string>) => ({
    client_id: client.identifier,
    redirect_uri: testRedirectUri,
    response_type: "id_token token",
    scope: "openid",
    state: "s",
    ...extra,
  });

  const nonce = randomBytes(16).toString("base64url");
  const { redirect } = await followAuthorize(signIn.context.request, implicit({ nonce }));
  const params = responseParams(redirect!);
  const accessToken = params.get("access_token")!;
  const claims = jwtClaims(params.get("id_token")!);
  // OpenID Connect Core 3.2.2.9: the left half of the SHA-256 of the access token, base64url.
  const digest = createHash("sha256").update(accessToken).digest();
  expect(claims.at_hash).toBe(digest.subarray(0, digest.length / 2).toString("base64url"));
  expect(claims.nonce).toBe(nonce);
  expect(jwtClaims(accessToken)).not.toHaveProperty("nonce");

  for (const responseType of ["id_token token", "id_token"]) {
    await test.step(`${responseType} with no nonce`, async () => {
      const { redirect: refused } = await followAuthorize(signIn.context.request, implicit({ response_type: responseType }));
      expectAuthorizeError(refused!, "invalid_request", "s");
    });
  }
  await signIn.context.close();
});
