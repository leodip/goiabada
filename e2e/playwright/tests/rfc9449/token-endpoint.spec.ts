// RFC 9449 at the token endpoint, through the real proxy: a proof on any of the four grants binds
// the access token to its key (section 5), answered token_type DPoP with cnf.jkt (section 6.1); the
// server's nonce is asked for with use_dpop_nonce, and every answer to a DPoP request carries a fresh
// one (section 8); and htu names the public URL the client reached, so a proof naming the auth
// server's internal URL, the hop behind the proxy, is refused (section 4.3). The full validation
// matrix is in the Go tiers. A proof is single-use (section 11.1): sent again, it is refused. A
// public client's refresh token is bound to the key too, and refused without a proof by it, where a
// confidential client's is left unbound (section 5). A client set to require DPoP is refused every
// token request without a proof, once it has authenticated, and answered with one (section 5.2).
import type { Page } from "@playwright/test";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { dpopKey, dpopProof, expectBoundTokenResponse, expectUseDPoPNonce, nonceOf, postTokenWithDPoP, setRequireDPoP } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test, type TestClient, type TestResource } from "../../lib/fixtures";
import { basicAuth, expectInvalidClient, expectTokenError, expectTokenResponse, postToken, tokenEndpoint } from "../../lib/rfc6749";
import { browserSignInClient, passwordGrantClient, publicSignInClient } from "../../lib/test-clients";

// A client of the client credentials grant holding a permission of a resource of its own: its Basic
// header and the request for that scope.
async function clientCredentialsClient(
  page: Page,
  clients: { create(options: { authorizationCode: boolean; clientCredentials: boolean }): Promise<TestClient> },
  resources: { create(options: { permissions: string[] }): Promise<TestResource> },
) {
  const resource = await resources.create({ permissions: ["read"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  return {
    client,
    basic: { Authorization: basicAuth(client.identifier, await readClientSecret(page, client.id)) },
    body: { grant_type: "client_credentials", scope: `${resource.identifier}:read` },
  };
}

test("a proof without a nonce is answered use_dpop_nonce, and the retry with it is a bound token (section 8)", async ({ page, clients, resources, request }) => {
  const { basic, body } = await clientCredentialsClient(page, clients, resources);
  const key = dpopKey();

  const asked = await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key) } });
  expectUseDPoPNonce(asked);
  expect(asked.body.error_description).toBe("Authorization server requires nonce in DPoP proof.");

  const answered = await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { nonce: nonceOf(asked) }) } });
  expectBoundTokenResponse(answered, key);

  await test.step("the nonce the success carried is good for the next request", async () => {
    const next = await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { nonce: nonceOf(answered) }) } });
    expectBoundTokenResponse(next, key);
  });
  await test.step("a nonce the server never handed out is answered use_dpop_nonce", async () => {
    expectUseDPoPNonce(await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { nonce: "not-a-nonce" }) } }));
  });
  await test.step("without a DPoP header the token is a bearer token, with no nonce", async () => {
    const bearer = await postToken(request, body, { headers: basic });
    expectTokenResponse(bearer);
    expect(bearer.headers["dpop-nonce"]).toBeUndefined();
  });
});

test("the client credentials and password grants bind the access token to the proof's key (section 5)", async ({
  page,
  clients,
  resources,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const key = dpopKey();
  expectBoundTokenResponse(
    await postTokenWithDPoP(request, { grant_type: "password", username: user.email, password: user.password, scope: "openid" }, key, basic),
    key,
  );

  const service = await clientCredentialsClient(page, clients, resources);
  const serviceKey = dpopKey();
  expectBoundTokenResponse(await postTokenWithDPoP(request, service.body, serviceKey, { headers: service.basic }), serviceKey);
});

test("the authorization code grant binds its access token, and a confidential client's refresh binds the new one to the refresh's own key (section 5)", async ({
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
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const key = dpopKey();
  const redeemed = await postTokenWithDPoP(
    request,
    { grant_type: "authorization_code", code: signIn.code, code_verifier: signIn.codeVerifier, redirect_uri: testRedirectUri },
    key,
    basic,
  );
  expectBoundTokenResponse(redeemed, key);

  const refreshKey = dpopKey();
  const refreshed = await postTokenWithDPoP(request, { grant_type: "refresh_token", refresh_token: String(redeemed.body.refresh_token) }, refreshKey, basic);
  expectBoundTokenResponse(refreshed, refreshKey);

  await test.step("the confidential client's refresh token is unbound: a refresh without a proof is a bearer token", async () => {
    const bearer = await postToken(request, { grant_type: "refresh_token", refresh_token: String(refreshed.body.refresh_token) }, basic);
    expectTokenResponse(bearer);
    expect(bearer.headers["dpop-nonce"]).toBeUndefined();
  });
});

const boundRefreshTokenRefusal = "The refresh token is bound to a DPoP key, and the request carries no proof by that key.";

test("a public client's refresh token is bound to its key: refused invalid_grant without a proof by it, and still the key holder's (section 5)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  await signIn.context.close();

  const key = dpopKey();
  const redeemed = await postTokenWithDPoP(
    request,
    { grant_type: "authorization_code", client_id: client.identifier, code: signIn.code, code_verifier: signIn.codeVerifier, redirect_uri: testRedirectUri },
    key,
  );
  expectBoundTokenResponse(redeemed, key);
  const refresh = { grant_type: "refresh_token", client_id: client.identifier, refresh_token: String(redeemed.body.refresh_token) };

  await test.step("a refresh without a proof is refused invalid_grant", async () => {
    const refused = await postToken(request, refresh);
    expectTokenError(refused, "invalid_grant");
    expect(refused.body.error_description).toBe(boundRefreshTokenRefusal);
  });
  await test.step("a refresh with a proof by another key is refused invalid_grant, with a fresh nonce", async () => {
    const refused = await postTokenWithDPoP(request, refresh, dpopKey());
    expectTokenError(refused, "invalid_grant");
    expect(refused.body.error_description).toBe(boundRefreshTokenRefusal);
    nonceOf(refused);
  });
  const refreshed = await test.step("the refusals spent nothing: a refresh by the key is answered", async () => {
    const answered = await postTokenWithDPoP(request, refresh, key);
    expectBoundTokenResponse(answered, key);
    return answered;
  });
  await test.step("and the new refresh token is bound to the same key", async () => {
    const refused = await postToken(request, { ...refresh, refresh_token: String(refreshed.body.refresh_token) });
    expectTokenError(refused, "invalid_grant");
    expect(refused.body.error_description).toBe(boundRefreshTokenRefusal);
  });
});

test("htu names the public URL: a proof naming the internal URL, or another host, is invalid_dpop_proof (section 4.3)", async ({ page, clients, resources, request }) => {
  const { basic, body } = await clientCredentialsClient(page, clients, resources);
  const key = dpopKey();
  const nonce = nonceOf(await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key) } }));

  for (const htu of [
    // The setup wizard's internal URL, which the admin console reaches the auth server at.
    "http://goiabada-authserver:9090/auth/token",
    // The address nginx proxies to.
    "http://127.0.0.1:9090/auth/token",
    `${new URL(env.adminUrl).origin}/auth/token`,
  ]) {
    await test.step(htu, async () => {
      const refused = await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { htu, nonce }) } });
      expectTokenError(refused, "invalid_dpop_proof");
      expect(refused.body.error_description).toBe("The DPoP proof is invalid.");
      nonceOf(refused);
    });
  }
  await test.step(`the public URL, ${tokenEndpoint}, is accepted`, async () => {
    expectBoundTokenResponse(await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { nonce }) } }), key);
  });
});

test("a proof is accepted once: sent again, it is invalid_dpop_proof, and a request refused before minting leaves it unspent (section 11.1)", async ({
  page,
  clients,
  resources,
  request,
}) => {
  const { basic, body } = await clientCredentialsClient(page, clients, resources);
  const key = dpopKey();
  const nonce = nonceOf(await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key) } }));
  const proof = dpopProof(key, { nonce });

  await test.step("refused at client authentication, the proof is not spent", async () => {
    const wrongSecret = { Authorization: basicAuth("no-such-client", "not-the-secret") };
    const refused = await postToken(request, body, { headers: { ...wrongSecret, DPoP: proof } });
    expectInvalidClient(refused, { viaBasic: true });
  });
  await test.step("its first use gets a bound token", async () => {
    expectBoundTokenResponse(await postToken(request, body, { headers: { ...basic, DPoP: proof } }), key);
  });
  await test.step("sent again, it is refused, with a fresh nonce", async () => {
    const replayed = await postToken(request, body, { headers: { ...basic, DPoP: proof } });
    expectTokenError(replayed, "invalid_dpop_proof");
    expect(replayed.body.error_description).toBe("The DPoP proof is invalid.");
    nonceOf(replayed);
  });
  await test.step("a new proof with the same nonce is another proof, and accepted", async () => {
    expectBoundTokenResponse(await postToken(request, body, { headers: { ...basic, DPoP: dpopProof(key, { nonce }) } }), key);
  });
});

const requiresDPoPRefusal = "This client requires a DPoP proof with every token request.";

test("a client requiring DPoP is refused a token without a proof once it has authenticated, and answered with one (section 5.2)", async ({
  page,
  clients,
  resources,
  users,
  request,
}) => {
  const service = await clientCredentialsClient(page, clients, resources);
  await setRequireDPoP(page, request, clients, service.client.id, true);

  await test.step("without a DPoP header it is invalid_dpop_proof, with no nonce", async () => {
    const refused = await postToken(request, service.body, { headers: service.basic });
    expectTokenError(refused, "invalid_dpop_proof");
    expect(refused.body.error_description).toBe(requiresDPoPRefusal);
    expect(refused.headers["dpop-nonce"]).toBeUndefined();
  });
  await test.step("a wrong secret is still invalid_client, so a stranger learns nothing of the setting", async () => {
    expectInvalidClient(await postToken(request, service.body, { headers: { Authorization: basicAuth(service.client.identifier, "not-the-secret") } }), {
      viaBasic: true,
    });
  });
  await test.step("with a proof it is a bound token", async () => {
    const key = dpopKey();
    expectBoundTokenResponse(await postTokenWithDPoP(request, service.body, key, { headers: service.basic }), key);
  });

  await test.step("the password grant is refused before the password is looked at", async () => {
    const user = await users.create();
    const { client, secret } = await passwordGrantClient(page, clients);
    await setRequireDPoP(page, request, clients, client.id, true);
    const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };
    const wrongPassword = await postToken(request, { grant_type: "password", username: user.email, password: "not-the-password", scope: "openid" }, basic);
    expectTokenError(wrongPassword, "invalid_dpop_proof");
    expect(wrongPassword.body.error_description).toBe(requiresDPoPRefusal);
    const key = dpopKey();
    expectBoundTokenResponse(
      await postTokenWithDPoP(request, { grant_type: "password", username: user.email, password: user.password, scope: "openid" }, key, basic),
      key,
    );
  });

  await test.step("switched off, the client is answered a bearer token without a proof again", async () => {
    await setRequireDPoP(page, request, clients, service.client.id, false);
    expectTokenResponse(await postToken(request, service.body, { headers: service.basic }));
  });
});
