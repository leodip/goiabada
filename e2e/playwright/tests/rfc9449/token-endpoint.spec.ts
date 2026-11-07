// RFC 9449 at the token endpoint, through the real proxy: a proof on any of the four grants binds
// the access token to its key (section 5), answered token_type DPoP with cnf.jkt (section 6.1); the
// server's nonce is asked for with use_dpop_nonce, and every answer to a DPoP request carries a fresh
// one (section 8); and htu names the public URL the client reached, so a proof naming the auth
// server's internal URL, the hop behind the proxy, is refused (section 4.3). The full validation
// matrix is in the Go tiers. A proof is single-use (section 11.1): sent again, it is refused.
import type { Page } from "@playwright/test";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { dpopKey, dpopProof, expectBoundTokenResponse, expectUseDPoPNonce, nonceOf, postTokenWithDPoP } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test, type TestClient, type TestResource } from "../../lib/fixtures";
import { basicAuth, expectInvalidClient, expectTokenError, expectTokenResponse, postToken, tokenEndpoint } from "../../lib/rfc6749";
import { browserSignInClient, passwordGrantClient } from "../../lib/test-clients";

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

test("the authorization code grant binds its access token, and a refresh binds the new one to the refresh's own key (section 5)", async ({
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
  expectBoundTokenResponse(
    await postTokenWithDPoP(request, { grant_type: "refresh_token", refresh_token: String(redeemed.body.refresh_token) }, refreshKey, basic),
    refreshKey,
  );
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
