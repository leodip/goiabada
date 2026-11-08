// Protect an API, through the test app's API (/api/products) and its service: the API checks each
// token on its own against the auth server's public keys, requiring the at+jwt header as RFC 9068
// section 4 asks, so every answer of 200 here is also a token the auth server issued as one, and
// answers 401 or 403. It then introspects the token with its own client (RFC 7662), so a token cut
// off since it was issued is refused at once. A token bound to a key with DPoP (RFC 9449) is
// accepted only with the DPoP scheme and a proof by that key for the request, its cnf.jkt read from
// the token and from introspection's answer, and refused as the guide's "Accept DPoP-bound tokens"
// says.
import type { APIRequestContext, Page } from "@playwright/test";
import { confirmDialog, grantClientPermission, grantUserPermission, readClientSecret, userUrl } from "../../lib/admin-console";
import { dpopKey, dpopProof, expectBoundTokenResponse, postTokenWithDPoP, type DPoPKey } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test, type TestClient } from "../../lib/fixtures";
import { basicAuth, expectTokenResponse, postToken } from "../../lib/rfc6749";
import { expectResult, resultBody, shownClaims, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

// The DPoP challenge the API answers beside its Bearer one, naming the algorithms it accepts.
const dpopChallenge = `DPoP realm="${testapp.api.resource}", algs="ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512 Ed25519"`;

test("the service gets a token with the client credentials flow and the API accepts it", async ({ browser }) => {
  const { context, page: service } = await userBrowser(browser);
  await service.goto(testapp.service.url);
  await service.getByRole("button", { name: "Get a token and call the API" }).click();
  await expectResult(service, "Got a token; the API answered 200");
  const body = await resultBody(service);
  expect((body.token_response as Record<string, unknown>).scope).toBe(testapp.api.scope);
  const access = await shownClaims(service, "Access token claims");
  // With no user, the subject is the client itself.
  expect(access.sub).toBe(testapp.service.clientId);
  expect(access.aud).toBe(testapp.api.resource);
  expect(access.scope).toBe(testapp.api.scope);
  await context.close();
});

test("the service asking for no scope gets every permission it holds; asking for openid is refused", async ({ browser }) => {
  const { context, page: service } = await userBrowser(browser);
  await service.goto(testapp.service.url);

  await service.getByRole("button", { name: "Same, with no scope in the request" }).click();
  await expectResult(service, "Got a token; the API answered 200");
  expect(((await resultBody(service)).token_response as Record<string, unknown>).scope).toBe(testapp.api.scope);

  await service.getByRole("button", { name: "Ask for openid (should be refused)" }).click();
  await expectResult(service, "The token request failed");
  expect((await resultBody(service)).error).toBe("invalid_scope");
  await context.close();
});

test("the API refuses a request with no token, a token it can't verify, and a token without its permission", async ({ page, request, browser, users }) => {
  const none = await request.get(testapp.api.url, { failOnStatusCode: false });
  expect(none.status()).toBe(401);
  expect(none.headers()["www-authenticate"]).toBe(`Bearer realm="${testapp.api.resource}", ${dpopChallenge}`);

  // A user holding only write signs in for it: the token is for the API, but carries no read.
  const user = await users.create();
  await grantUserPermission(page, user.id, testapp.api.resource, "write");
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user, { scope: `openid ${testapp.api.resource}:write` });
  await expectResult(app, "Signed in");
  const access = await shownClaims(app, "Access token claims");
  expect(access.aud).toContain(testapp.api.resource);
  await app.getByRole("button", { name: "Call the API" }).click();
  await expectResult(app, "The API answered 403");
  const refused = await resultBody(app);
  expect(refused.www_authenticate).toContain('error="insufficient_scope"');
  await context.close();

  // A token the auth server never signed, naming a key it doesn't have.
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "made-up" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: env.authUrl, aud: testapp.api.resource, scope: testapp.api.scope, exp: 9999999999 })).toString("base64url");
  const forged = await request.get(testapp.api.url, { headers: { Authorization: `Bearer ${header}.${payload}.c2lnbmF0dXJl` }, failOnStatusCode: false });
  expect(forged.status()).toBe(401);
  expect(forged.headers()["www-authenticate"]).toContain('error="invalid_token"');
});

// The web app with no back-channel logout URI keeps its token after the end; one that has the URI is
// told and drops it (backchannel-logout.spec.ts).
test("the API introspects each token, so one whose session was ended is refused at once", async ({ page, browser, users }) => {
  const user = await users.create();
  await grantUserPermission(page, user.id, testapp.api.resource, "read");
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web3, user);
  await expectResult(app, "Signed in");
  await app.getByRole("button", { name: "Call the API" }).click();
  await expectResult(app, "The API answered 200");

  // The administrator ends the user's session: the token's signature and expiry still check out.
  await page.goto(userUrl(user.id, "sessions"));
  await page.locator("#sessionsTable tbody tr").first().getByRole("button", { name: /^End session/ }).click();
  await confirmDialog(page, "Clients the user signed in to from it");
  await expect(page.locator("#sessions-status")).toContainText("Session ended.");

  await app.getByRole("button", { name: "Call the API" }).click();
  await expectResult(app, "The API answered 401");
  const refused = await resultBody(app);
  expect(refused.www_authenticate).toContain('error="invalid_token"');
  expect(refused.body).toEqual({ error: "invalid_token", error_description: "The auth server says the token is no longer active." });
  await context.close();
});

// A service of the test's own, holding the API's read permission, and an access token for the API
// from the client credentials flow: bound to key with a proof when there is one, a bearer token
// otherwise.
async function serviceToken(page: Page, request: APIRequestContext, clients: { create(options: { authorizationCode: boolean; clientCredentials: boolean }): Promise<TestClient> }) {
  const service = await clients.create({ authorizationCode: false, clientCredentials: true });
  const [resource, permission] = testapp.api.scope.split(":");
  await grantClientPermission(page, service.id, resource, permission);
  const basic = basicAuth(service.identifier, await readClientSecret(page, service.id));
  const body = { grant_type: "client_credentials", scope: testapp.api.scope };
  return {
    async bound(key: DPoPKey): Promise<string> {
      const answer = await postTokenWithDPoP(request, body, key, { headers: { Authorization: basic } });
      expectBoundTokenResponse(answer, key);
      return String(answer.body.access_token);
    },
    async bearer(): Promise<string> {
      const answer = await postToken(request, body, { headers: { Authorization: basic } });
      expectTokenResponse(answer);
      expect(answer.body.token_type).toBe("Bearer");
      return String(answer.body.access_token);
    },
  };
}

// GETs the API, checking the token the way check names (local, introspection, or both when
// undefined), with this Authorization header and, when there is one, this DPoP proof.
async function callApi(request: APIRequestContext, check: string | undefined, authorization: string, proof?: string) {
  const url = check ? `${testapp.api.url}?check=${check}` : testapp.api.url;
  const response = await request.get(url, { headers: { Authorization: authorization, ...(proof ? { DPoP: proof } : {}) }, failOnStatusCode: false });
  return { status: response.status(), challenge: response.headers()["www-authenticate"], body: await response.json() };
}

// A proof for GET the API, whatever the query: htu is its URL without one.
const apiProof = (key: DPoPKey, accessToken: string, overrides: { htu?: string; htm?: string } = {}) =>
  dpopProof(key, { htm: "GET", htu: testapp.api.url, accessToken, ...overrides });

test.describe("DPoP-bound tokens at the API", () => {
  test("a bound token with the DPoP scheme and its proof is accepted, by local validation and by introspection", async ({ page, request, clients }) => {
    const key = dpopKey();
    const token = await (await serviceToken(page, request, clients)).bound(key);

    for (const check of ["local", "introspection", undefined]) {
      await test.step(`checked ${check ?? "locally and by introspection"}`, async () => {
        const answer = await callApi(request, check, `DPoP ${token}`, apiProof(key, token));
        expect(answer.status, JSON.stringify(answer.body)).toBe(200);
        expect(answer.body.scheme).toBe("DPoP");
        expect(answer.body.scope).toBe(testapp.api.scope);
        if (check !== "introspection") expect(answer.body.binding.token_cnf).toEqual({ jkt: key.thumbprint });
        if (check !== "local") expect(answer.body.binding.introspection).toEqual({ token_type: "DPoP", cnf: { jkt: key.thumbprint } });
      });
    }
  });

  test("the API refuses a bound token sent as Bearer, a missing proof, a proof for another URL or method, a wrong ath, another key and a replay", async ({ page, request, clients }) => {
    const key = dpopKey();
    const service = await serviceToken(page, request, clients);
    const token = await service.bound(key);
    const bearer = await service.bearer();
    const anotherUrl = new URL("/api/orders", testapp.api.url).href;

    // Each check refuses each case by itself: introspection alone reads the binding from the auth
    // server's answer.
    for (const check of ["local", "introspection"]) {
      await test.step(`checked ${check}`, async () => {
        const bearerRefusal = await callApi(request, check, `Bearer ${token}`);
        expect(bearerRefusal.status).toBe(401);
        expect(bearerRefusal.challenge).toMatch(new RegExp(`^Bearer realm="${testapp.api.resource}", error="invalid_token", .*, ${escapeRegExp(dpopChallenge)}$`));
        expect(bearerRefusal.body).toEqual({ error: "invalid_token", error_description: "The access token is bound to a DPoP key and must be sent with the DPoP scheme." });

        for (const [what, proof] of [
          ["no proof", undefined],
          ["a proof for another URL", apiProof(key, token, { htu: anotherUrl })],
          ["a proof for another method", apiProof(key, token, { htm: "POST" })],
          ["a proof whose ath is another token's", apiProof(key, bearer)],
        ] as const) {
          const refused = await callApi(request, check, `DPoP ${token}`, proof);
          expect(refused.status, what).toBe(401);
          expect(refused.challenge, what).toMatch(new RegExp(`^Bearer realm="${testapp.api.resource}", ${escapeRegExp(dpopChallenge)}, error="invalid_dpop_proof", `));
          expect(refused.body.error, what).toBe("invalid_dpop_proof");
        }

        const otherKey = await callApi(request, check, `DPoP ${token}`, apiProof(dpopKey(), token));
        expect(otherKey.status).toBe(401);
        expect(otherKey.challenge).toMatch(new RegExp(`^Bearer realm="${testapp.api.resource}", ${escapeRegExp(dpopChallenge)}, error="invalid_token", `));
        expect(otherKey.body).toEqual({ error: "invalid_token", error_description: "The DPoP proof is signed by another key than the one the access token is bound to." });

        const unbound = await callApi(request, check, `DPoP ${bearer}`, apiProof(key, bearer));
        expect(unbound.status).toBe(401);
        expect(unbound.body).toEqual({ error: "invalid_token", error_description: "The access token is not bound to a DPoP key and must be sent with the Bearer scheme." });

        // The bearer token as Bearer is still answered, a stray DPoP header beside it ignored.
        expect((await callApi(request, check, `Bearer ${bearer}`, apiProof(key, bearer))).status).toBe(200);

        const proof = apiProof(key, token);
        expect((await callApi(request, check, `DPoP ${token}`, proof)).status).toBe(200);
        const replay = await callApi(request, check, `DPoP ${token}`, proof);
        expect(replay.status).toBe(401);
        expect(replay.body).toEqual({ error: "invalid_dpop_proof", error_description: "The DPoP proof is invalid: it was already used." });
      });
    }
  });
});

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
