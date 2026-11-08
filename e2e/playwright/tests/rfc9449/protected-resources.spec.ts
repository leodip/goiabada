// RFC 9449 at the auth server's own resources, through the real proxy: userinfo and the Account API
// take an access token bound to a key with the DPoP scheme, beside a proof whose htu is the public
// URL the client reached and whose ath is the token's hash (section 7.1). A bound token sent as a
// bearer token is refused (section 7.2 MUST), and so are a bearer token sent with the DPoP scheme
// and a proof for another token. Every 401 names both schemes, Bearer first, the error in the
// challenge of the scheme used (section 7.2). The full matrix is in the Go tiers.
import type { APIRequestContext } from "@playwright/test";
import { authServerDPoPChallenge as dpopChallenge, dpopKey, dpopProof, expectBoundTokenResponse, postTokenWithDPoP, type DPoPKey } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, expectTokenResponse, postToken } from "../../lib/rfc6749";
import { passwordGrantClient } from "../../lib/test-clients";

const userinfoUrl = `${env.authUrl}/userinfo`;
const profileUrl = `${env.authUrl}/api/v1/account/profile`;
const scope = "openid authserver:manage-account";

// GETs url with the Authorization header given and, when there is one, the proof as a DPoP header.
async function call(request: APIRequestContext, url: string, authorization: string, proof?: string) {
  const response = await request.get(url, {
    headers: { Authorization: authorization, ...(proof ? { DPoP: proof } : {}) },
    failOnStatusCode: false,
  });
  const text = await response.text();
  return { status: response.status(), challenge: response.headers()["www-authenticate"], body: text ? JSON.parse(text) : {}, text };
}

// A user's access token from the password grant, bound to key when there is one.
async function userToken(
  request: APIRequestContext,
  credentials: { basic: string; username: string; password: string },
  key?: DPoPKey,
): Promise<string> {
  const body = { grant_type: "password", username: credentials.username, password: credentials.password, scope };
  const headers = { headers: { Authorization: credentials.basic } };
  if (!key) {
    const answer = await postToken(request, body, headers);
    expectTokenResponse(answer);
    expect(answer.body.token_type).toBe("Bearer");
    return String(answer.body.access_token);
  }
  const answer = await postTokenWithDPoP(request, body, key, headers);
  expectBoundTokenResponse(answer, key);
  return String(answer.body.access_token);
}

test.describe("DPoP at userinfo and the Account API", () => {
  test("a bound token with the DPoP scheme and its proof is answered, once per proof (sections 7.1 and 11.1)", async ({ page, clients, users, request }) => {
    const user = await users.create();
    const { client, secret } = await passwordGrantClient(page, clients);
    const key = dpopKey();
    const token = await userToken(request, { basic: basicAuth(client.identifier, secret), username: user.email, password: user.password }, key);

    const proof = dpopProof(key, { htm: "GET", htu: userinfoUrl, accessToken: token });
    const claims = await call(request, userinfoUrl, `DPoP ${token}`, proof);
    expect(claims.status, claims.text).toBe(200);
    expect(claims.body.sub).toBeTruthy();

    const profile = await call(request, profileUrl, `DPoP ${token}`, dpopProof(key, { htm: "GET", htu: profileUrl, accessToken: token }));
    expect(profile.status, profile.text).toBe(200);
    expect(profile.body.user.email).toBe(user.email);

    await test.step("the same proof again is refused invalid_dpop_proof", async () => {
      const replay = await call(request, userinfoUrl, `DPoP ${token}`, proof);
      expect(replay.status).toBe(401);
      expect(replay.challenge).toBe(`Bearer realm="goiabada", ${dpopChallenge}, error="invalid_dpop_proof", error_description="The DPoP proof is invalid."`);
      expect(replay.body).toEqual({ error: "invalid_dpop_proof", error_description: "The DPoP proof is invalid." });
    });
  });

  test("a bound token sent as Bearer, a bearer token sent as DPoP and a proof for another token are refused (section 7.2)", async ({
    page,
    clients,
    users,
    request,
  }) => {
    const user = await users.create();
    const { client, secret } = await passwordGrantClient(page, clients);
    const credentials = { basic: basicAuth(client.identifier, secret), username: user.email, password: user.password };
    const key = dpopKey();
    const bound = await userToken(request, credentials, key);
    const bearer = await userToken(request, credentials);

    await test.step("a bound token sent as Bearer: invalid_token in the Bearer challenge", async () => {
      const description = "The access token is bound to a DPoP key and must be sent with the DPoP scheme.";
      const challenge = `Bearer realm="goiabada", error="invalid_token", error_description="${description}", ${dpopChallenge}`;
      const userinfo = await call(request, userinfoUrl, `Bearer ${bound}`);
      expect(userinfo.status).toBe(401);
      expect(userinfo.challenge).toBe(challenge);
      expect(userinfo.body).toEqual({ error: "invalid_token", error_description: description });
      const profile = await call(request, profileUrl, `Bearer ${bound}`);
      expect(profile.status).toBe(401);
      expect(profile.challenge).toBe(challenge);
      expect(profile.body).toEqual({ error_code: "INVALID_TOKEN", error_description: description });
    });

    await test.step("a bearer token sent with DPoP: invalid_token in the DPoP challenge", async () => {
      const description = "The access token is not bound to a DPoP key and must be sent with the Bearer scheme.";
      const refused = await call(request, userinfoUrl, `DPoP ${bearer}`, dpopProof(key, { htm: "GET", htu: userinfoUrl, accessToken: bearer }));
      expect(refused.status).toBe(401);
      expect(refused.challenge).toBe(`Bearer realm="goiabada", ${dpopChallenge}, error="invalid_token", error_description="${description}"`);
      expect(refused.body).toEqual({ error: "invalid_token", error_description: description });
    });

    await test.step("the bearer token as Bearer is still answered", async () => {
      expect((await call(request, userinfoUrl, `Bearer ${bearer}`)).status).toBe(200);
    });

    await test.step("a proof whose ath is another token's: invalid_dpop_proof", async () => {
      const refused = await call(request, profileUrl, `DPoP ${bound}`, dpopProof(key, { htm: "GET", htu: profileUrl, accessToken: bearer }));
      expect(refused.status).toBe(401);
      expect(refused.challenge).toBe(`Bearer realm="goiabada", ${dpopChallenge}, error="invalid_dpop_proof", error_description="The DPoP proof is invalid."`);
      expect(refused.body).toEqual({ error_code: "INVALID_DPOP_PROOF", error_description: "The DPoP proof is invalid." });
    });

    await test.step("a proof naming the internal URL, the hop behind the proxy: invalid_dpop_proof", async () => {
      const refused = await call(request, userinfoUrl, `DPoP ${bound}`, dpopProof(key, { htm: "GET", htu: "http://127.0.0.1:9090/userinfo", accessToken: bound }));
      expect(refused.status).toBe(401);
      expect(refused.body.error).toBe("invalid_dpop_proof");
    });

    await test.step("a proof two minutes old: invalid_dpop_proof", async () => {
      const refused = await call(request, userinfoUrl, `DPoP ${bound}`, dpopProof(key, { htm: "GET", htu: userinfoUrl, accessToken: bound, iatOffsetSeconds: -120 }));
      expect(refused.status).toBe(401);
      expect(refused.body.error).toBe("invalid_dpop_proof");
    });
  });

  test("a request with no credentials is told both schemes, Bearer first, with no error (section 7.2)", async ({ request }) => {
    for (const url of [userinfoUrl, profileUrl]) {
      await test.step(url, async () => {
        const response = await request.get(url, { failOnStatusCode: false });
        expect(response.status()).toBe(401);
        expect(response.headers()["www-authenticate"]).toBe(`Bearer realm="goiabada", ${dpopChallenge}`);
      });
    }
  });
});
