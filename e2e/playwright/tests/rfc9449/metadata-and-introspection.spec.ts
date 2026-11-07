// RFC 9449's metadata and introspection, through the real proxy: discovery, at both of its
// addresses, lists the algorithms a proof may be signed with in dpop_signing_alg_values_supported
// (section 5.1), never none or a symmetric one; and introspection answers an API about an access
// token bound to a key with token_type DPoP and the token's cnf, the key's thumbprint as jkt
// (section 6.2), while a bearer token keeps token_type Bearer and no cnf, and a caller not listed
// for the token's audience learns nothing of it. The proof checks themselves are in
// token-endpoint.spec.ts and the Go tiers.
import type { APIRequestContext, Page } from "@playwright/test";
import { addIntrospectionResource, clientUrl, grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { dpopKey, expectBoundTokenResponse, postTokenWithDPoP } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test, type TestClient } from "../../lib/fixtures";
import { jwtClaims } from "../../lib/oauth";
import { basicAuth, expectTokenResponse, postToken } from "../../lib/rfc6749";

const introspectionEndpoint = `${env.authUrl}/auth/introspect`;

// Lists resources on the client's Introspection tab and saves them.
async function listIntrospectionResources(page: Page, client: TestClient, identifiers: string[]) {
  await page.goto(clientUrl(client.id, "introspection"));
  for (const identifier of identifiers) await addIntrospectionResource(page, identifier);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Introspection resources saved.")).toBeVisible();
}

// Posts token to the introspection endpoint with the client's Basic credentials, and the extra
// header fields given.
async function introspect(request: APIRequestContext, clientId: string, clientSecret: string, token: string, headers: Record<string, string> = {}) {
  const response = await request.post(introspectionEndpoint, {
    form: { token },
    headers: { Authorization: basicAuth(clientId, clientSecret), ...headers },
    failOnStatusCode: false,
  });
  return { status: response.status(), headers: response.headers(), body: (await response.json()) as Record<string, unknown> };
}

test("discovery lists the proof algorithms at both addresses, and none or a symmetric one at neither (section 5.1)", async ({ request }) => {
  for (const path of ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]) {
    await test.step(path, async () => {
      const response = await request.get(`${env.authUrl}${path}`);
      expect(response.status()).toBe(200);
      const algorithms = (await response.json()).dpop_signing_alg_values_supported;
      expect(algorithms).toEqual(["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "Ed25519", "EdDSA"]);
      for (const refused of ["none", "HS256", "HS384", "HS512"]) expect(algorithms).not.toContain(refused);
    });
  }
});

test("introspection answers a bound access token DPoP with its cnf, and a bearer token Bearer with none (section 6.2)", async ({
  page,
  clients,
  resources,
  request,
}) => {
  const resource = await resources.create({ permissions: ["read"] });
  const service = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, service.id, resource.identifier, "read");
  const basic = { Authorization: basicAuth(service.identifier, await readClientSecret(page, service.id)) };
  const body = { grant_type: "client_credentials", scope: `${resource.identifier}:read` };

  const api = await clients.create();
  await listIntrospectionResources(page, api, [resource.identifier]);
  const apiSecret = await readClientSecret(page, api.id);

  const key = dpopKey();
  const issued = await postTokenWithDPoP(request, body, key, { headers: basic });
  expectBoundTokenResponse(issued, key);
  const bound = String(issued.body.access_token);
  const claims = jwtClaims(bound);

  const answer = await introspect(request, api.identifier, apiSecret, bound);
  expect(answer.status).toBe(200);
  expect(answer.headers["cache-control"]).toBe("no-store");
  expect(answer.body).toEqual({
    active: true,
    scope: `${resource.identifier}:read`,
    client_id: service.identifier,
    sub: service.identifier,
    aud: resource.identifier,
    iss: env.authUrl,
    exp: claims.exp,
    iat: claims.iat,
    nbf: claims.nbf,
    jti: claims.jti,
    token_type: "DPoP",
    cnf: { jkt: key.thumbprint },
  });

  await test.step("a DPoP header sent to introspection is ignored", async () => {
    const withHeader = await introspect(request, api.identifier, apiSecret, bound, { DPoP: "not-a-proof" });
    expect(withHeader.status).toBe(200);
    expect(withHeader.body).toEqual(answer.body);
  });

  await test.step("a caller not listed for the token's audience gets {active: false}, and no cnf", async () => {
    const other = await clients.create();
    const unlisted = await introspect(request, other.identifier, await readClientSecret(page, other.id), bound);
    expect(unlisted.status).toBe(200);
    expect(unlisted.body).toEqual({ active: false });
  });

  await test.step("the same client's bearer token is answered Bearer, with no cnf", async () => {
    const bearer = await postToken(request, body, { headers: basic });
    expectTokenResponse(bearer);
    const introspected = await introspect(request, api.identifier, apiSecret, String(bearer.body.access_token));
    expect(introspected.body.active).toBe(true);
    expect(introspected.body.token_type).toBe("Bearer");
    expect(introspected.body).not.toHaveProperty("cnf");
  });
});
