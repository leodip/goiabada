// RFC 7662, token introspection: an API, calling as a confidential client an administrator listed
// resources on, asks /auth/introspect whether a token is active (section 2.1) and gets its members
// or exactly {"active": false} (section 2.2), never cached (section 4). A token the caller is not
// listed for is inactive, a refresh token is answered to its own client alone, a public client is
// refused since a caller must authenticate (section 4), and GET is refused. The test app's API, which
// introspects every token, is in ../testapp/protect-an-api.spec.ts.
import type { APIRequestContext, Page } from "@playwright/test";
import { addIntrospectionResource, clientUrl, readClientSecret } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test, type TestClient } from "../../lib/fixtures";
import { jwtClaims, userTokens } from "../../lib/oauth";
import { passwordGrantClient, publicSignInClient } from "../../lib/test-clients";

const introspectionEndpoint = `${env.authUrl}/auth/introspect`;

// Lists resources on the client's Introspection tab and saves them.
async function listIntrospectionResources(page: Page, client: TestClient, identifiers: string[]) {
  await page.goto(clientUrl(client.id, "introspection"));
  for (const identifier of identifiers) await addIntrospectionResource(page, identifier);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Introspection resources saved.")).toBeVisible();
}

// Posts token to the introspection endpoint with the client's Basic credentials.
async function introspect(request: APIRequestContext, clientId: string, clientSecret: string, token: string) {
  const response = await request.post(introspectionEndpoint, {
    form: { token },
    headers: { Authorization: `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64")}` },
    failOnStatusCode: false,
  });
  return { status: response.status(), headers: response.headers(), body: (await response.json()) as Record<string, unknown> };
}

test("discovery announces the introspection endpoint and its client authentication methods", async ({ request }) => {
  const metadata = await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json();
  expect(metadata.introspection_endpoint).toBe(introspectionEndpoint);
  expect(metadata.introspection_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post"]);
});

test("an access token is active to a client listed for its audience, and inactive once its grant is revoked (section 2.2)", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const app = await passwordGrantClient(page, clients);
  const api = await clients.create();
  await listIntrospectionResources(page, api, ["authserver"]);
  const apiSecret = await readClientSecret(page, api.id);
  const tokens = await userTokens(request, app.client.identifier, app.secret, user, "openid");
  const accessToken = tokens.body.access_token as string;

  const active = await introspect(request, api.identifier, apiSecret, accessToken);
  expect(active.status).toBe(200);
  expect(active.headers["cache-control"]).toBe("no-store");
  expect(active.body).toEqual({
    active: true,
    scope: "openid",
    client_id: app.client.identifier,
    sub: tokens.access.sub,
    aud: tokens.access.aud,
    iss: env.authUrl,
    exp: tokens.access.exp,
    iat: tokens.access.iat,
    nbf: tokens.access.nbf,
    jti: tokens.access.jti,
    token_type: "Bearer",
  });

  const revoked = await request.post(`${env.authUrl}/auth/revoke`, {
    form: { token: tokens.body.refresh_token as string, client_id: app.client.identifier, client_secret: app.secret },
  });
  expect(revoked.status()).toBe(200);

  const inactive = await introspect(request, api.identifier, apiSecret, accessToken);
  expect(inactive.status).toBe(200);
  expect(inactive.body).toEqual({ active: false });
});

test("a client not listed for a token's audience gets {active: false} for a live one (section 2.2)", async ({
  page,
  clients,
  resources,
  users,
  request,
}) => {
  const user = await users.create();
  const app = await passwordGrantClient(page, clients);
  const other = await resources.create();
  const api = await clients.create();
  await listIntrospectionResources(page, api, [other.identifier]);
  const apiSecret = await readClientSecret(page, api.id);
  const tokens = await userTokens(request, app.client.identifier, app.secret, user, "openid");

  const answer = await introspect(request, api.identifier, apiSecret, tokens.body.access_token as string);

  expect(answer.status).toBe(200);
  expect(answer.body).toEqual({ active: false });
});

test("a refresh token is active to its own client alone, and introspecting it spends nothing", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const app = await passwordGrantClient(page, clients);
  const other = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, app.client.identifier, app.secret, user, "openid offline_access");
  const refreshToken = tokens.body.refresh_token as string;
  const claims = jwtClaims(refreshToken);

  const own = await introspect(request, app.client.identifier, app.secret, refreshToken);
  expect(own.body).toEqual({
    active: true,
    scope: "openid offline_access",
    client_id: app.client.identifier,
    sub: claims.sub,
    iss: env.authUrl,
    exp: claims.exp,
    iat: claims.iat,
    jti: claims.jti,
  });
  expect((await introspect(request, other.client.identifier, other.secret, refreshToken)).body).toEqual({ active: false });

  const refreshed = await request.post(`${env.authUrl}/auth/token`, {
    form: { grant_type: "refresh_token", refresh_token: refreshToken, client_id: app.client.identifier, client_secret: app.secret },
    failOnStatusCode: false,
  });
  expect(refreshed.status(), "the refresh token still refreshes").toBe(200);
});

test("a public client is refused with invalid_client, and GET is refused (section 4)", async ({ page, clients, request }) => {
  const client = await publicSignInClient(page, clients);

  const answer = await request.post(introspectionEndpoint, { form: { token: "anything", client_id: client.identifier }, failOnStatusCode: false });
  expect(answer.status()).toBe(401);
  expect(answer.headers()["cache-control"]).toBe("no-store");
  expect((await answer.json()).error).toBe("invalid_client");

  const get = await request.get(introspectionEndpoint, { failOnStatusCode: false });
  expect(get.status()).toBe(405);
});
