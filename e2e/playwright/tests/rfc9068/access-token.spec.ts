// RFC 9068, the JWT profile for OAuth 2.0 access tokens: every access token carries the header typ
// at+jwt (2.1) and the client_id of its client (2.2); those of a grant that issues a refresh token
// carry its grant_id, the same through every refresh; offline_access names the auth server in aud
// (2.2.3). The auth server checks its own access tokens as section 4 asks of a resource server, and
// also refuses one whose client is disabled. The test app's API, which requires at+jwt, is in
// ../testapp/protect-an-api.spec.ts.
import type { Page } from "@playwright/test";
import { clientUrl, confirmDialog, grantClientPermission, grantUserPermission, readClientSecret } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { clientCredentialsToken, jwtClaims, refreshToken, userTokens, userinfo } from "../../lib/oauth";
import { passwordGrantClient } from "../../lib/test-clients";

// The JOSE header of a JWT, unverified.
function jwtHeader(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
}

async function setClientEnabled(page: Page, id: number, enabled: boolean) {
  await page.goto(clientUrl(id, "settings"));
  await page.locator('input[name="enabled"]').setChecked(enabled);
  await page.locator("#btnSave").click();
  if (!enabled) await confirmDialog(page, "You're disabling the client");
  await expect(page.getByText("Settings saved.")).toBeVisible();
}

test("a user's access token is an at+jwt naming its client and its grant, through every refresh", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid offline_access");
  const accessToken = tokens.body.access_token as string;

  expect(jwtHeader(accessToken).typ).toBe("at+jwt");
  // The ID and refresh tokens are no access tokens, and say so.
  expect(jwtHeader(tokens.body.id_token as string).typ).not.toBe("at+jwt");
  expect(jwtHeader(tokens.body.refresh_token as string).typ).not.toBe("at+jwt");
  expect(tokens.access.client_id).toBe(client.identifier);
  expect(tokens.access.grant_id, "the grant is named").toEqual(expect.any(String));
  // The grant is its first refresh token's identifier.
  expect(tokens.access.grant_id).toBe(jwtClaims(tokens.body.refresh_token as string).jti);
  // offline_access means something to the auth server alone, so it names authserver (2.2.3 MUST).
  expect(tokens.access.aud).toBe("authserver");
  expect(tokens.access.scope).toBe("openid offline_access");

  const refreshed = await refreshToken(request, client.identifier, secret, tokens.body.refresh_token as string);
  expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
  const refreshedAccess = refreshed.body.access_token as string;
  expect(jwtHeader(refreshedAccess).typ).toBe("at+jwt");
  expect(jwtClaims(refreshedAccess).grant_id, "a refresh stays in its grant").toBe(tokens.access.grant_id);
  expect(jwtClaims(refreshedAccess).client_id).toBe(client.identifier);
});

test("a token for an API and offline_access names both, and the API's own scope", async ({ page, clients, users, resources, request }) => {
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read"] });
  await grantUserPermission(page, user.id, resource.identifier, "read");
  const { client, secret } = await passwordGrantClient(page, clients);

  const tokens = await userTokens(request, client.identifier, secret, user, `${resource.identifier}:read offline_access`);

  expect(tokens.access.aud).toEqual([resource.identifier, "authserver"]);
});

test("a client credentials token is an at+jwt naming its client and no grant", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const answer = await clientCredentialsToken(request, client.identifier, await readClientSecret(page, client.id), "authserver:manage-account");
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  const accessToken = answer.body.access_token as string;

  expect(jwtHeader(accessToken).typ).toBe("at+jwt");
  const claims = jwtClaims(accessToken);
  expect(claims.client_id).toBe(client.identifier);
  expect(claims.sub).toBe(client.identifier);
  expect(claims).not.toHaveProperty("grant_id");
});

test("the auth server refuses a user's access token while its client is disabled, and takes it back once enabled", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid");
  const accessToken = tokens.body.access_token as string;
  expect((await userinfo(request, accessToken)).status).toBe(200);

  await setClientEnabled(page, client.id, false);
  const refused = await request.get(`${env.authUrl}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    failOnStatusCode: false,
  });
  expect(refused.status()).toBe(401);
  expect(refused.headers()["www-authenticate"]).toBe(
    'Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."',
  );

  await setClientEnabled(page, client.id, true);
  expect((await userinfo(request, accessToken)).status).toBe(200);
});

// The admin API checks a token before its scope, so a token the client holds for another resource
// shows the difference: refused for its scope while the client is enabled, refused as a token once
// it is not.
test("the auth server refuses a client's access token at the admin API while the client is disabled", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const answer = await clientCredentialsToken(request, client.identifier, await readClientSecret(page, client.id), "authserver:manage-account");
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  const accessToken = answer.body.access_token as string;
  const listResources = () =>
    request.get(`${env.authUrl}/api/v1/admin/resources`, { headers: { Authorization: `Bearer ${accessToken}` }, failOnStatusCode: false });
  const enabled = await listResources();
  expect(enabled.status()).toBe(403);
  expect((await enabled.json()).error_code).toBe("INSUFFICIENT_SCOPE");

  await setClientEnabled(page, client.id, false);
  const refused = await listResources();
  expect(refused.status()).toBe(401);
  expect(await refused.json()).toEqual({ error_code: "INVALID_TOKEN", error_description: "The access token is invalid." });
});
