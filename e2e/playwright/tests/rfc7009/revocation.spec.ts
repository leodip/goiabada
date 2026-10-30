// RFC 7009, token revocation: a client sends one of its tokens to /auth/revoke and the whole grant
// behind it ends (section 2.1), the refresh token at the token endpoint and the access tokens at
// /userinfo. An invalid token is answered 200 (2.2), another client's live token is refused with
// invalid_grant and left live, the hint is ignored, and a public client revokes with its client_id
// alone (section 5). A client credentials token, which belongs to no grant, is revoked on its own. The test app's sign-out, which revokes first, is in ../testapp/sign-out.spec.ts
// and ../testapp/spa.spec.ts.
import type { APIRequestContext } from "@playwright/test";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { clientCredentialsToken, refreshToken, userTokens, userinfo } from "../../lib/oauth";
import { passwordGrantClient, publicSignInClient } from "../../lib/test-clients";

const revocationEndpoint = `${env.authUrl}/auth/revoke`;

// Posts form to the revocation endpoint, with Basic credentials when a secret is given.
async function revoke(request: APIRequestContext, clientId: string, clientSecret: string | null, form: Record<string, string>) {
  const headers: Record<string, string> = {};
  if (clientSecret === null) {
    form = { ...form, client_id: clientId };
  } else {
    headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64")}`;
  }
  const response = await request.post(revocationEndpoint, { form, headers, failOnStatusCode: false });
  return { status: response.status(), text: await response.text() };
}

test("discovery announces the revocation endpoint and its client authentication methods", async ({ request }) => {
  const metadata = await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json();
  expect(metadata.revocation_endpoint).toBe(revocationEndpoint);
  expect(metadata.revocation_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post", "none"]);
});

test("revoking the refresh token ends the grant: the refresh token and its access tokens are refused (section 2.1)", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid offline_access");
  const accessToken = tokens.body.access_token as string;
  expect((await userinfo(request, accessToken)).status).toBe(200);

  const answer = await revoke(request, client.identifier, secret, { token: tokens.body.refresh_token as string });
  expect(answer).toEqual({ status: 200, text: "" });

  const refreshed = await refreshToken(request, client.identifier, secret, tokens.body.refresh_token as string);
  expect(refreshed.status).toBe(400);
  expect(refreshed.body.error).toBe("invalid_grant");
  expect((await userinfo(request, accessToken)).status).toBe(401);

  await test.step("revoking it again is answered as any invalid token (section 2.2)", async () => {
    expect(await revoke(request, client.identifier, secret, { token: tokens.body.refresh_token as string })).toEqual({ status: 200, text: "" });
  });
});

test("revoking an access token ends its grant, refresh token included, whatever the hint says", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid");

  const answer = await revoke(request, client.identifier, secret, {
    token: tokens.body.access_token as string,
    token_type_hint: "refresh_token",
  });
  expect(answer).toEqual({ status: 200, text: "" });

  const refreshed = await refreshToken(request, client.identifier, secret, tokens.body.refresh_token as string);
  expect(refreshed.body.error).toBe("invalid_grant");
  // A library that revokes the access token first and then the refresh token gets 200 for both.
  expect(await revoke(request, client.identifier, secret, { token: tokens.body.refresh_token as string })).toEqual({ status: 200, text: "" });
});

test("another client's live token is refused with invalid_grant, and stays live (section 2.1)", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const owner = await passwordGrantClient(page, clients);
  const other = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, owner.client.identifier, owner.secret, user, "openid");

  const answer = await revoke(request, other.client.identifier, other.secret, { token: tokens.body.refresh_token as string });

  expect(answer.status).toBe(400);
  expect(JSON.parse(answer.text)).toEqual({ error: "invalid_grant", error_description: "The token was issued to another client." });
  expect((await userinfo(request, tokens.body.access_token as string)).status).toBe(200);
  const refreshed = await refreshToken(request, owner.client.identifier, owner.secret, tokens.body.refresh_token as string);
  expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
});

test("an invalid token is answered 200 with an empty body (section 2.2)", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid");

  for (const [name, token] of Object.entries({
    "a string that is no token": "not-a-token",
    "an ID token": tokens.body.id_token as string,
  })) {
    await test.step(name, async () => {
      expect(await revoke(request, client.identifier, secret, { token })).toEqual({ status: 200, text: "" });
    });
  }
  expect((await userinfo(request, tokens.body.access_token as string)).status, "nothing was revoked").toBe(200);
});

test("a client that cannot authenticate is refused with invalid_client, and the token stays live", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid");

  const answer = await revoke(request, client.identifier, "not-the-secret", { token: tokens.body.refresh_token as string });

  expect(answer.status).toBe(401);
  expect(JSON.parse(answer.text).error).toBe("invalid_client");
  expect((await userinfo(request, tokens.body.access_token as string)).status).toBe(200);
});

test("a public client revokes with its client_id alone (section 5)", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const redeemed = await request.post(`${env.authUrl}/auth/token`, {
    form: {
      grant_type: "authorization_code",
      client_id: client.identifier,
      code: signIn.code,
      code_verifier: signIn.codeVerifier,
      redirect_uri: testRedirectUri,
    },
    failOnStatusCode: false,
  });
  await signIn.context.close();
  const tokens = await redeemed.json();
  expect(redeemed.status(), JSON.stringify(tokens)).toBe(200);

  expect(await revoke(request, client.identifier, null, { token: tokens.refresh_token })).toEqual({ status: 200, text: "" });

  expect((await userinfo(request, tokens.access_token)).status).toBe(401);
});

// The admin API checks a token before its scope, so a token for another of the auth server's
// permissions shows whether it is live: refused for its scope while it is, refused as a token once
// it is revoked.
test("a client credentials token belongs to no grant and is revoked on its own (section 2.1)", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const secret = await readClientSecret(page, client.id);
  const answer = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  const accessToken = answer.body.access_token as string;
  const listResources = () =>
    request.get(`${env.authUrl}/api/v1/admin/resources`, { headers: { Authorization: `Bearer ${accessToken}` }, failOnStatusCode: false });
  const live = await listResources();
  expect(live.status()).toBe(403);
  expect((await live.json()).error_code).toBe("INSUFFICIENT_SCOPE");

  expect(await revoke(request, client.identifier, secret, { token: accessToken })).toEqual({ status: 200, text: "" });

  const refused = await listResources();
  expect(refused.status()).toBe(401);
  expect(await refused.json()).toEqual({ error_code: "INVALID_TOKEN", error_description: "The access token is invalid." });

  await test.step("revoking it again is answered as any invalid token (section 2.2)", async () => {
    expect(await revoke(request, client.identifier, secret, { token: accessToken })).toEqual({ status: 200, text: "" });
  });
});
