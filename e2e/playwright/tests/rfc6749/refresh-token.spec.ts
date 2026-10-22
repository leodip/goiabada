// RFC 6749 section 6, refreshing an access token: the refresh token is bound to its client and
// authenticated with it (6, 10.4), its scope can be narrowed but never widened, and the refresh token
// that replaces it keeps the scope it had (6). Rotation, the replay of a rotated token, and a refresh
// token presented by another client are in ../oauth/refresh-tokens.spec.ts.
import type { APIRequestContext, Browser } from "@playwright/test";
import { confirmDialog, grantUserPermission, userUrl } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { jwtClaims, userinfo } from "../../lib/oauth";
import { basicAuth, expectInvalidClient, expectTokenError, expectTokenResponse, postToken } from "../../lib/rfc6749";
import { browserSignInClient, publicSignInClient } from "../../lib/test-clients";

// A user's tokens through the authorization code flow, the way a refresh token is usually issued. A
// client with a secret authenticates with it; one without names itself with client_id.
async function tokensFor(
  browser: Browser,
  request: APIRequestContext,
  client: { identifier: string; secret?: string },
  user: { email: string; password: string },
  scope = "openid",
) {
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope });
  await signIn.context.close();
  const form = { grant_type: "authorization_code", code: signIn.code, code_verifier: signIn.codeVerifier, redirect_uri: testRedirectUri };
  const answer = client.secret
    ? await postToken(request, form, { headers: { Authorization: basicAuth(client.identifier, client.secret) } })
    : await postToken(request, { ...form, client_id: client.identifier });
  expectTokenResponse(answer);
  expect(answer.body.refresh_token, "a refresh token was issued").toBeTruthy();
  return answer.body;
}

const scopeOf = (accessToken: unknown) => String(jwtClaims(accessToken as string).scope).split(" ").sort();

test("a refresh token gets new tokens; missing, garbled, altered or presented without client authentication it is refused", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const tokens = await tokensFor(browser, request, { identifier: client.identifier, secret }, user);
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };

  const refreshed = await postToken(request, { grant_type: "refresh_token", refresh_token: tokens.refresh_token as string }, basic);
  expectTokenResponse(refreshed);
  const current = refreshed.body.refresh_token as string;

  expectTokenError(await postToken(request, { grant_type: "refresh_token" }, basic), "invalid_request");
  expectTokenError(await postToken(request, { grant_type: "refresh_token", refresh_token: "not-a-refresh-token" }, basic), "invalid_grant");
  // Section 10.4 MUST: a refresh token cannot be modified into a valid one. One character of its
  // payload changed, so its signature no longer covers it.
  const at = current.indexOf(".") + 8;
  const altered = `${current.slice(0, at)}${current[at] === "A" ? "B" : "A"}${current.slice(at + 1)}`;
  expectTokenError(await postToken(request, { grant_type: "refresh_token", refresh_token: altered }, basic), "invalid_grant");
  // Section 6 MUST: a confidential client authenticates; naming itself is not enough.
  expectInvalidClient(
    await postToken(request, { grant_type: "refresh_token", refresh_token: current, client_id: client.identifier }),
    { viaBasic: false },
  );

  // None of those spent it.
  expectTokenResponse(await postToken(request, { grant_type: "refresh_token", refresh_token: current }, basic));
});

test("a refresh may narrow the scope but never widen it, and the refresh token it issues keeps the original scope", async ({
  page,
  browser,
  clients,
  resources,
  users,
  request,
}) => {
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read", "write"] });
  await grantUserPermission(page, user.id, resource.identifier, "read");
  await grantUserPermission(page, user.id, resource.identifier, "write");
  const { client, secret } = await browserSignInClient(page, clients);
  const full = ["openid", `${resource.identifier}:read`, `${resource.identifier}:write`].sort();
  const tokens = await tokensFor(browser, request, { identifier: client.identifier, secret }, user, full.join(" "));
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };
  const refresh = (token: unknown, scope?: string) =>
    postToken(request, { grant_type: "refresh_token", refresh_token: token as string, ...(scope ? { scope } : {}) }, basic);

  // Omitted: treated as the scope originally granted.
  const same = await refresh(tokens.refresh_token);
  expectTokenResponse(same);
  expect(scopeOf(same.body.access_token)).toEqual(full);

  // Narrower: honoured, and named in the answer since it differs from the grant.
  const narrow = `openid ${resource.identifier}:read`;
  const narrowed = await refresh(same.body.refresh_token, narrow);
  expectTokenResponse(narrowed);
  expect(String(narrowed.body.scope).split(" ").sort()).toEqual(narrow.split(" ").sort());
  expect(scopeOf(narrowed.body.access_token)).toEqual(narrow.split(" ").sort());

  // Section 6 MUST: the refresh token issued then has the scope of the one presented, the full one.
  const restored = await refresh(narrowed.body.refresh_token);
  expectTokenResponse(restored);
  expect(scopeOf(restored.body.access_token)).toEqual(full);

  // Section 6 MUST NOT: nothing the user did not originally grant.
  expectTokenError(await refresh(restored.body.refresh_token, "openid email"), "invalid_scope");
});

test("a public client refreshes with its client_id; without one, or with another public client's, it is refused", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  const other = await publicSignInClient(page, clients);
  const tokens = await tokensFor(browser, request, { identifier: client.identifier }, user);
  const form = { grant_type: "refresh_token", refresh_token: tokens.refresh_token as string };

  expectTokenError(await postToken(request, form), ["invalid_request", "invalid_client"]);
  // Section 10.4 MUST: the binding to the client it was issued to holds for a public client too.
  expectTokenError(await postToken(request, { ...form, client_id: other.identifier }), "invalid_grant");
  expectTokenResponse(await postToken(request, { ...form, client_id: client.identifier }));
});

test("a refresh token is no access token: /userinfo refuses it as a bearer (section 1.5)", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const tokens = await tokensFor(browser, request, { identifier: client.identifier, secret }, user);

  expect((await userinfo(request, tokens.access_token as string)).status).toBe(200);
  expect((await userinfo(request, tokens.refresh_token as string)).status).toBe(401);
});

test("a disabled user's refresh token is refused", async ({ page, browser, clients, users, request }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const tokens = await tokensFor(browser, request, { identifier: client.identifier, secret }, user);

  await page.goto(userUrl(user.id, "details"));
  await page.locator("#enabledDisabled").uncheck();
  // Disabling asks first.
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're disabling the user");
  await expect(page.getByText("Changes saved.")).toBeVisible();

  const refused = await postToken(
    request,
    { grant_type: "refresh_token", refresh_token: tokens.refresh_token as string },
    { headers: { Authorization: basicAuth(client.identifier, secret) } },
  );
  expectTokenError(refused, "invalid_grant");
});
