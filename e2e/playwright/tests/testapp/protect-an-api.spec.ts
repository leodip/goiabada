// Protect an API, through the test app's API (/api/products) and its service: the API checks each
// token on its own against the auth server's public keys, requiring the at+jwt header as RFC 9068
// section 4 asks, so every answer of 200 here is also a token the auth server issued as one, and
// answers 401 or 403.
import { grantUserPermission } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, shownClaims, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

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
  expect(none.headers()["www-authenticate"]).toBe(`Bearer realm="${testapp.api.resource}"`);

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
