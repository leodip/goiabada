// Refresh token rotation (Token endpoint, "Refresh token"): every refresh hands back a new refresh
// token and retires the one sent, and a retired one presented again is taken as a replay, which
// revokes its whole rotation family.
import { expect, test } from "../../lib/fixtures";
import { testRedirectUri, signInThroughClient } from "../../lib/browser-sign-in";
import { codeToken, refreshToken } from "../../lib/oauth";
import { browserSignInClient } from "../../lib/test-clients";

test("a refresh token already rotated is refused, and revokes the one that replaced it", async ({ page, browser, request, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, {
    clientId: client.identifier,
    email: user.email,
    password: user.password,
    scope: "openid",
  });
  await signIn.context.close();
  const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  const first = tokens.body.refresh_token as string;

  const rotated = await refreshToken(request, client.identifier, secret, first);
  expect(rotated.status, JSON.stringify(rotated.body)).toBe(200);
  const second = rotated.body.refresh_token as string;
  expect(second).toBeTruthy();
  expect(second).not.toBe(first);

  const replay = await refreshToken(request, client.identifier, secret, first);
  expect(replay.status).toBe(400);
  expect(replay.body).toMatchObject({ error: "invalid_grant", error_description: "This refresh token has been revoked." });
  // The replay revoked the family, the token the client holds now included.
  const after = await refreshToken(request, client.identifier, secret, second);
  expect(after.status).toBe(400);
  expect(after.body.error).toBe("invalid_grant");
});

test("a refresh token works only for the client it was issued to", async ({ page, browser, request, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const other = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, {
    clientId: client.identifier,
    email: user.email,
    password: user.password,
    scope: "openid",
  });
  await signIn.context.close();
  const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);

  const stolen = await refreshToken(request, other.client.identifier, other.secret, tokens.body.refresh_token as string);
  expect(stolen.status).toBe(400);
  expect(stolen.body.error).toBe("invalid_grant");
  // The rightful client still refreshes with it.
  const own = await refreshToken(request, client.identifier, secret, tokens.body.refresh_token as string);
  expect(own.status, JSON.stringify(own.body)).toBe(200);
});
