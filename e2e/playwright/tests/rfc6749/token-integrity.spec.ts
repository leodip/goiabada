// RFC 6749 sections 10.3 and 10.10: tokens cannot be generated, modified or guessed into valid ones,
// and generated credentials are guessable with probability at most 2^-128. The access token is a
// signed JWT, so /userinfo, the auth server's own protected resource, is where a forged one is tried.
// The entropy checks are evidence from the outside only: length and spread, not randomness.
//
// A real token altered only in its serialization keeps a good signature, and is refused all the same
// (#709): the compact serialization is unpadded base64url with no line breaks (RFC 7515 sections 2
// and 5.2), and every endpoint that reads a token answers such a one as it answers a token that is
// no JWT at all.
import type { APIRequestContext } from "@playwright/test";
import { createSign, generateKeyPairSync } from "node:crypto";
import { addIntrospectionResource, clientUrl, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient } from "../../lib/browser-sign-in";
import { authServerDPoPChallenge } from "../../lib/dpop";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { refreshToken, userinfo, userTokens } from "../../lib/oauth";
import { codeRequest, followAuthorize } from "../../lib/rfc6749";
import { browserSignInClient, passwordGrantClient } from "../../lib/test-clients";

const b64 = (value: object | Buffer) => (Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value))).toString("base64url");
const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;

test("/userinfo refuses an access token altered, unsigned, signed with alg none, or signed by another key (section 10.3)", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const other = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const token = (await userTokens(request, client.identifier, secret, user, "openid")).body.access_token as string;
  const otherSubject = (await userTokens(request, client.identifier, secret, other, "openid")).access.sub as string;
  const [header, payload, signature] = token.split(".");
  expect((await userinfo(request, token)).status).toBe(200);

  const someoneElse = b64({ ...decode(payload), sub: otherSubject });
  const foreignKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const signedElsewhere = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(foreignKey);
  for (const [what, forged] of [
    ["another user's subject, the signature kept", `${header}.${someoneElse}.${signature}`],
    ["the signature stripped", `${header}.${payload}.`],
    ["alg none", `${b64({ ...decode(header), alg: "none" })}.${payload}.`],
    ["signed by a key not the server's, under its kid", `${header}.${payload}.${b64(signedElsewhere)}`],
  ]) {
    await test.step(what, async () => {
      expect((await userinfo(request, forged)).status).toBe(401);
    });
  }
});

// What a bearer-guarded endpoint answered: status, challenge and body, compared whole.
async function bearerAnswer(request: APIRequestContext, method: "GET" | "POST", path: string, options: { token?: string; form?: string } = {}) {
  const response = await request.fetch(`${env.authUrl}${path}`, {
    method,
    headers: options.token === undefined ? {} : { Authorization: `Bearer ${options.token}` },
    form: options.form === undefined ? undefined : { access_token: options.form },
    failOnStatusCode: false,
  });
  return { status: response.status(), challenge: response.headers()["www-authenticate"], body: await response.text() };
}

test("/userinfo and the account API refuse a real access token with = padding added, sent in the Authorization header (#709)", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const token = (await userTokens(request, client.identifier, secret, user, "openid authserver:manage-account")).body.access_token as string;
  const [header, payload, signature] = token.split(".");

  for (const path of ["/userinfo", "/api/v1/account/profile"]) {
    await test.step(path, async () => {
      expect((await bearerAnswer(request, "GET", path, { token })).status, "the unaltered token is accepted").toBe(200);
      const malformed = await bearerAnswer(request, "GET", path, { token: "not-a-token" });
      expect(malformed.status).toBe(401);
      expect(malformed.challenge).toBe(`Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid.", ${authServerDPoPChallenge}`);
      for (const padded of [`${token}=`, `${token}==`, `${header}.${payload}=.${signature}`]) {
        expect(await bearerAnswer(request, "GET", path, { token: padded }), padded.slice(-8)).toEqual(malformed);
      }
    });
  }
});

test("a real token with a line break added, sent in a form body, is refused at /userinfo, at introspection and at the refresh grant (#709)", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = (await userTokens(request, client.identifier, secret, user, "openid")).body;
  const accessToken = tokens.access_token as string;
  const refresh = tokens.refresh_token as string;
  const api = await clients.create();
  await page.goto(clientUrl(api.id, "introspection"));
  await addIntrospectionResource(page, "authserver");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Introspection resources saved.")).toBeVisible();
  const apiBasic = `Basic ${Buffer.from(`${encodeURIComponent(api.identifier)}:${encodeURIComponent(await readClientSecret(page, api.id))}`).toString("base64")}`;
  const introspect = async (token: string) =>
    (await request.post(`${env.authUrl}/auth/introspect`, { form: { token }, headers: { Authorization: apiBasic } })).json();

  // HTTP refuses CR and LF in a header field, so only a form body carries the token to the parser.
  const broken = (token: string) => [`${token}\n`, `${token}\r\n`, `${token.slice(0, -20)}\n${token.slice(-20)}`];

  await test.step("/userinfo", async () => {
    const malformed = await bearerAnswer(request, "POST", "/userinfo", { form: "not-a-token" });
    expect(malformed.status).toBe(401);
    expect(malformed.challenge).toBe(`Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid.", ${authServerDPoPChallenge}`);
    for (const token of broken(accessToken)) expect(await bearerAnswer(request, "POST", "/userinfo", { form: token })).toEqual(malformed);
    expect((await bearerAnswer(request, "POST", "/userinfo", { form: accessToken })).status, "the unaltered token is accepted").toBe(200);
  });

  await test.step("introspection", async () => {
    for (const token of broken(accessToken)) expect(await introspect(token)).toEqual({ active: false });
    expect((await introspect(accessToken)).active, "the unaltered token is active").toBe(true);
  });

  await test.step("the refresh grant", async () => {
    for (const token of broken(refresh)) {
      const refused = await refreshToken(request, client.identifier, secret, token);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_grant");
      expect(refused.body.error_description).toBe("The refresh token is invalid.");
    }
    const refreshed = await refreshToken(request, client.identifier, secret, refresh);
    expect(refreshed.status, "the unaltered refresh token still refreshes: a malformed one revokes nothing").toBe(200);
  });
});

test("authorization codes and client secrets are long and never repeat (section 10.10)", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const second = await clients.create();
  const otherSecret = await readClientSecret(page, second.id);

  // 128 bits take at least 22 characters of a 64-character alphabet.
  for (const value of [secret, otherSecret]) expect(value).toMatch(/^[\x21-\x7E]{22,}$/);
  expect(secret).not.toBe(otherSecret);

  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const codes = [signIn.code];
  for (let i = 0; i < 3; i++) {
    const { redirect } = await followAuthorize(signIn.context.request, codeRequest(client.identifier).params);
    codes.push(redirect!.searchParams.get("code")!);
  }
  await signIn.context.close();
  for (const code of codes) expect(code).toMatch(/^[\x21-\x7E]{22,}$/);
  expect(new Set(codes).size).toBe(codes.length);
});
