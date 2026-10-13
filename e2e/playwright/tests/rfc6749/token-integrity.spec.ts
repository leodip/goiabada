// RFC 6749 sections 10.3 and 10.10: tokens cannot be generated, modified or guessed into valid ones,
// and generated credentials are guessable with probability at most 2^-128. The access token is a
// signed JWT, so /userinfo, the auth server's own protected resource, is where a forged one is tried.
// The entropy checks are evidence from the outside only: length and spread, not randomness.
import { createSign, generateKeyPairSync } from "node:crypto";
import { readClientSecret } from "../../lib/admin-console";
import { signInThroughClient } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { userinfo, userTokens } from "../../lib/oauth";
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
