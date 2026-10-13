// RFC 9700 sections 2.3 and 4.10.2, access token privilege restriction. A token should carry no more
// than the use it was asked for, and be audience-restricted to the resource servers it is for; a
// resource server must refuse a token not meant for it. Goiabada's access tokens name as audience the
// resources of their scope, and authserver for a claim scope, which /userinfo answers; the auth
// server is itself the resource server of /userinfo and its two APIs. Sender-constrained tokens
// (2.2.1, 4.10.1) are not implemented, and not tested.
import { grantClientPermission, grantUserPermission, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken, jwtClaims } from "../../lib/oauth";
import { basicAuth, expectTokenResponse, postToken } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

const audiences = (claims: Record<string, unknown>) => [claims.aud].flat().map(String).sort();

test("an access token carries only the scope asked for, and names as audience only the resources in it (section 2.3)", async ({
  page,
  browser,
  clients,
  resources,
  users,
  request,
}) => {
  const a = await resources.create({ permissions: ["read", "write"] });
  const b = await resources.create({ permissions: ["read"] });

  await test.step("a client's own token, though it holds more", async () => {
    const client = await clients.create({ authorizationCode: false, clientCredentials: true });
    for (const [resource, permission] of [
      [a.identifier, "read"],
      [a.identifier, "write"],
      [b.identifier, "read"],
    ]) {
      await grantClientPermission(page, client.id, resource, permission);
    }
    const secret = await readClientSecret(page, client.id);
    const answer = await postToken(
      request,
      { grant_type: "client_credentials", scope: `${a.identifier}:read` },
      { headers: { Authorization: basicAuth(client.identifier, secret) } },
    );
    expectTokenResponse(answer);
    const claims = jwtClaims(answer.body.access_token as string);
    expect(claims.scope).toBe(`${a.identifier}:read`);
    expect(audiences(claims)).toEqual([a.identifier]);
  });

  await test.step("a user's token, though the user holds more", async () => {
    const user = await users.create();
    await grantUserPermission(page, user.id, a.identifier, "read");
    await grantUserPermission(page, user.id, b.identifier, "read");
    const { client, secret } = await browserSignInClient(page, clients);
    const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: `openid ${a.identifier}:read` });
    await signIn.context.close();
    const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
    expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
    const claims = jwtClaims(tokens.body.access_token as string);
    expect(String(claims.scope).split(" ").sort()).toEqual([`${a.identifier}:read`, "openid"].sort());
    expect(audiences(claims)).toEqual(["authserver", a.identifier].sort());
  });
});

test("the auth server's own endpoints refuse an access token meant for another resource (sections 2.3, 4.10.2)", async ({
  page,
  clients,
  resources,
  request,
}) => {
  const resource = await resources.create({ permissions: ["read"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const answer = await postToken(
    request,
    { grant_type: "client_credentials", scope: `${resource.identifier}:read` },
    { headers: { Authorization: basicAuth(client.identifier, await readClientSecret(page, client.id)) } },
  );
  expectTokenResponse(answer);
  const bearer = { Authorization: `Bearer ${answer.body.access_token as string}` };
  expect(audiences(jwtClaims(answer.body.access_token as string))).toEqual([resource.identifier]);

  for (const path of ["/userinfo", "/api/v1/admin/clients", "/api/v1/account/profile"]) {
    await test.step(path, async () => {
      const refused = await request.get(`${env.authUrl}${path}`, { headers: bearer, failOnStatusCode: false });
      expect([401, 403], `${path} answered ${refused.status()}`).toContain(refused.status());
    });
  }
});
