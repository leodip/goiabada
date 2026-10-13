// RFC 6749 section 3.3 and Appendix A.4, the scope parameter: case-sensitive values whose order does
// not matter, separated by single spaces, each of printable ASCII but '"' and '\'. Malformed, it is
// invalid_scope at both endpoints (4.1.2.1, 5.2). What an omitted scope means on each grant is in
// token-endpoint, password-grant and authorization-request.spec.ts.
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { signInThroughClient } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, codeRequest, expectAuthorizeError, expectTokenError, expectTokenResponse, followAuthorize, postToken } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

test("at the token endpoint scope values are case-sensitive, their order does not matter, and a malformed scope is invalid_scope", async ({
  page,
  clients,
  resources,
  request,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  await grantClientPermission(page, client.id, resource.identifier, "write");
  const basic = { headers: { Authorization: basicAuth(client.identifier, await readClientSecret(page, client.id)) } };
  const read = `${resource.identifier}:read`;
  const write = `${resource.identifier}:write`;
  const token = (scope: string) => postToken(request, `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`, basic);

  const forward = await token(`${read} ${write}`);
  expectTokenResponse(forward);
  const backward = await token(`${write} ${read}`);
  expectTokenResponse(backward);
  expect(String(backward.body.scope).split(" ").sort()).toEqual(String(forward.body.scope).split(" ").sort());

  // A value sent twice adds nothing: refused, or granted once.
  const repeated = await token(`${read} ${read}`);
  if (repeated.status === 200) expect(String(repeated.body.scope).split(" ")).toEqual([read]);
  else expectTokenError(repeated, "invalid_scope");

  for (const malformed of [
    read.toUpperCase(),
    `${read}  ${write}`,
    ` ${read}`,
    `${read} `,
    `${read}\t${write}`,
    `${read} "${write}"`,
    `${read} ${write}\\`,
    `${read} café`,
  ]) {
    await test.step(JSON.stringify(malformed), async () => {
      expectTokenError(await token(malformed), "invalid_scope");
    });
  }
});

test("at the authorization endpoint a malformed or miscased scope is invalid_scope at the redirect URI", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  for (const malformed of ["OPENID", "openid  email", "openid ", "openid\temail", 'openid "email"']) {
    await test.step(JSON.stringify(malformed), async () => {
      const { params } = codeRequest(client.identifier, { scope: malformed });
      const { redirect } = await followAuthorize(signIn.context.request, params);
      expect(redirect, "answered at the redirect URI").toBeDefined();
      expectAuthorizeError(redirect!, "invalid_scope", params.state);
    });
  }

  // The same values well formed, in either order, are granted.
  for (const scope of ["openid email", "email openid"]) {
    const { redirect } = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { scope }).params);
    expect(redirect?.searchParams.get("code"), redirect?.href).toBeTruthy();
  }
  await signIn.context.close();
});
