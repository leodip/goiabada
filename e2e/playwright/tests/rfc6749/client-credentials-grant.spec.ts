// RFC 6749 section 4.4, the client credentials grant: confidential clients only, authenticated, for a
// scope the client holds (3.3), and no refresh token (4.4.3). Both authentication methods, a missing
// one and an omitted scope are in token-endpoint.spec.ts; a client without the grant enabled is in
// ../admin-console/clients/token-endpoint.spec.ts.
import { clientUrl, confirmDialog, grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { expect, test } from "../../lib/fixtures";
import { jwtClaims } from "../../lib/oauth";
import { basicAuth, expectTokenError, expectTokenResponse, postToken } from "../../lib/rfc6749";

test("a client gets a token for a scope it holds, with no refresh token; any other scope is invalid_scope", async ({
  page,
  clients,
  resources,
  request,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const basic = { headers: { Authorization: basicAuth(client.identifier, await readClientSecret(page, client.id)) } };

  const granted = await postToken(request, { grant_type: "client_credentials", scope: `${resource.identifier}:read` }, basic);
  expectTokenResponse(granted);
  // Section 4.4.3: a refresh token SHOULD NOT be included.
  expect(granted.body.refresh_token).toBeUndefined();

  for (const scope of [`${resource.identifier}:write`, `${resource.identifier}:delete`, "no-such-resource:read", "openid"]) {
    await test.step(scope, async () => {
      expectTokenError(await postToken(request, { grant_type: "client_credentials", scope }, basic), "invalid_scope");
    });
  }
});

test("a public client cannot use the client credentials grant (section 4.4 MUST)", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: true, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Public", exact: true }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();

  const answer = await postToken(request, { grant_type: "client_credentials", scope: "authserver:manage-account", client_id: client.identifier });
  expectTokenError(answer, ["unauthorized_client", "invalid_client"], answer.status === 401 ? 401 : 400);
});

test("a client authenticated as itself gets no token for another client named in the body", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  const other = await clients.create({ authorizationCode: false, clientCredentials: true });
  for (const c of [client, other]) await grantClientPermission(page, c.id, "authserver", "manage-account");
  const secret = await readClientSecret(page, client.id);

  const answer = await postToken(
    request,
    { grant_type: "client_credentials", scope: "authserver:manage-account", client_id: other.identifier },
    { headers: { Authorization: basicAuth(client.identifier, secret) } },
  );
  // Refused, or a token for the authenticated client: never one for the client the body names.
  if (answer.status === 200) {
    const claims = JSON.stringify(jwtClaims(answer.body.access_token as string));
    expect(claims).toContain(client.identifier);
    expect(claims).not.toContain(other.identifier);
  } else {
    expectTokenError(answer, ["invalid_request", "invalid_client"], answer.status === 401 ? 401 : 400);
  }
});
