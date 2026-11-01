// RFC 6749 section 4.3, the resource owner password credentials grant: the client authenticates when
// it can, the user's credentials are checked, and the scope follows section 3.3. Its brute-force
// protection, which 4.3.2 makes a MUST, is ../../rate-limits/sign-ins-from-one-address.spec.ts; UTF-8 in a
// password is in token-endpoint.spec.ts.
import {
  clientUrl,
  grantUserPermission,
  publishLegalDocument,
  retireLegalDocument,
  setLegalDocumentApps,
} from "../../lib/admin-console";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, expectInvalidClient, expectTokenError, expectTokenResponse, postToken } from "../../lib/rfc6749";
import { passwordGrantClient } from "../../lib/test-clients";

test("the right credentials get tokens; a missing one is invalid_request, a wrong password or unknown user invalid_grant", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const basic = { headers: { Authorization: basicAuth(client.identifier, secret) } };
  const grant = (form: Record<string, string>) => postToken(request, { grant_type: "password", scope: "openid", ...form }, basic);

  expectTokenResponse(await grant({ username: user.email, password: user.password }));
  expectTokenError(await grant({ password: user.password }), "invalid_request");
  expectTokenError(await grant({ username: user.email }), "invalid_request");
  expectTokenError(await grant({ username: user.email, password: `${user.password}x` }), "invalid_grant");
  expectTokenError(await grant({ username: `nobody-${user.email}`, password: user.password }), "invalid_grant");
});

test("a confidential client must authenticate, and a client without the grant enabled is unauthorized_client", async ({
  page,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const form = { grant_type: "password", username: user.email, password: user.password, scope: "openid" };

  // Section 4.3.2 MUST: client authentication for a confidential client.
  expectInvalidClient(await postToken(request, { ...form, client_id: client.identifier }), { viaBasic: false });

  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await page.locator('input[name="ropcEnabled"][value="off"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("OAuth2 flows saved.")).toBeVisible();
  expectTokenError(await postToken(request, form, { headers: { Authorization: basicAuth(client.identifier, secret) } }), "unauthorized_client");
});

test("an unknown scope is invalid_scope; a scope the user does not hold is refused or left out, and the answer names what was granted", async ({
  page,
  clients,
  resources,
  users,
  request,
}) => {
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read", "write"] });
  await grantUserPermission(page, user.id, resource.identifier, "read");
  const { client, secret } = await passwordGrantClient(page, clients);
  const grant = (scope?: string) =>
    postToken(
      request,
      { grant_type: "password", username: user.email, password: user.password, ...(scope ? { scope } : {}) },
      { headers: { Authorization: basicAuth(client.identifier, secret) } },
    );

  expectTokenError(await grant("openid no-such-resource:read"), "invalid_scope");

  // Section 3.3: the server MAY ignore part of the scope, and MUST then say what it granted.
  const partly = await grant(`openid ${resource.identifier}:read ${resource.identifier}:write`);
  if (partly.status === 200) {
    expectTokenResponse(partly);
    expect(String(partly.body.scope).split(" ").sort()).toEqual(["openid", `${resource.identifier}:read`].sort());
  } else {
    expectTokenError(partly, "invalid_scope");
  }

  // Omitted: the documented default, named in the answer since nothing was asked for.
  const omitted = await grant();
  expectTokenResponse(omitted);
  expect(omitted.body.scope).toBe("openid");
});

// A user who owes the acceptance step a legal document for the client (#622) is refused invalid_grant,
// the grant being unable to show the step, and told to accept it in a browser. Once nothing is owed,
// here because the document is retired, the grant works again. The document is set to the test's own
// client before it is published, so no other test's sign-in owes it.
test("a user who owes a legal document for the client is refused invalid_grant", async ({ page, clients, users, legalDocuments, request }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice." });
  await setLegalDocumentApps(page, doc.id, [client.identifier]);
  await publishLegalDocument(page, doc.id);
  const grant = () =>
    postToken(
      request,
      { grant_type: "password", username: user.email, password: user.password, scope: "openid" },
      { headers: { Authorization: basicAuth(client.identifier, secret) } },
    );

  const refused = await grant();
  expectTokenError(refused, "invalid_grant");
  expect(refused.body.error_description).toBe(
    "The user has not accepted a legal document this app requires. Sign in to the app in a browser to accept it, then try again.",
  );

  await retireLegalDocument(page, doc.id);
  expectTokenResponse(await grant());
});
