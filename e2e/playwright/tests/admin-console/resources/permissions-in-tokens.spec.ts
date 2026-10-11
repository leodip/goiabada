// What a resource's permissions mean outside the Resources pages: a client granted one gets it in its
// tokens, and renaming, removing or deleting on the Resources pages changes what the token endpoint
// issues.
import {
  clientUrl,
  deleteResource,
  grantClientPermission,
  readClientSecret,
  resourcePermissionRow,
  resourceUrl,
  saveResourcePermissions,
  addResourcePermission,
} from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken, jwtClaims } from "../../../lib/oauth";

test("a client granted a resource's permission gets it in a token, with the resource as audience", async ({
  page,
  request,
  clients,
  resources,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const secret = await readClientSecret(page, client.id);

  const granted = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:read`);
  expect(granted.status, JSON.stringify(granted.body)).toBe(200);
  expect(granted.body.scope).toBe(`${resource.identifier}:read`);
  const claims = jwtClaims(granted.body.access_token as string);
  expect(claims.aud).toBe(resource.identifier);
  expect(claims.scope).toBe(`${resource.identifier}:read`);

  // The other permission of the same resource was never granted.
  const notGranted = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:write`);
  expect(notGranted.body.error).toBe("invalid_scope");
});

test("renaming a permission carries the grant over to the new name", async ({ page, request, clients, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const secret = await readClientSecret(page, client.id);

  await page.goto(resourceUrl(resource.id, "permissions"));
  await resourcePermissionRow(page, "read").getByRole("cell").nth(2).getByRole("button").click();
  await page.locator("#permissionIdentifier").fill("view");
  const validated = page.waitForResponse((r) => r.url().endsWith("/admin/resources/validate-permission"));
  await page.getByRole("button", { name: "Update permission" }).click();
  await validated;
  await saveResourcePermissions(page);

  const renamed = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:view`);
  expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
  const old = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:read`);
  expect(old.body.error).toBe("invalid_scope");

  await page.goto(clientUrl(client.id, "permissions"));
  await expect(page.locator("#permissionsTable")).toContainText(`${resource.identifier}:view`);
});

test("removing a permission from its resource takes it from the clients that held it", async ({
  page,
  request,
  clients,
  resources,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const secret = await readClientSecret(page, client.id);

  await page.goto(resourceUrl(resource.id, "permissions"));
  await resourcePermissionRow(page, "read").getByRole("cell").nth(3).getByRole("button").click();
  await saveResourcePermissions(page);

  const answer = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:read`);
  expect(answer.body.error).toBe("invalid_scope");
  await page.goto(clientUrl(client.id, "permissions"));
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:read`);
});

test("a permission added later can be granted at once", async ({ page, request, clients, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "audit");
  await saveResourcePermissions(page);

  await grantClientPermission(page, client.id, resource.identifier, "audit");
  const secret = await readClientSecret(page, client.id);
  const answer = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:audit`);
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
});

test("deleting a resource takes its permissions from the clients that held them", async ({
  page,
  request,
  clients,
  resources,
}) => {
  const resource = await resources.create({ permissions: ["read"] });
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, resource.identifier, "read");
  const secret = await readClientSecret(page, client.id);

  await deleteResource(page, resource.id);
  resource.markDeleted();

  const answer = await clientCredentialsToken(request, client.identifier, secret, `${resource.identifier}:read`);
  expect(answer.body.error).toBe("invalid_scope");
  await page.goto(clientUrl(client.id, "permissions"));
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:read`);
});
