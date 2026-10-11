import { addPermissionRow, clientUrl, expectErrorDialog, readClientSecret } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken, jwtClaims } from "../../../lib/oauth";

// authserver:manage-account is not one of the administrative scopes, so any client may hold it.
const permission = "authserver:manage-account";


test("a granted permission is saved, gets a token with that scope, and once removed is refused", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  const secret = await readClientSecret(page, client.id);
  const table = page.locator("#permissionsTable");

  // Not granted yet: the token endpoint refuses the scope.
  const before = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(before.status).toBe(400);
  expect(before.body.error).toBe("invalid_scope");

  await page.goto(clientUrl(client.id, "permissions"));
  await expect(table).toContainText("(none yet)");
  await addPermissionRow(page, "authserver", "manage-account");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client permissions saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText(permission);

  const granted = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(granted.status, JSON.stringify(granted.body)).toBe(200);
  expect(granted.body.token_type).toBe("Bearer");
  const claims = jwtClaims(String(granted.body.access_token));
  expect(String(claims.scope).split(" ")).toContain(permission);

  await table.getByRole("row").filter({ hasText: permission }).getByRole("button").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client permissions saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText("(none yet)");

  const after = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(after.body.error).toBe("invalid_scope");
});

test("the same permission cannot be granted twice", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "permissions"));
  await addPermissionRow(page, "authserver", "manage-account");
  await addPermissionRow(page, "authserver", "manage-account");
  await expectErrorDialog(page, "The permission is already in the list.");
  await expect(page.locator("#permissionsTable").getByRole("row").filter({ hasText: permission })).toHaveCount(1);
});

test("a client without the client credentials flow has no permissions to manage", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "permissions"));
  await expect(page.getByText(/^Client permissions can only be configured within the context of the/)).toBeVisible();
  await expect(page.locator("#resourcesSelect")).toBeHidden();
});
