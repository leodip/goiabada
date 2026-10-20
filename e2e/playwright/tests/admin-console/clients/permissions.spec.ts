import { addPermissionRow, clientUrl, expectFieldError, readClientSecret } from "../../../lib/admin-console";
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
  const none = page.getByText("No permissions granted yet.");

  // Not granted yet: the token endpoint refuses the scope.
  const before = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(before.status).toBe(400);
  expect(before.body.error).toBe("invalid_scope");

  await page.goto(clientUrl(client.id, "permissions"));
  await expect(none).toBeVisible();
  await addPermissionRow(page, "authserver", "manage-account");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
  await page.reload();
  await expect(table).toContainText(permission);

  const granted = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(granted.status, JSON.stringify(granted.body)).toBe(200);
  expect(granted.body.token_type).toBe("Bearer");
  const claims = jwtClaims(String(granted.body.access_token));
  expect(String(claims.scope).split(" ")).toContain(permission);

  await table.getByRole("button", { name: `Remove ${permission}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
  await page.reload();
  await expect(none).toBeVisible();

  const after = await clientCredentialsToken(request, client.identifier, secret, permission);
  expect(after.body.error).toBe("invalid_scope");
});

// The seeded authserver resource and its manage-account permission, whose description is longer than
// a choice's label holds.
test("a chosen resource's and permission's descriptions show whole beneath their fields", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "permissions"));
  const resources = page.locator("#resourcesSelect");
  const loaded = page.waitForResponse((r) => r.url().includes("/admin/get-permissions"));
  await resources.selectOption((await resources.locator('option[data-resource-identifier="authserver"]').getAttribute("value"))!);
  await loaded;
  await expect(page.locator("#resourcesSelect-description")).toHaveText("Authorization server (system-level)");

  const permissions = page.locator("#permissionsSelect");
  const option = permissions.locator('option[data-permission-identifier="manage-account"]');
  await expect(option).toHaveText(/^manage-account – View and update user account data .*…$/);
  await permissions.selectOption((await option.getAttribute("value"))!);
  await expect(page.locator("#permissionsSelect-description")).toHaveText("View and update user account data for the current user");
});

test("Grant with no permission chosen is refused at the permission field", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "permissions"));
  await page.locator("#grantPermissionBtn").click();
  await expectFieldError(page, "permissionsSelect", "Choose a permission to grant.");
  await expect(page.getByText("No permissions granted yet.")).toBeVisible();
});

test("the same permission cannot be granted twice", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "permissions"));
  await addPermissionRow(page, "authserver", "manage-account");
  await addPermissionRow(page, "authserver", "manage-account");
  await expectFieldError(page, "permissionsSelect", "The client already has that permission.");
  await expect(page.locator("#permissionsTable").getByRole("row").filter({ hasText: permission })).toHaveCount(1);
});

test("a client without the client credentials flow has no permissions to manage", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "permissions"));
  await expect(page.getByText(/^A client's permissions are scopes it gets with the client credentials flow\./)).toBeVisible();
  await expect(page.locator("#resourcesSelect")).toHaveCount(0);
});
