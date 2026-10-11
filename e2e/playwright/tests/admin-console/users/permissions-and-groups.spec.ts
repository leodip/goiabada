import { addPermissionRow, expectErrorDialog, groupUrl, resourceUrl, rowWithCell, userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

const permissionsSaved = "Permissions saved successfully";

test("a permission granted to the user reaches their tokens, and is removed again", async ({
  page,
  request,
  clients,
  resources,
  users,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const scope = `openid ${resource.identifier}:read`;
  const table = page.locator("#permissionsTable");

  await page.goto(userUrl(user.id, "permissions"));
  // A new user holds authserver:manage-account, which every account needs for its own pages.
  await expect(table).toContainText("authserver:manage-account");
  await expect(table).not.toContainText(resource.identifier);
  await addPermissionRow(page, resource.identifier, "read");
  await page.locator("#btnSave").click();
  await expect(page.getByText(permissionsSaved)).toBeVisible();
  await page.reload();
  await expect(table).toContainText(`${resource.identifier}:read`);

  const tokens = await userTokens(request, client.identifier, secret, user, scope);
  expect(String(tokens.access.scope).split(" ")).toContain(`${resource.identifier}:read`);
  expect(tokens.access.aud).toContain(resource.identifier);
  // The resource's Users with permission tab lists the user.
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await expect(rowWithCell(page, user.email)).toHaveCount(1);

  await page.goto(userUrl(user.id, "permissions"));
  await table.getByRole("row").filter({ hasText: `${resource.identifier}:read` }).getByRole("button").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText(permissionsSaved)).toBeVisible();
  const answer = await passwordToken(request, client.identifier, secret, user.email, user.password, scope);
  expect(answer.body.error).toBe("invalid_scope");
});

test("a permission already in the list is refused", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(userUrl(user.id, "permissions"));
  await addPermissionRow(page, resource.identifier, "read");
  await addPermissionRow(page, resource.identifier, "read");
  await expectErrorDialog(page, "The permission is already in the list.");
});

test("a permissions save from a page loaded before another save is refused", async ({ page, context, resources, users }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const user = await users.create();
  const other = await context.newPage();
  await page.goto(userUrl(user.id, "permissions"));
  await other.goto(userUrl(user.id, "permissions"));
  await addPermissionRow(other, resource.identifier, "read");
  await other.locator("#btnSave").click();
  await expect(other.getByText(permissionsSaved)).toBeVisible();
  await other.close();

  await addPermissionRow(page, resource.identifier, "write");
  await page.locator("#btnSave").click();
  await expectErrorDialog(page, "The list was changed by another save after it was loaded.");
  await page.reload();
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:write`);
});

test("group membership is granted and removed from the user's side", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  const table = page.locator("#groupsTable");

  await page.goto(userUrl(user.id, "groups"));
  await expect(table).toContainText("(none yet)");
  await page.locator("#groupsSelect").selectOption({ label: group.identifier });
  await page.getByRole("button", { name: "Grant membership" }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Groups saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText(group.identifier);

  await page.goto(groupUrl(group.id, "members"));
  await expect(rowWithCell(page, user.email)).toHaveCount(1);

  await page.goto(userUrl(user.id, "groups"));
  await table.getByRole("row").filter({ hasText: group.identifier }).getByRole("button").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Groups saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText("(none yet)");
});

test("a group already in the list is refused", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  await page.goto(userUrl(user.id, "groups"));
  for (let i = 0; i < 2; i++) {
    await page.locator("#groupsSelect").selectOption({ label: group.identifier });
    await page.getByRole("button", { name: "Grant membership" }).click();
  }
  await expectErrorDialog(page, "The group is already in the list.");
});
