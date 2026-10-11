import {
  addPermissionRow,
  expectErrorDialog,
  grantGroupPermission,
  groupUrl,
  resourceUrl,
} from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

test("a permission is granted, shows on the resource's side, and is removed", async ({ page, groups, resources }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const group = await groups.create();
  const table = page.locator("#permissionsTable");

  await page.goto(groupUrl(group.id, "permissions"));
  await expect(table).toContainText("(none yet)");
  await grantGroupPermission(page, group.id, resource.identifier, "read");
  await page.reload();
  await expect(table).toContainText(`${resource.identifier}:read`);
  await expect(table).not.toContainText(`${resource.identifier}:write`);

  // The resource's Groups with permission tab agrees.
  await page.goto(resourceUrl(resource.id, "groups-with-permission"));
  const row = page.locator("#groupsTable tbody tr").filter({ has: page.getByRole("link", { name: group.identifier, exact: true }) });
  await expect(row.getByRole("cell").nth(2)).toHaveText("Yes");

  await page.goto(groupUrl(group.id, "permissions"));
  await table.getByRole("button", { name: `Remove permission ${resource.identifier}:read`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Group permissions saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText("(none yet)");
});

test("a permission already in the list is refused", async ({ page, groups, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const group = await groups.create();
  await grantGroupPermission(page, group.id, resource.identifier, "read");
  await addPermissionRow(page, resource.identifier, "read");
  await expectErrorDialog(page, "The permission is already in the list.");
});

test("a save from a page loaded before another save is refused, and changes nothing", async ({
  page,
  context,
  groups,
  resources,
}) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const group = await groups.create();
  const other = await context.newPage();
  await page.goto(groupUrl(group.id, "permissions"));
  await grantGroupPermission(other, group.id, resource.identifier, "read");
  await other.close();

  // This page still shows the list as it was before that save.
  await addPermissionRow(page, resource.identifier, "write");
  await page.locator("#btnSave").click();
  await expectErrorDialog(page, "The list was changed by another save after it was loaded.");

  await page.reload();
  await expect(page.locator("#permissionsTable")).toContainText(`${resource.identifier}:read`);
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:write`);
});
