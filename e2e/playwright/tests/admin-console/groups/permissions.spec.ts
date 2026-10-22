import type { Page } from "@playwright/test";
import {
  addPermissionRow,
  addResourcePermission,
  expectFieldError,
  grantGroupPermission,
  groupUrl,
  resourceUrl,
  rowWithCell,
  saveResourcePermissions,
} from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

const empty = "No permissions granted yet.";

// The group's row on a resource's Groups with permission tab, for this permission. The tab lists
// every group, ten to a page, so the pages are walked to the one holding it.
async function groupWithPermissionRow(page: Page, resourceId: number, permission: string, group: string) {
  await page.goto(resourceUrl(resourceId, "groups-with-permission"));
  await page.getByLabel("Permission", { exact: true }).selectOption({ label: permission });
  await page.getByRole("button", { name: "Show", exact: true }).click();
  await expect(page).toHaveURL(/permission=\d+/);
  await page.waitForLoadState();
  for (;;) {
    const row = rowWithCell(page, group);
    if ((await row.count()) === 1) return row;
    const next = page.getByRole("link", { name: "Next page", exact: true });
    if ((await next.count()) === 0) throw new Error(`group ${group} not listed`);
    // Followed by its address, so the next look is at the page it leads to.
    await page.goto(new URL((await next.getAttribute("href"))!, page.url()).href);
  }
}

test("a permission is granted, shows on the resource's side, and is removed", async ({ page, groups, resources }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const group = await groups.create();
  const table = page.locator("#permissionsTable");

  await page.goto(groupUrl(group.id, "permissions"));
  await expect(page.getByText(empty)).toBeVisible();
  await grantGroupPermission(page, group.id, resource.identifier, "read");
  await page.reload();
  await expect(table).toContainText(`${resource.identifier}:read`);
  await expect(table).not.toContainText(`${resource.identifier}:write`);

  // The resource's Groups with permission tab agrees.
  const row = await groupWithPermissionRow(page, resource.id, "read", group.identifier);
  await expect(row.getByText("Granted", { exact: true })).toBeVisible();

  await page.goto(groupUrl(group.id, "permissions"));
  await table.getByRole("button", { name: `Remove ${resource.identifier}:read`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
});

test("Grant with no permission chosen is refused at the field", async ({ page, groups }) => {
  const group = await groups.create();
  await page.goto(groupUrl(group.id, "permissions"));
  await page.getByRole("button", { name: "Grant permission", exact: true }).click();
  await expectFieldError(page, "permissionsSelect", "Choose a permission to grant.");
  await expect(page.getByText(empty)).toBeVisible();
});

test("a choice's description is shortened in the list and shown whole under its field", async ({ page, groups, resources }) => {
  const description = "Orders, invoices and the payments that settle them, for the billing team";
  const resource = await resources.create({ description });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "read", "Read the orders");
  await saveResourcePermissions(page);
  const group = await groups.create();

  await page.goto(groupUrl(group.id, "permissions"));
  const resourceChoice = page.locator("#resourcesSelect");
  const option = resourceChoice.locator(`option[data-resource-identifier="${resource.identifier}"]`);
  await expect(option).toHaveText(new RegExp(`^${resource.identifier} – Orders, invoices .*…$`));
  const loaded = page.waitForResponse((r) => r.url().includes("/admin/get-permissions"));
  await resourceChoice.selectOption((await option.getAttribute("value"))!);
  await loaded;
  await expect(page.locator("#resourcesSelect-description")).toHaveText(description);
  await page.locator("#permissionsSelect").selectOption({ label: "read – Read the orders" });
  await expect(page.locator("#permissionsSelect-description")).toHaveText("Read the orders");
});

test("a permission already in the list is refused", async ({ page, groups, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const group = await groups.create();
  await grantGroupPermission(page, group.id, resource.identifier, "read");
  await addPermissionRow(page, resource.identifier, "read");
  await expectFieldError(page, "permissionsSelect", "The group already has that permission.");
  await expect(page.locator("#permissionsTable tbody tr")).toHaveCount(1);
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
  await expect(page.locator("#permissionListStatus")).toContainText("The list was changed by another save after it was loaded.");

  await page.reload();
  await expect(page.locator("#permissionsTable")).toContainText(`${resource.identifier}:read`);
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:write`);
});
