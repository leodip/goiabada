import {
  addResourcePermission,
  expectErrorDialog,
  idFromListLink,
  resourcePermissionRow,
  resourceUrl,
  saveResourcePermissions,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const permissionRows = "#permissionsTable tbody tr";

test("a new resource has no permissions", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await expect(page.locator(permissionRows)).toHaveText(["This resource has no permissions defined"]);
});

test("permissions are created with descriptions and saved", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "read", "Read things");
  await addResourcePermission(page, "write", "Write things");
  await expect(page.locator(permissionRows)).toHaveCount(2);
  await saveResourcePermissions(page);

  await page.reload();
  await expect(resourcePermissionRow(page, "read")).toContainText("Read things");
  await expect(resourcePermissionRow(page, "write")).toContainText("Write things");
  await expect(page.locator(permissionRows)).toHaveCount(2);
});

test("unsaved changes are lost on leaving the page", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "read");
  await page.reload();
  await expect(page.locator(permissionRows)).toHaveText(["This resource has no permissions defined"]);
});

test("a permission is edited, and Cancel edit leaves it as it was", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  const editButton = () => page.getByRole("button", { name: "Edit permission read", exact: true });

  await editButton().click();
  await expect(page.locator("#permissionIdentifier")).toHaveValue("read");
  await page.locator("#permissionIdentifier").fill("view");
  await page.getByText("Cancel edit").click();
  await expect(page.getByRole("button", { name: "Create permission" })).toBeVisible();
  await expect(page.locator("#permissionIdentifier")).toHaveValue("");
  await expect(resourcePermissionRow(page, "read")).toHaveCount(1);

  await editButton().click();
  await page.locator("#permissionIdentifier").fill("view");
  await page.locator("#permissionDescription").fill("View things");
  const validated = page.waitForResponse((r) => new URL(r.url()).pathname === "/admin/resources/validate-permission");
  await page.getByRole("button", { name: "Update permission" }).click();
  await validated;
  // The table changes once the page has read the answer, which is after the answer arrives.
  await expect(resourcePermissionRow(page, "view")).toHaveCount(1);
  await saveResourcePermissions(page);

  await page.reload();
  await expect(resourcePermissionRow(page, "view")).toContainText("View things");
  await expect(resourcePermissionRow(page, "read")).toHaveCount(0);
});

test("a permission is removed", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await page.getByRole("button", { name: "Remove permission read", exact: true }).click();
  await expect(resourcePermissionRow(page, "read")).toHaveCount(0);
  await saveResourcePermissions(page);

  await page.reload();
  await expect(page.locator(permissionRows)).toHaveCount(1);
  await expect(resourcePermissionRow(page, "write")).toHaveCount(1);
});

for (const { identifier, description, message } of [
  { identifier: "not valid", description: "", message: "Invalid identifier format." },
  { identifier: "ab", description: "", message: "The identifier must be at least 3 characters long." },
  {
    identifier: "read",
    description: "<i>html</i>",
    message: "The description contains invalid characters, as we do not permit the use of HTML in the description.",
  },
  { identifier: "read", description: "x".repeat(101), message: "The description cannot exceed a maximum length of 100 characters." },
]) {
  test(`the permission ${JSON.stringify(identifier)} described ${JSON.stringify(description.slice(0, 12))} is refused`, async ({
    page,
    resources,
  }) => {
    const resource = await resources.create();
    await page.goto(resourceUrl(resource.id, "permissions"));
    await addResourcePermission(page, identifier, description);
    await expectErrorDialog(page, message);
    await expect(page.locator(permissionRows)).toHaveText(["This resource has no permissions defined"]);
  });
}

test("a permission already in the list is refused", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await page.locator("#permissionIdentifier").fill("read");
  await page.getByRole("button", { name: "Create permission" }).click();
  await expectErrorDialog(page, "The permission identifier is already in the list.");
  await expect(page.locator(permissionRows)).toHaveCount(1);
});

test("a save from a page loaded before another save is refused, and changes nothing", async ({ page, context, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const other = await context.newPage();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await other.goto(resourceUrl(resource.id, "permissions"));

  await addResourcePermission(other, "write");
  await saveResourcePermissions(other);
  await other.close();

  // This page still shows the list as it was before that save.
  await addResourcePermission(page, "delete");
  await page.locator("#btnSave").click();
  await expectErrorDialog(page, "The list was changed by another save after it was loaded.");

  await page.reload();
  await expect(resourcePermissionRow(page, "write")).toHaveCount(1);
  await expect(resourcePermissionRow(page, "delete")).toHaveCount(0);
});

test("the system resource's built-in permissions cannot be edited or removed", async ({ page }) => {
  const id = await idFromListLink(page, `${env.adminUrl}/admin/resources`, "authserver", "Manage");
  await page.goto(resourceUrl(id, "permissions"));
  await expect(page.getByText("This is a system-level resource.")).toBeVisible();
  for (const permission of ["manage", "manage-account", "admin-read"]) {
    await expect(resourcePermissionRow(page, permission).getByRole("button")).toHaveCount(0);
  }

  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("You are about to modify a system-level resource.");
  await dialog.getByRole("button", { name: "No" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("Resource permissions saved successfully")).toHaveCount(0);
});
