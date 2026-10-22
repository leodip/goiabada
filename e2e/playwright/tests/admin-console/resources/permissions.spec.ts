import {
  addResourcePermission,
  cancelDialog,
  expectFieldError,
  idFromListLink,
  resourcePermissionRow,
  resourceUrl,
  saveResourcePermissions,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const permissionRows = "#permissionsTable tbody tr";
const empty = "No permissions yet.";

test("a new resource has no permissions", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await expect(page.getByText(empty)).toBeVisible();
  await expect(page.locator(permissionRows)).toHaveCount(0);
});

test("permissions are created with descriptions and saved", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "read", "Read things");
  await addResourcePermission(page, "write", "Write things");
  await expect(page.locator(permissionRows)).toHaveCount(2);
  await expect(page.getByText(empty)).toBeHidden();
  await saveResourcePermissions(page);

  await page.reload();
  await expect(resourcePermissionRow(page, "read")).toContainText("Read things");
  await expect(resourcePermissionRow(page, "write")).toContainText("Write things");
  await expect(page.locator(permissionRows)).toHaveCount(2);
});

// Enter in either field adds what they hold, as the Add permission button does.
test("Enter in the permission fields adds the permission", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await page.locator("#permissionIdentifier").fill("read");
  const validated = page.waitForResponse((r) => new URL(r.url()).pathname === "/admin/resources/validate-permission");
  await page.locator("#permissionIdentifier").press("Enter");
  await validated;
  await expect(resourcePermissionRow(page, "read")).toHaveCount(1);
  await expect(page.locator("#permissionIdentifier")).toHaveValue("");
  // Still only in the page.
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
});

test("unsaved changes are lost on leaving the page", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "permissions"));
  await addResourcePermission(page, "read");
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
});

test("a permission is edited, and Cancel leaves it as it was", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  const row = resourcePermissionRow(page, "read");
  const editButton = page.getByRole("button", { name: "Edit read", exact: true });

  // The row being edited says so, in place of its Edit.
  await editButton.click();
  await expect(page.locator("#permissionIdentifier")).toHaveValue("read");
  await expect(row.getByText("Editing", { exact: true })).toBeVisible();
  await expect(editButton).toBeHidden();
  await expect(page.getByRole("button", { name: "Add permission", exact: true })).toBeHidden();
  await page.locator("#permissionIdentifier").fill("view");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("button", { name: "Add permission", exact: true })).toBeVisible();
  await expect(page.locator("#permissionIdentifier")).toHaveValue("");
  await expect(row).toHaveCount(1);
  await expect(row.getByText("Editing", { exact: true })).toHaveCount(0);
  await expect(editButton).toBeVisible();

  await editButton.click();
  await page.locator("#permissionIdentifier").fill("view");
  await page.locator("#permissionDescription").fill("View things");
  const validated = page.waitForResponse((r) => new URL(r.url()).pathname === "/admin/resources/validate-permission");
  await page.getByRole("button", { name: "Update permission", exact: true }).click();
  await validated;
  // The table changes once the page has read the answer, which is after the answer arrives.
  await expect(resourcePermissionRow(page, "view")).toHaveCount(1);
  await expect(resourcePermissionRow(page, "view").getByText("Editing", { exact: true })).toHaveCount(0);
  await saveResourcePermissions(page);

  await page.reload();
  await expect(resourcePermissionRow(page, "view")).toContainText("View things");
  await expect(resourcePermissionRow(page, "read")).toHaveCount(0);
});

test("a permission is removed", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await page.getByRole("button", { name: "Remove read", exact: true }).click();
  await expect(resourcePermissionRow(page, "read")).toHaveCount(0);
  await saveResourcePermissions(page);

  await page.reload();
  await expect(page.locator(permissionRows)).toHaveCount(1);
  await expect(resourcePermissionRow(page, "write")).toHaveCount(1);
});

for (const { identifier, description, field, message } of [
  { identifier: "not valid", description: "", field: "permissionIdentifier", message: "Invalid identifier format." },
  { identifier: "ab", description: "", field: "permissionIdentifier", message: "The identifier must be at least 3 characters long." },
  {
    identifier: "read",
    description: "<i>html</i>",
    field: "permissionDescription",
    message: "The description contains invalid characters, as we do not permit the use of HTML in the description.",
  },
  {
    identifier: "read",
    description: "x".repeat(101),
    field: "permissionDescription",
    message: "The description cannot exceed a maximum length of 100 characters.",
  },
]) {
  test(`the permission ${JSON.stringify(identifier)} described ${JSON.stringify(description.slice(0, 12))} is refused`, async ({
    page,
    resources,
  }) => {
    const resource = await resources.create();
    await page.goto(resourceUrl(resource.id, "permissions"));
    await addResourcePermission(page, identifier, description);
    await expectFieldError(page, field, message);
    await expect(page.getByText(empty)).toBeVisible();
  });
}

test("a permission already in the list is refused", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "permissions"));
  await page.locator("#permissionIdentifier").fill("read");
  await page.getByRole("button", { name: "Add permission", exact: true }).click();
  await expectFieldError(page, "permissionIdentifier", "The resource already has a permission with that identifier.");
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
  await expect(page.locator("#resourcePermissionsStatus")).toContainText("The list was changed by another save after it was loaded.");

  await page.reload();
  await expect(resourcePermissionRow(page, "write")).toHaveCount(1);
  await expect(resourcePermissionRow(page, "delete")).toHaveCount(0);
});

test("the system resource's built-in permissions cannot be edited or removed", async ({ page }) => {
  const id = await idFromListLink(page, `${env.adminUrl}/admin/resources`, "authserver");
  await page.goto(resourceUrl(id, "permissions"));
  await expect(page.getByText("Its built-in permissions can't be renamed or deleted")).toBeVisible();
  for (const permission of ["manage", "manage-account", "admin-read"]) {
    await expect(resourcePermissionRow(page, permission).getByRole("button")).toHaveCount(0);
    await expect(resourcePermissionRow(page, permission).getByText("Built-in", { exact: true })).toBeVisible();
  }

  // Cancel: nothing of the system resource changes in a shared environment.
  await page.locator("#btnSave").click();
  await cancelDialog(page, "This is the auth server's own resource: a wrong change can stop administrators from managing Goiabada.");
  await expect(page.getByText("Permissions saved.")).toHaveCount(0);
});
