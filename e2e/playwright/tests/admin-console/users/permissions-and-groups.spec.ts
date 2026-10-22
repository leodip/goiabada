import type { Page } from "@playwright/test";
import { addPermissionRow, expectFieldError, groupUrl, resourceUrl, rowWithCell, userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

const permissionsSaved = "Permissions saved.";
const groupsSaved = "Groups saved.";
const noGroups = "Not in any group yet.";

// Chooses a group in the Group field by its identifier, which its option carries; the option's
// label adds the group's description, shortened.
async function chooseGroup(page: Page, identifier: string) {
  const select = page.locator("#groupsSelect");
  await select.selectOption((await select.locator(`option[data-group-identifier="${identifier}"]`).getAttribute("value"))!);
}

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
  await table.getByRole("button", { name: `Remove ${resource.identifier}:read`, exact: true }).click();
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
  await expectFieldError(page, "permissionsSelect", "The user already has that permission.");
});

test("Grant with no permission chosen is refused at the field", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "permissions"));
  await page.getByRole("button", { name: "Grant permission" }).click();
  await expectFieldError(page, "permissionsSelect", "Choose a permission to grant.");
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
  await expect(page.locator("#permissionListStatus")).toContainText("The list was changed by another save after it was loaded.");
  await page.reload();
  await expect(page.locator("#permissionsTable")).not.toContainText(`${resource.identifier}:write`);
});

test("group membership is granted and removed from the user's side", async ({ page, groups, users }) => {
  const group = await groups.create({ description: "Everyone in sales" });
  const user = await users.create();
  const table = page.locator("#groupsTable");

  await page.goto(userUrl(user.id, "groups"));
  await expect(page.getByText(noGroups)).toBeVisible();
  await expect(table).toBeHidden();
  await chooseGroup(page, group.identifier);
  // The chosen group's description, whole, under the field.
  await expect(page.locator("#groupsSelect-description")).toHaveText("Everyone in sales");
  await page.getByRole("button", { name: "Add to group" }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText(groupsSaved)).toBeVisible();
  await page.reload();
  await expect(table).toContainText(group.identifier);

  await page.goto(groupUrl(group.id, "members"));
  await expect(rowWithCell(page, user.email)).toHaveCount(1);

  await page.goto(userUrl(user.id, "groups"));
  await table.getByRole("button", { name: `Remove ${group.identifier}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText(groupsSaved)).toBeVisible();
  await page.reload();
  await expect(page.getByText(noGroups)).toBeVisible();
});

test("a group already in the list is refused", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  await page.goto(userUrl(user.id, "groups"));
  for (let i = 0; i < 2; i++) {
    await chooseGroup(page, group.identifier);
    await page.getByRole("button", { name: "Add to group" }).click();
  }
  await expectFieldError(page, "groupsSelect", "The user is already in that group.");
});

test("Add to group with no group chosen is refused at the field", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "groups"));
  await page.getByRole("button", { name: "Add to group" }).click();
  await expectFieldError(page, "groupsSelect", "Choose a group to add the user to.");
});
