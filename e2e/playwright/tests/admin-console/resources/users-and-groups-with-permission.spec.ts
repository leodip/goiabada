import type { Page } from "@playwright/test";
import { resourceUrl, rowWithCell } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

// The select's option value of a permission, as the tabs name it in their links.
async function permissionId(page: Page, permission: string): Promise<string> {
  const option = page.locator("#permissionSelect option").filter({ hasText: new RegExp(` - ${permission}( |$)`) });
  return (await option.getAttribute("value"))!;
}

test("a resource with no permissions says so on both tabs", async ({ page, resources }) => {
  const resource = await resources.create();
  for (const tab of ["users-with-permission", "groups-with-permission"] as const) {
    await page.goto(resourceUrl(resource.id, tab));
    await expect(page.getByText("No permissions have been assigned to the resource.")).toBeVisible();
  }
});

test("a permission is granted to a user found by search, listed, and removed", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const user = await users.create();
  const usersTable = page.locator("#usersTable");

  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await expect(usersTable).toContainText("No users have been assigned the selected permission.");
  await page.locator("#permissionSelect").selectOption(await permissionId(page, "write"));
  await expect(page).toHaveURL(/permission=\d+/);

  await page.getByRole("link", { name: "Grant permission to user" }).click();
  await expect(usersTable).toContainText("Enter a search term.");
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  const row = rowWithCell(page, user.email);
  await row.getByRole("button", { name: "Grant permission" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText(`${resource.identifier}:write`);
  await expect(dialog).toContainText(user.email);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(row.getByText("Has permission")).toBeVisible();

  await page.getByRole("link", { name: "Back to list of users with permission" }).click();
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
  // Only the permission granted: the other one has no users.
  await page.locator("#permissionSelect").selectOption(await permissionId(page, "read"));
  await expect(usersTable).toContainText("No users have been assigned the selected permission.");
  await page.locator("#permissionSelect").selectOption(await permissionId(page, "write"));

  await rowWithCell(page, user.email).getByRole("button", { name: "Remove permission" }).click();
  await expect(dialog).toContainText(`${resource.identifier}:write`);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(rowWithCell(page, user.email).getByText("Removed")).toBeVisible();
  await page.reload();
  await expect(usersTable).toContainText("No users have been assigned the selected permission.");
});

test("a user who already holds the permission shows so in the search", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await page.getByRole("link", { name: "Grant permission to user" }).click();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await rowWithCell(page, user.email).getByRole("button", { name: "Grant permission" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(rowWithCell(page, user.email).getByText("Has permission")).toBeVisible();

  await page.reload();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await expect(rowWithCell(page, user.email).getByText("Has permission")).toBeVisible();
  await expect(rowWithCell(page, user.email).getByRole("button", { name: "Grant permission" })).toHaveCount(0);
});

test("Enter in the search box only searches: it grants nothing and stays on the page", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await page.getByRole("link", { name: "Grant permission to user" }).click();
  await expect(page.locator("#usersTable")).toContainText("Enter a search term.");
  const addUrl = page.url();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  const row = rowWithCell(page, user.email);
  await expect(row.getByRole("button", { name: "Grant permission" })).toBeVisible();

  // Enter's keyup runs the search again; by its answer, a click or a submit would have happened.
  const searched = page.waitForResponse((r) =>
    new URL(r.url()).pathname.startsWith(`/admin/resources/${resource.id}/users-with-permission/search/`),
  );
  await page.locator("#search").press("Enter");
  await searched;
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page).toHaveURL(addUrl);
  await expect(row.getByRole("button", { name: "Grant permission" })).toBeVisible();
});

test("a search that matches nobody says so", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await page.getByRole("link", { name: "Grant permission to user" }).click();
  await page.locator("#search").pressSequentially("nobody-matches-this-e2e-search");
  await expect(page.locator("#usersTable")).toContainText("No users found.");
});

test("a permission is granted to a group and removed again", async ({ page, resources, groups }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const group = await groups.create();
  const dialog = page.locator("dialog[open]");

  // The tab lists every group, ten to a page; walk the pages to the one holding this group.
  const groupRow = async () => {
    for (let pageNumber = 1; ; pageNumber++) {
      await page.goto(`${resourceUrl(resource.id, "groups-with-permission")}?page=${pageNumber}`);
      const row = page.locator("#groupsTable tbody tr").filter({ has: page.getByRole("link", { name: group.identifier, exact: true }) });
      if ((await row.count()) === 1) return row;
      if ((await page.locator("#groupsTable tbody tr").count()) < 10) throw new Error(`group ${group.identifier} not listed`);
    }
  };

  let row = await groupRow();
  await expect(row.getByRole("cell").nth(2)).toHaveText("No");
  await row.getByRole("button", { name: "Grant permission" }).click();
  await expect(dialog).toContainText(`${resource.identifier}:read`);
  await expect(dialog).toContainText(group.identifier);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(row.getByRole("cell").nth(2)).toHaveText("Yes");

  row = await groupRow();
  await expect(row.getByRole("cell").nth(2)).toHaveText("Yes");
  await row.getByRole("button", { name: "Remove permission" }).click();
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(row.getByRole("cell").nth(2)).toHaveText("No");

  row = await groupRow();
  await expect(row.getByRole("cell").nth(2)).toHaveText("No");
});
