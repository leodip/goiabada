import { addGroupMember, groupUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

test("a user is added from the search, shows as a member everywhere, and is removed", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  const usersTable = page.locator("#usersTable");

  await page.goto(groupUrl(group.id, "members"));
  await expect(usersTable).toContainText("No users assigned to group.");
  await page.getByRole("link", { name: "Add member" }).click();
  await expect(usersTable).toContainText("Enter a search term.");
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await rowWithCell(page, user.email).getByRole("button", { name: "Add to group" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText(user.email);
  await expect(dialog).toContainText(group.identifier);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(rowWithCell(page, user.email).getByText("In group")).toBeVisible();

  // Searching again shows the user already in the group, with nothing to add.
  await page.reload();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await expect(rowWithCell(page, user.email).getByText("In group")).toBeVisible();
  await expect(rowWithCell(page, user.email).getByRole("button", { name: "Add to group" })).toHaveCount(0);

  await page.getByRole("link", { name: "Back to members" }).click();
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
  await page.goto(`${env.adminUrl}/admin/groups`);
  await expect(rowWithCell(page, group.identifier).getByRole("cell").nth(4)).toHaveText("1");
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/groups`);
  await expect(page.locator("#groupsTable")).toContainText(group.identifier);

  await page.goto(groupUrl(group.id, "members"));
  await rowWithCell(page, user.email).getByRole("button", { name: "Remove" }).click();
  await expect(dialog).toContainText(user.email);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(rowWithCell(page, user.email).getByText("Removed")).toBeVisible();
  await page.reload();
  await expect(usersTable).toContainText("No users assigned to group.");
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/groups`);
  await expect(page.locator("#groupsTable")).not.toContainText(group.identifier);
});

test("Enter in the search box only searches: it adds nobody and stays on the page", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  const addUrl = `${env.adminUrl}/admin/groups/${group.id}/members/add`;
  await page.goto(addUrl);
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  const row = rowWithCell(page, user.email);
  await expect(row.getByRole("button", { name: "Add to group" })).toBeVisible();

  // Enter's keyup runs the search again; by its answer, a click or a submit would have happened.
  const searched = page.waitForResponse((r) => new URL(r.url()).pathname === `/admin/groups/${group.id}/members/search`);
  await page.locator("#search").press("Enter");
  await searched;
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page).toHaveURL(addUrl);
  await expect(row.getByRole("button", { name: "Add to group" })).toBeVisible();
});

test("a search that matches nobody says so", async ({ page, groups }) => {
  const group = await groups.create();
  await page.goto(`${env.adminUrl}/admin/groups/${group.id}/members/add`);
  await page.locator("#search").pressSequentially("nobody-matches-this-e2e-search");
  await expect(page.locator("#usersTable")).toContainText("No users found.");
});

test("deleting a member's user takes them off the group", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);

  await page.goto(`${env.adminUrl}/admin/users/${user.id}/delete`);
  await page.getByRole("button", { name: "Delete user" }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`));
  user.markDeleted();

  await page.goto(groupUrl(group.id, "members"));
  await expect(page.locator("#usersTable")).toContainText("No users assigned to group.");
  await page.goto(`${env.adminUrl}/admin/groups`);
  await expect(rowWithCell(page, group.identifier).getByRole("cell").nth(4)).toHaveText("0");
});
