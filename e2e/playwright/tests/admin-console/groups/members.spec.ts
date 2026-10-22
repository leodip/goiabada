import { addGroupMember, cancelDialog, confirmDialog, deleteUser, groupUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const empty = "No one is in this group yet.";

test("a user is added from the search, shows as a member everywhere, and is removed", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();

  await page.goto(groupUrl(group.id, "members"));
  await expect(page.getByText(empty)).toBeVisible();
  await page.getByRole("link", { name: "Add members", exact: true }).click();
  await expect(page.getByText("Type to search for users to add.")).toBeVisible();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  // Add to group acts at once: the row says so, and so does the page.
  const found = rowWithCell(page, user.email);
  await expect(found.getByText("Playwright Tester")).toBeVisible();
  await found.getByRole("button", { name: `Add to group ${user.email}`, exact: true }).click();
  await expect(found.getByText("In group", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Added to the group.");

  // Searching again shows the user already in the group, with nothing to add.
  await page.reload();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await expect(rowWithCell(page, user.email).getByText("In group", { exact: true })).toBeVisible();
  await expect(rowWithCell(page, user.email).getByRole("button", { name: /^Add to group/ })).toHaveCount(0);

  await page.getByRole("link", { name: "Back to members", exact: true }).click();
  await expect(page).toHaveURL(groupUrl(group.id, "members"));
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
  await page.goto(`${env.adminUrl}/admin/groups`);
  await expect(rowWithCell(page, group.identifier).getByRole("cell").nth(1)).toHaveText("1");
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/groups`);
  await expect(page.locator("#groupsTable")).toContainText(group.identifier);

  await page.goto(groupUrl(group.id, "members"));
  const member = rowWithCell(page, user.email);
  await member.getByRole("button", { name: `Remove ${user.email}`, exact: true }).click();
  await confirmDialog(page, `Remove ${user.email} from the group?`);
  await expect(member.getByText("Removed", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Member removed.");
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/groups`);
  await expect(page.locator("#groupsTable")).not.toContainText(group.identifier);
});

test("removing a member can be cancelled", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);

  await page.goto(groupUrl(group.id, "members"));
  const remove = rowWithCell(page, user.email).getByRole("button", { name: `Remove ${user.email}`, exact: true });
  await remove.click();
  await cancelDialog(page, `Remove ${user.email} from the group?`);
  await expect(remove).toBeVisible();
  await page.reload();
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
});

test("Enter in the search box only searches: it adds nobody and stays on the page", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  const addUrl = `${env.adminUrl}/admin/groups/${group.id}/members/add`;
  await page.goto(addUrl);
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  const add = rowWithCell(page, user.email).getByRole("button", { name: `Add to group ${user.email}`, exact: true });
  await expect(add).toBeVisible();

  // Enter runs the search again at once; by its answer, a click or a submit would have happened.
  const searched = page.waitForResponse((r) => new URL(r.url()).pathname === `/admin/groups/${group.id}/members/search`);
  await page.locator("#search").press("Enter");
  await searched;
  await expect(page).toHaveURL(addUrl);
  await expect(add).toBeVisible();
  await expect(page.getByText("In group", { exact: true })).toHaveCount(0);
});

test("a search that matches nobody says so", async ({ page, groups }) => {
  const group = await groups.create();
  await page.goto(`${env.adminUrl}/admin/groups/${group.id}/members/add`);
  await page.locator("#search").pressSequentially("nobody-matches-this-e2e-search");
  await expect(page.getByText("No users found.", { exact: true })).toBeVisible();
  await expect(page.locator("#usersTable")).toBeHidden();
});

test("deleting a member's user takes them off the group", async ({ page, groups, users }) => {
  const group = await groups.create();
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);

  await deleteUser(page, user.id);
  user.markDeleted();

  await page.goto(groupUrl(group.id, "members"));
  await expect(page.getByText(empty)).toBeVisible();
  await page.goto(`${env.adminUrl}/admin/groups`);
  await expect(rowWithCell(page, group.identifier).getByRole("cell").nth(1)).toHaveText("0");
});
