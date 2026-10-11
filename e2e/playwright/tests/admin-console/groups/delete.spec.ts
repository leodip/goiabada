import { addGroupMember, groupUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const list = `${env.adminUrl}/admin/groups`;

test("deleting needs the identifier typed, and leaves its members' users in place", async ({ page, groups, users }) => {
  const group = await groups.create({ description: "To be deleted" });
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);

  await page.goto(groupUrl(group.id, "delete"));
  await expect(rowWithCell(page, "Group identifier").getByRole("cell").nth(1)).toHaveText(group.identifier);
  await expect(rowWithCell(page, "Group description").getByRole("cell").nth(1)).toHaveText("To be deleted");
  await expect(page.getByRole("row").filter({ hasText: "Count of members" }).getByRole("cell").nth(1)).toContainText("1");

  const input = page.locator('input[name="groupIdentifier"]');
  const deleteButton = page.getByRole("button", { name: "Delete", exact: true });
  await deleteButton.click();
  await expect(page.getByText("Group identifier is required.")).toBeVisible();
  await input.fill(`${group.identifier}-wrong`);
  await deleteButton.click();
  await expect(page.getByText("Group identifier does not match the group being deleted.")).toBeVisible();
  await page.goto(list);
  await expect(rowWithCell(page, group.identifier)).toHaveCount(1);

  await page.goto(groupUrl(group.id, "delete"));
  await input.fill(group.identifier);
  await deleteButton.click();
  await expect(page).toHaveURL(list);
  await expect(rowWithCell(page, group.identifier)).toHaveCount(0);
  group.markDeleted();

  const response = await page.goto(groupUrl(group.id, "settings"));
  expect(response?.status()).toBe(404);
  // The member's user is still there, in no group.
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/groups`);
  await expect(page.locator("#groupsTable")).not.toContainText(group.identifier);
});
