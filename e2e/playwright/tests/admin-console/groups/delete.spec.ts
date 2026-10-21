import { addGroupMember, detail, groupUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const list = `${env.adminUrl}/admin/groups`;

test("deleting needs the identifier typed, and leaves its members' users in place", async ({ page, groups, users }) => {
  const group = await groups.create({ description: "To be deleted" });
  const user = await users.create();
  await addGroupMember(page, group.id, user.email);

  // The list's Delete link, named for the group, opens its delete page, which shows what goes.
  await page.goto(list);
  await rowWithCell(page, group.identifier).getByRole("link", { name: `Delete ${group.identifier}`, exact: true }).click();
  await expect(page).toHaveURL(groupUrl(group.id, "delete"));
  await expect(page).toHaveTitle(new RegExp(`^Delete group – ${group.identifier} – `));
  await expect(detail(page, "Group identifier")).toHaveText(group.identifier);
  await expect(detail(page, "Description")).toHaveText("To be deleted");
  await expect(detail(page, "Members")).toHaveText(/^1\b/);
  await expect(detail(page, "Members").getByRole("link", { name: "View members" })).toHaveAttribute(
    "href",
    `/admin/groups/${group.id}/members`,
  );

  const input = page.getByLabel("To confirm, type the group identifier");
  const deleteButton = page.getByRole("button", { name: "Delete group", exact: true });
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("Type the group identifier to confirm.");
  await expect(input).toHaveAttribute("aria-invalid", "true");
  await input.fill(`${group.identifier}-wrong`);
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("That isn't this group's identifier. Type it as shown above.");
  // Cancel goes back to the list, the group still in it.
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(list);
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
