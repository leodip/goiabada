import type { Page } from "@playwright/test";
import { cancelDialog, confirmDialog, resourceUrl, rowWithCell } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

const noUsers = "No user holds this permission directly.";

type Row = ReturnType<typeof rowWithCell>;

// Shows a tab's list for one of the resource's permissions: the choice, then Show, which loads the
// tab for it.
async function showPermission(page: Page, permission: string) {
  const choice = page.getByLabel("Permission", { exact: true });
  await choice.selectOption({ label: permission });
  const value = await choice.inputValue();
  await page.getByRole("button", { name: "Show", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`[?&]permission=${value}(&|$)`));
}

// Opens the Grant to a user page for the permission the Users with permission tab shows, and finds
// the user there.
async function searchToGrant(page: Page, email: string) {
  await page.getByRole("link", { name: "Grant to a user", exact: true }).click();
  await page.locator("#search").pressSequentially(email.split("@")[0]);
  return rowWithCell(page, email);
}

test("a resource with no permissions says so on both tabs", async ({ page, resources }) => {
  const resource = await resources.create();
  for (const tab of ["users-with-permission", "groups-with-permission"] as const) {
    await page.goto(resourceUrl(resource.id, tab));
    await expect(page.getByText("This resource has no permissions yet. Add them on the Permissions tab.")).toBeVisible();
  }
});

test("a permission is granted to a user found by search, listed, and removed", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read", "write"] });
  const user = await users.create();

  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await expect(page.getByText(noUsers)).toBeVisible();
  await showPermission(page, "write");

  await page.getByRole("link", { name: "Grant to a user", exact: true }).click();
  await expect(page.locator("dl.detail-list dd")).toHaveText(`${resource.identifier}:write`);
  await expect(page.getByText("Type to search for users to grant the permission to.")).toBeVisible();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  // Grant acts at once: the row says so, and so does the page.
  const row = rowWithCell(page, user.email);
  await row.getByRole("button", { name: `Grant ${user.email}`, exact: true }).click();
  await expect(row.getByText("Granted", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Permission granted to the user.");

  await page.getByRole("link", { name: "Back to users with permission", exact: true }).click();
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
  // Only the permission granted: the other one has no users.
  await showPermission(page, "read");
  await expect(page.getByText(noUsers)).toBeVisible();
  await showPermission(page, "write");

  await rowWithCell(page, user.email).getByRole("button", { name: `Remove ${user.email}`, exact: true }).click();
  await confirmDialog(page, `Remove ${resource.identifier}:write from ${user.email}?`);
  await expect(rowWithCell(page, user.email).getByText("Removed", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Permission removed from the user.");
  await page.reload();
  await expect(page.getByText(noUsers)).toBeVisible();
});

test("removing a user's permission can be cancelled", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  const found = await searchToGrant(page, user.email);
  await found.getByRole("button", { name: `Grant ${user.email}`, exact: true }).click();
  await expect(found.getByText("Granted", { exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Back to users with permission", exact: true }).click();
  const remove = rowWithCell(page, user.email).getByRole("button", { name: `Remove ${user.email}`, exact: true });
  await remove.click();
  await cancelDialog(page, `Remove ${resource.identifier}:read from ${user.email}?`);
  await expect(remove).toBeVisible();
  await page.reload();
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
});

test("a user who already holds the permission shows so in the search", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  const found = await searchToGrant(page, user.email);
  await found.getByRole("button", { name: `Grant ${user.email}`, exact: true }).click();
  await expect(found.getByText("Granted", { exact: true })).toBeVisible();

  await page.reload();
  await page.locator("#search").pressSequentially(user.email.split("@")[0]);
  await expect(rowWithCell(page, user.email).getByText("Granted", { exact: true })).toBeVisible();
  await expect(rowWithCell(page, user.email).getByRole("button", { name: /^Grant/ })).toHaveCount(0);
});

test("Enter in the search box only searches: it grants nothing and stays on the page", async ({ page, resources, users }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  const found = await searchToGrant(page, user.email);
  const addUrl = page.url();
  const grant = found.getByRole("button", { name: `Grant ${user.email}`, exact: true });
  await expect(grant).toBeVisible();

  // Enter runs the search again at once; by its answer, a click or a submit would have happened.
  const searched = page.waitForResponse((r) =>
    new URL(r.url()).pathname.startsWith(`/admin/resources/${resource.id}/users-with-permission/search/`),
  );
  await page.locator("#search").press("Enter");
  await searched;
  await expect(page).toHaveURL(addUrl);
  await expect(grant).toBeVisible();
  await expect(page.getByText("Granted", { exact: true })).toHaveCount(0);
});

test("a search that matches nobody says so", async ({ page, resources }) => {
  const resource = await resources.create({ permissions: ["read"] });
  await page.goto(resourceUrl(resource.id, "users-with-permission"));
  await page.getByRole("link", { name: "Grant to a user", exact: true }).click();
  await page.locator("#search").pressSequentially("nobody-matches-this-e2e-search");
  await expect(page.getByText("No users found.", { exact: true })).toBeVisible();
  await expect(page.locator("#usersTable")).toBeHidden();
});

test("a permission is granted to a group and removed again", async ({ page, resources, groups }) => {
  const resource = await resources.create({ permissions: ["read"] });
  const group = await groups.create();

  // The tab lists every group, ten to a page; walk the pages to the one holding this group.
  const groupRow = async () => {
    await page.goto(resourceUrl(resource.id, "groups-with-permission"));
    for (;;) {
      const row = rowWithCell(page, group.identifier);
      if ((await row.count()) === 1) return row;
      const next = page.getByRole("link", { name: "Next page", exact: true });
      if ((await next.count()) === 0) throw new Error(`group ${group.identifier} not listed`);
      // Followed by its address, so the next look is at the page it leads to.
      await page.goto(new URL((await next.getAttribute("href"))!, page.url()).href);
    }
  };
  const grant = (row: Row) => row.getByRole("button", { name: `Grant ${group.identifier}`, exact: true });
  const remove = (row: Row) => row.getByRole("button", { name: `Remove ${group.identifier}`, exact: true });
  const granted = (row: Row) => row.getByText("Granted", { exact: true });

  // Grant acts at once, and gives way to Remove in the row.
  let row = await groupRow();
  await expect(granted(row)).toBeHidden();
  await grant(row).click();
  await expect(granted(row)).toBeVisible();
  await expect(remove(row)).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Permission granted to the group.");

  // Remove asks first: Cancel leaves the grant, Remove permission takes it away.
  row = await groupRow();
  await expect(granted(row)).toBeVisible();
  await remove(row).click();
  await cancelDialog(page, `Remove ${resource.identifier}:read from ${group.identifier}?`);
  await expect(granted(row)).toBeVisible();
  await remove(row).click();
  await confirmDialog(page, `Remove ${resource.identifier}:read from ${group.identifier}?`);
  await expect(granted(row)).toBeHidden();
  await expect(grant(row)).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Permission removed from the group.");

  row = await groupRow();
  await expect(granted(row)).toBeHidden();
});
