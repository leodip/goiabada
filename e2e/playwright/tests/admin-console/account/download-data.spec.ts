// A user downloading their own data from Account, Your data (#782): the menu item, the page, and
// Download my data, which saves the same file an administrator's Download data saves, without the
// attributes no app receives and without naming the administrator who changed the account, and is
// audited as exported_own_user_data. The round trip after an old sign-in isn't here: the suite
// can't age a sign-in, and the integration tier and the console's handler tests cover it.
import { readFileSync } from "node:fs";
import { userUrl } from "../../../lib/admin-console";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { auditRows } from "../../../lib/sessions";

test("a user who just signed in downloads their own data, and the download is audited", async ({ page, browser, users }) => {
  const user = await users.create();

  // The administrator gives the user an attribute apps receive, with the form's default of both
  // token flags on, and one with both flags off, an administrators' own note; and changes the
  // user's profile, a change the file marks without naming who made it.
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/attributes/add`);
  await page.locator("#attributeKey").fill("employee_id");
  await page.locator('input[name="attributeValue"]').fill("E-3003");
  await page.locator("#btnSave").click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(\\?|$)`));
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/attributes/add`);
  await page.locator("#attributeKey").fill("administrators_note");
  await page.locator('input[name="attributeValue"]').fill("asked-twice-about-billing");
  await page.locator('input[name="includeInAccessToken"]').uncheck();
  await page.locator('input[name="includeInIdToken"]').uncheck();
  await page.locator("#btnSave").click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(\\?|$)`));
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="nickname"]').fill("set-by-an-administrator");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Profile saved.")).toBeVisible();

  // The user signs in, and finds Your data in the account menu.
  const own = await signInToConsole(browser, user);
  const account = own.page.getByRole("navigation", { name: "Account", exact: true });
  await account.getByRole("link", { name: "Your data", exact: true }).click();
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/data`);
  await expect(account.getByRole("link", { name: "Your data", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(own.page).toHaveTitle(/^Download your data – /);
  await expect(own.page.getByRole("heading", { name: "Download your data", level: 1 })).toBeVisible();
  await expect(own.page.getByText("in one JSON file.")).toBeVisible();
  await expect(own.page.getByText("What's in it:")).toBeVisible();
  await expect(own.page.getByText("If you haven't signed in during the last few minutes, you're asked to sign in again first.")).toBeVisible();

  // Signed in just now, so the button downloads the file at once, and the page stays.
  const downloading = own.page.waitForEvent("download");
  await own.page.getByRole("button", { name: "Download my data", exact: true }).click();
  const download = await downloading;
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/data`);

  const text = readFileSync((await download.path())!, "utf8");
  const file = JSON.parse(text);
  // The name is the user's id and the UTC date the file was exported on.
  expect(file.exportedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  expect(download.suggestedFilename()).toBe(`user-${user.id}-${file.exportedAt.slice(0, 10)}.json`);

  // The user's profile.
  expect(file.formatVersion).toBe(1);
  expect(file.identifiers.id).toBe(user.id);
  expect(file.user.email).toBe(user.email);
  expect(file.user.givenName).toBe("Playwright");
  expect(file.user.nickname).toBe("set-by-an-administrator");

  // The attribute apps receive is there; the administrators' note is not.
  expect(file.attributes).toEqual([expect.objectContaining({ key: "employee_id", value: "E-3003" })]);
  expect(text).not.toContain("administrators_note");
  expect(text).not.toContain("asked-twice-about-billing");

  // The administrator's profile change is marked as an administrator's, without naming them.
  const profileChanges = file.auditEvents.filter(
    (event: { auditEvent: string }) => event.auditEvent === "updated_user_profile",
  );
  expect(profileChanges.length).toBeGreaterThan(0);
  for (const change of profileChanges) {
    expect(change).toEqual(expect.objectContaining({ actedByAdministrator: true, loggedInUserId: null, userId: user.id }));
    expect(JSON.parse(change.details)).not.toHaveProperty("logged_in_user");
  }
  expect(text).not.toContain(env.adminEmail);

  // Nothing secret is in it.
  expect(text).not.toContain("passwordHash");
  expect(text).not.toContain(user.password);
  await own.context.close();

  // The administrator's audit log lists the user's own download under the user.
  await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?userId=${user.id}&auditEvent=exported_own_user_data`);
  await expect(auditRows(page, { user_id: String(user.id) }).filter({ hasText: "exported_own_user_data" })).toHaveCount(1);
});
