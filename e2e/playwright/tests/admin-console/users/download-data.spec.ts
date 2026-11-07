// Download data, in the header of every tab of a user, saves the user's data as one JSON file,
// without the attributes no app receives, and the export is audited under the user.
import { readFileSync } from "node:fs";
import { userUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { auditRows } from "../../../lib/sessions";

test("Download data saves the user's file, without their secrets, and is audited", async ({ page, users }) => {
  const user = await users.create();

  // An attribute and a profile change, for the file to hold. The attribute keeps the form's
  // default, both token flags on.
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/attributes/add`);
  await page.locator("#attributeKey").fill("employee_id");
  await page.locator('input[name="attributeValue"]').fill("E-2002");
  await page.locator("#btnSave").click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(\\?|$)`));
  // An attribute with both flags off, which no app receives: an administrators' own note, which
  // the file leaves out.
  await page.goto(`${env.adminUrl}/admin/users/${user.id}/attributes/add`);
  await page.locator("#attributeKey").fill("administrators_note");
  await page.locator('input[name="attributeValue"]').fill("slow-to-answer-email");
  await page.locator('input[name="includeInAccessToken"]').uncheck();
  await page.locator('input[name="includeInIdToken"]').uncheck();
  await page.locator("#btnSave").click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/attributes(\\?|$)`));
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="nickname"]').fill("exported");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Profile saved.")).toBeVisible();

  // The button is a form: the file downloads, and the page stays where it is.
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download data", exact: true }).click();
  const download = await downloading;
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/profile(\\?|$)`));

  const text = readFileSync((await download.path())!, "utf8");
  const file = JSON.parse(text);
  // The name is the user's id and the UTC date the file was exported on.
  expect(file.exportedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  expect(download.suggestedFilename()).toBe(`user-${user.id}-${file.exportedAt.slice(0, 10)}.json`);

  expect(file.formatVersion).toBe(1);
  expect(file.identifiers.id).toBe(user.id);
  expect(file.identifiers.email).toBe(user.email);
  expect(file.identifiers.subject).toBe(file.user.subject);
  expect(file.user.email).toBe(user.email);
  expect(file.user.givenName).toBe("Playwright");
  expect(file.user.nickname).toBe("exported");
  expect(file.attributes).toEqual([expect.objectContaining({ key: "employee_id", value: "E-2002" })]);
  expect(text).not.toContain("administrators_note");
  expect(text).not.toContain("slow-to-answer-email");

  // Nothing secret is in it.
  expect(text).not.toContain("passwordHash");
  expect(text).not.toMatch(/otpSecret/i);
  expect(text).not.toContain(user.password);

  // The audit log, filtered by the user's id, lists the export.
  await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?userId=${user.id}&auditEvent=exported_user_data`);
  await expect(auditRows(page, { user_id: String(user.id) }).filter({ hasText: "exported_user_data" })).toHaveCount(1);
});
