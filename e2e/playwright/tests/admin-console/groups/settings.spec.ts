import { groupUrl, idFromListLink, rowWithCell, saveAndExpectSaved } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/groups`;
const saved = "Group settings saved successfully";

test("the description and include switches are saved, and show on the list", async ({ page, groups }) => {
  const group = await groups.create({ description: "before" });
  await page.goto(groupUrl(group.id, "settings"));
  await expect(page.locator('input[name="description"]')).toHaveValue("before");
  await page.locator('input[name="description"]').fill("after");
  await page.locator('input[name="includeInAccessToken"]').uncheck();
  await page.locator('input[name="includeInIdToken"]').uncheck();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('input[name="description"]')).toHaveValue("after");
  await expect(page.locator('input[name="includeInAccessToken"]')).not.toBeChecked();
  await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
  await expect(page.getByText(saved)).toHaveCount(0);

  await page.goto(list);
  const row = rowWithCell(page, group.identifier);
  await expect(row.getByRole("cell").nth(1)).toHaveText("after");
  await expect(row.getByRole("cell").nth(2)).toHaveText("No");
  await expect(row.getByRole("cell").nth(3)).toHaveText("No");
});

test("renaming asks first: No keeps the old identifier, Yes saves the new one", async ({ page, groups }) => {
  const group = await groups.create();
  const renamed = uniqueIdentifier("g");
  const dialog = page.locator("dialog[open]");
  await page.goto(groupUrl(group.id, "settings"));
  await page.locator("#groupIdentifier").fill(renamed);
  await page.locator("#btnSave").click();
  await expect(dialog).toContainText("You've modified the group identifier");
  await dialog.getByRole("button", { name: "No" }).click();
  await page.goto(groupUrl(group.id, "settings"));
  await expect(page.locator("#groupIdentifier")).toHaveValue(group.identifier);

  await page.locator("#groupIdentifier").fill(renamed);
  await page.locator("#btnSave").click();
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator("#groupIdentifier")).toHaveValue(renamed);

  await page.goto(list);
  await expect(rowWithCell(page, group.identifier)).toHaveCount(0);
  expect(await idFromListLink(page, list, renamed, "Manage")).toBe(group.id);
});

test("renaming to an identifier in use, or an invalid one, is refused", async ({ page, groups }) => {
  const first = await groups.create();
  const second = await groups.create();
  for (const { identifier, message } of [
    { identifier: first.identifier, message: "The group identifier is already in use" },
    { identifier: "not valid", message: "Invalid identifier format." },
  ]) {
    await page.goto(groupUrl(second.id, "settings"));
    await page.locator("#groupIdentifier").fill(identifier);
    await page.locator("#btnSave").click();
    await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
    await expect(page.getByText(message)).toBeVisible();
  }
  await page.goto(groupUrl(second.id, "settings"));
  await expect(page.locator("#groupIdentifier")).toHaveValue(second.identifier);
});

test("a refused rename is drawn with the stored identifier, and the same rename asks again", async ({ page, groups }) => {
  const group = await groups.create();
  const renamed = uniqueIdentifier("g");
  const dialog = page.locator("dialog[open]");
  await page.goto(groupUrl(group.id, "settings"));
  await page.locator("#groupIdentifier").fill(renamed);
  await page.locator('input[name="description"]').fill("a <b> tag");
  await page.locator("#btnSave").click();
  await expect(dialog).toContainText("You've modified the group identifier");
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("The description cannot contain the characters < or >.")).toBeVisible();
  await expect(page.getByRole("heading", { name: `Group settings - ${group.identifier}`, exact: true })).toBeVisible();
  await expect(page.locator("#groupIdentifier")).toHaveValue(renamed);

  // Still a rename of the stored group, so Save asks again.
  await page.locator("#btnSave").click();
  await expect(dialog).toContainText("You've modified the group identifier");
  await dialog.getByRole("button", { name: "No" }).click();
  await page.goto(groupUrl(group.id, "settings"));
  await expect(page.locator("#groupIdentifier")).toHaveValue(group.identifier);
});
