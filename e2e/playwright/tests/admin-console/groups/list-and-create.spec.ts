import { deleteGroup, expectRefusal, idFromListLink, rowWithCell, submitNewGroup } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/groups`;

// A list row's cells after the first, which holds the identifier with the description beneath it,
// in the list's column order.
function cells(row: ReturnType<typeof rowWithCell>) {
  return {
    members: row.getByRole("cell").nth(1),
    inTokens: row.getByRole("cell").nth(2),
  };
}

test("a group is created with its description and include switches, and listed", async ({ page }) => {
  const identifier = uniqueIdentifier("g");
  await submitNewGroup(page, { identifier: `  ${identifier}  `, description: "  Editors  ", includeInAccessToken: false });
  await expect(page).toHaveURL(list);
  const row = rowWithCell(page, identifier);
  await expect(row.getByText("Editors", { exact: true })).toBeVisible();
  await expect(cells(row).members).toHaveText("0");
  await expect(cells(row).inTokens).toHaveText("ID token");
  await expect(row.getByRole("link", { name: `Delete ${identifier}`, exact: true })).toBeVisible();

  await deleteGroup(page, await idFromListLink(page, list, identifier));
  await expect(rowWithCell(page, identifier)).toHaveCount(0);
});

test("the new group form starts with both include switches on", async ({ page }) => {
  await page.goto(list);
  await page.getByRole("link", { name: "New group", exact: true }).click();
  await expect(page).toHaveURL(`${list}/new`);
  await expect(page.getByRole("heading", { level: 1, name: "New group", exact: true })).toBeVisible();
  await expect(page.locator('input[name="includeInAccessToken"]')).toBeChecked();
  await expect(page.locator('input[name="includeInIdToken"]')).toBeChecked();
});

const badFormat = "Invalid identifier format.";
for (const { identifier, message } of [
  { identifier: "", message: "Group identifier is required" },
  { identifier: "ab", message: "The identifier must be at least 3 characters long." },
  { identifier: "1abc", message: badFormat },
  { identifier: "abc_", message: badFormat },
  { identifier: "has space", message: badFormat },
  { identifier: `e2e-${"x".repeat(35)}`, message: "The identifier cannot exceed a maximum length of 38 characters." },
]) {
  test(`the identifier ${JSON.stringify(identifier)} is refused, and the form keeps what was typed`, async ({ page }) => {
    await submitNewGroup(page, { identifier, description: "kept" });
    await expect(page).toHaveURL(`${list}/new`);
    await expectRefusal(page, "group-error", "groupIdentifier", message);
    await expect(page.locator("#groupIdentifier")).toHaveValue(identifier);
    await expect(page.locator('input[name="description"]')).toHaveValue("kept");
  });
}

// Were the switches to come back on, fixing the identifier and pressing Create group again would
// create a group the administrator had kept out of the tokens.
test("a refused group keeps the include switches as they were set", async ({ page }) => {
  await submitNewGroup(page, { identifier: "1abc", includeInAccessToken: false, includeInIdToken: false });
  await expectRefusal(page, "group-error", "groupIdentifier", badFormat);
  await expect(page.locator('input[name="includeInAccessToken"]')).not.toBeChecked();
  await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
});

test("an identifier already in use is refused", async ({ page, groups }) => {
  const existing = await groups.create();
  await submitNewGroup(page, { identifier: existing.identifier });
  await expect(page).toHaveURL(`${list}/new`);
  await expectRefusal(page, "group-error", "groupIdentifier", "The group identifier is already in use");
  await page.goto(list);
  await expect(rowWithCell(page, existing.identifier)).toHaveCount(1);
});

for (const { description, message } of [
  { description: "x".repeat(101), message: "The description cannot exceed a maximum length of 100 characters" },
  { description: "<b>bold</b>", message: "The description cannot contain the characters < or >." },
]) {
  test(`the description ${JSON.stringify(description.slice(0, 12))}… is refused`, async ({ page }) => {
    const identifier = uniqueIdentifier("g");
    await submitNewGroup(page, { identifier, description });
    await expect(page).toHaveURL(`${list}/new`);
    await expectRefusal(page, "group-error", "description", message);
    await page.goto(list);
    await expect(rowWithCell(page, identifier)).toHaveCount(0);
  });
}
