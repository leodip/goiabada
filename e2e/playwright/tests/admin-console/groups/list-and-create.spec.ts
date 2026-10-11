import { deleteGroup, idFromListLink, rowWithCell, submitNewGroup } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/groups`;

// A list row's cells, in the list's column order.
function cells(row: ReturnType<typeof rowWithCell>) {
  return {
    description: row.getByRole("cell").nth(1),
    inAccessToken: row.getByRole("cell").nth(2),
    inIdToken: row.getByRole("cell").nth(3),
    members: row.getByRole("cell").nth(4),
  };
}

test("a group is created with its description and include switches, and listed", async ({ page }) => {
  const identifier = uniqueIdentifier("g");
  await submitNewGroup(page, { identifier: `  ${identifier}  `, description: "  Editors  ", includeInAccessToken: false });
  await expect(page).toHaveURL(list);
  const row = cells(rowWithCell(page, identifier));
  await expect(row.description).toHaveText("Editors");
  await expect(row.inAccessToken).toHaveText("No");
  await expect(row.inIdToken).toHaveText("Yes");
  await expect(row.members).toHaveText("0");

  await deleteGroup(page, await idFromListLink(page, list, identifier, "Manage"));
  await expect(rowWithCell(page, identifier)).toHaveCount(0);
});

test("the new group form starts with both include switches on", async ({ page }) => {
  await page.goto(`${list}/new`);
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
    await expect(page.getByText(message)).toBeVisible();
    await expect(page.locator("#groupIdentifier")).toHaveValue(identifier);
    await expect(page.locator('input[name="description"]')).toHaveValue("kept");
  });
}

// Were the switches to come back on, fixing the identifier and pressing Create again would create a
// group the administrator had kept out of the tokens.
test("a refused group keeps the include switches as they were set", async ({ page }) => {
  await submitNewGroup(page, { identifier: "1abc", includeInAccessToken: false, includeInIdToken: false });
  await expect(page.getByText(badFormat)).toBeVisible();
  await expect(page.locator('input[name="includeInAccessToken"]')).not.toBeChecked();
  await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
});

test("an identifier already in use is refused", async ({ page, groups }) => {
  const existing = await groups.create();
  await submitNewGroup(page, { identifier: existing.identifier });
  await expect(page).toHaveURL(`${list}/new`);
  await expect(page.getByText("The group identifier is already in use")).toBeVisible();
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
    await expect(page.getByText(message)).toBeVisible();
    await page.goto(list);
    await expect(rowWithCell(page, identifier)).toHaveCount(0);
  });
}
