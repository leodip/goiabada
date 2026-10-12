import { addGroupAttribute, groupUrl, rowWithCell, submitGroupAttributeForm } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const attributeRows = "#attributesTable tbody tr";

test("a new group has no attributes", async ({ page, groups }) => {
  const group = await groups.create();
  await page.goto(groupUrl(group.id, "attributes"));
  await expect(page.locator(attributeRows)).toHaveText(["No attributes attached to group."]);
});

test("an attribute is added, edited and removed", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales", includeInIdToken: false });
  let row = rowWithCell(page, "department");
  await expect(row.getByRole("cell").nth(1)).toHaveText("Sales");
  await expect(row.getByRole("cell").nth(2)).toHaveText("Yes");
  await expect(row.getByRole("cell").nth(3)).toHaveText("No");

  await row.getByRole("button", { name: "Edit" }).click();
  await expect(page.locator("#attributeKey")).toHaveValue("department");
  await expect(page.locator('input[name="attributeValue"]')).toHaveValue("Sales");
  await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
  await submitGroupAttributeForm(page, { key: "team", value: "Inside sales", includeInAccessToken: false, includeInIdToken: true });
  await expect(page).toHaveURL(groupUrl(group.id, "attributes"));
  await expect(rowWithCell(page, "department")).toHaveCount(0);
  row = rowWithCell(page, "team");
  await expect(row.getByRole("cell").nth(1)).toHaveText("Inside sales");
  await expect(row.getByRole("cell").nth(2)).toHaveText("No");
  await expect(row.getByRole("cell").nth(3)).toHaveText("Yes");

  await row.getByRole("button", { name: "Remove" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("team");
  await expect(dialog).toContainText(group.identifier);
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(row.getByText("Removed")).toBeVisible();
  await page.reload();
  await expect(page.locator(attributeRows)).toHaveText(["No attributes attached to group."]);
});

test("removing an attribute can be cancelled", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  await rowWithCell(page, "department").getByRole("button", { name: "Remove" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "No" }).click();
  await page.reload();
  await expect(rowWithCell(page, "department")).toHaveCount(1);
});

test("a refused edit keeps the typed key, and the title names the stored one", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  await rowWithCell(page, "department").getByRole("button", { name: "Edit" }).click();
  await submitGroupAttributeForm(page, { key: "not valid", value: "Sales" });
  await expect(page.getByText("Invalid identifier format.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Edit group attribute - department", exact: true })).toBeVisible();
  await expect(page.locator("#attributeKey")).toHaveValue("not valid");
  await page.goto(groupUrl(group.id, "attributes"));
  await expect(rowWithCell(page, "department")).toHaveCount(1);
});

for (const { key, value, message } of [
  { key: "", value: "x", message: "Attribute key is required" },
  { key: "not valid", value: "x", message: "Invalid identifier format." },
  { key: "department", value: "x".repeat(251), message: "The attribute value cannot exceed a maximum length of 250 characters" },
  { key: "department", value: "<b>x</b>", message: "The attribute value cannot contain the characters < or >." },
]) {
  test(`the attribute ${JSON.stringify(key)} = ${JSON.stringify(value.slice(0, 10))}… is refused, and the form keeps it`, async ({
    page,
    groups,
  }) => {
    const group = await groups.create();
    await page.goto(`${env.adminUrl}/admin/groups/${group.id}/attributes/add`);
    await submitGroupAttributeForm(page, { key, value, includeInAccessToken: false });
    await expect(page.getByText(message)).toBeVisible();
    await expect(page.locator("#attributeKey")).toHaveValue(key);
    await expect(page.locator('input[name="attributeValue"]')).toHaveValue(value);
    await expect(page.locator('input[name="includeInAccessToken"]')).not.toBeChecked();
    await page.goto(groupUrl(group.id, "attributes"));
    await expect(page.locator(attributeRows)).toHaveText(["No attributes attached to group."]);
  });
}
