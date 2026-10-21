import {
  addGroupAttribute,
  cancelDialog,
  confirmDialog,
  expectRefusal,
  groupUrl,
  rowWithCell,
  submitGroupAttributeForm,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const empty = "No attributes yet.";

// A row's cells after the key: its value, and the tokens it is in.
function cells(row: ReturnType<typeof rowWithCell>) {
  return { value: row.getByRole("cell").nth(1), inTokens: row.getByRole("cell").nth(2) };
}

test("a new group has no attributes", async ({ page, groups }) => {
  const group = await groups.create();
  await page.goto(groupUrl(group.id, "attributes"));
  await expect(page.getByText(empty)).toBeVisible();
  await expect(page.locator("#attributesTable")).toHaveCount(0);
});

test("an attribute is added, edited and removed", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales", includeInIdToken: false });
  let row = rowWithCell(page, "department");
  await expect(cells(row).value).toHaveText("Sales");
  await expect(cells(row).inTokens).toHaveText("Access token");

  // The key is the link to its edit form.
  await row.getByRole("link", { name: "department", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Edit attribute department", exact: true })).toBeVisible();
  await expect(page.locator("#attributeKey")).toHaveValue("department");
  await expect(page.locator('input[name="attributeValue"]')).toHaveValue("Sales");
  await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
  await submitGroupAttributeForm(page, { key: "team", value: "Inside sales", includeInAccessToken: false, includeInIdToken: true });
  await expect(page).toHaveURL(groupUrl(group.id, "attributes"));
  await expect(rowWithCell(page, "department")).toHaveCount(0);
  row = rowWithCell(page, "team");
  await expect(cells(row).value).toHaveText("Inside sales");
  await expect(cells(row).inTokens).toHaveText("ID token");

  await row.getByRole("button", { name: "Remove team", exact: true }).click();
  await confirmDialog(page, "Remove the attribute team?");
  await expect(row.getByText("Removed", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Attribute removed.");
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
});

test("removing an attribute can be cancelled", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  const remove = rowWithCell(page, "department").getByRole("button", { name: "Remove department", exact: true });
  await remove.click();
  await cancelDialog(page, "Remove the attribute department?");
  await expect(remove).toBeVisible();
  await page.reload();
  await expect(rowWithCell(page, "department")).toHaveCount(1);
});

test("Cancel on the edit form leaves the attribute as it was", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  await rowWithCell(page, "department").getByRole("link", { name: "department", exact: true }).click();
  await page.locator('input[name="attributeValue"]').fill("Marketing");
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(groupUrl(group.id, "attributes"));
  await expect(cells(rowWithCell(page, "department")).value).toHaveText("Sales");
});

test("a refused edit keeps the typed key, and the title names the stored one", async ({ page, groups }) => {
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "Sales" });
  await rowWithCell(page, "department").getByRole("link", { name: "department", exact: true }).click();
  await submitGroupAttributeForm(page, { key: "not valid", value: "Sales" });
  await expectRefusal(page, "attribute-error", "attributeKey", "Invalid identifier format.");
  await expect(page.getByRole("heading", { name: "Edit attribute department", exact: true })).toBeVisible();
  await expect(page).toHaveTitle(new RegExp(`^Edit attribute department – ${group.identifier} – `));
  await expect(page.locator("#attributeKey")).toHaveValue("not valid");
  await page.goto(groupUrl(group.id, "attributes"));
  await expect(rowWithCell(page, "department")).toHaveCount(1);
});

for (const { key, value, field, message } of [
  { key: "", value: "x", field: "attributeKey", message: "Attribute key is required" },
  { key: "not valid", value: "x", field: "attributeKey", message: "Invalid identifier format." },
  {
    key: "department",
    value: "x".repeat(251),
    field: "attributeValue",
    message: "The attribute value cannot exceed a maximum length of 250 characters",
  },
  { key: "department", value: "<b>x</b>", field: "attributeValue", message: "The attribute value cannot contain the characters < or >." },
] as const) {
  test(`the attribute ${JSON.stringify(key)} = ${JSON.stringify(value.slice(0, 10))}… is refused, and the form keeps it`, async ({
    page,
    groups,
  }) => {
    const group = await groups.create();
    await page.goto(`${env.adminUrl}/admin/groups/${group.id}/attributes/add`);
    await expect(page.getByRole("heading", { name: "New attribute", exact: true })).toBeVisible();
    await submitGroupAttributeForm(page, { key, value, includeInAccessToken: false });
    await expectRefusal(page, "attribute-error", field, message);
    await expect(page.locator("#attributeKey")).toHaveValue(key);
    await expect(page.locator('input[name="attributeValue"]')).toHaveValue(value);
    await expect(page.locator('input[name="includeInAccessToken"]')).not.toBeChecked();
    await page.goto(groupUrl(group.id, "attributes"));
    await expect(page.getByText(empty)).toBeVisible();
  });
}
