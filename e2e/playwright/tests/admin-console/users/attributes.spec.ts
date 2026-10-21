import { addGroupAttribute, addGroupMember, cancelDialog, confirmDialog, expectRefusal, rowWithCell, userUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import type { Page } from "@playwright/test";

const empty = "No attributes yet.";

async function submitAttribute(page: Page, a: { key: string; value: string; accessToken?: boolean; idToken?: boolean }) {
  await page.locator("#attributeKey").fill(a.key);
  await page.locator('input[name="attributeValue"]').fill(a.value);
  await page.locator('input[name="includeInAccessToken"]').setChecked(a.accessToken ?? true);
  await page.locator('input[name="includeInIdToken"]').setChecked(a.idToken ?? true);
  await page.locator("#btnSave").click();
}

async function addAttribute(page: Page, userId: number, a: Parameters<typeof submitAttribute>[1]) {
  await page.goto(`${env.adminUrl}/admin/users/${userId}/attributes/add`);
  await submitAttribute(page, a);
  // The list, not the form it was added from.
  await expect(page).toHaveURL(new RegExp(`/admin/users/${userId}/attributes(\\?|$)`));
}

test("an attribute is added, edited and removed", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "attributes"));
  await expect(page.getByText(empty)).toBeVisible();

  await addAttribute(page, user.id, { key: "employee_id", value: "E-1001", idToken: false });
  let row = rowWithCell(page, "employee_id");
  await expect(row.getByRole("cell").nth(1)).toHaveText("E-1001");
  await expect(row.getByRole("cell").nth(2)).toHaveText("Access token");

  // The key is the link to its edit form.
  await row.getByRole("link", { name: "employee_id", exact: true }).click();
  await expect(page.locator("#attributeKey")).toHaveValue("employee_id");
  await submitAttribute(page, { key: "employee_number", value: "1001", accessToken: false });
  row = rowWithCell(page, "employee_number");
  await expect(row.getByRole("cell").nth(1)).toHaveText("1001");
  await expect(row.getByRole("cell").nth(2)).toHaveText("ID token");

  // Remove asks first, and Cancel keeps the attribute.
  const remove = row.getByRole("button", { name: "Remove employee_number", exact: true });
  await remove.click();
  await cancelDialog(page, "Remove the attribute employee_number?");
  await page.reload();
  await expect(remove).toBeVisible();

  await remove.click();
  await confirmDialog(page, "Remove the attribute employee_number?");
  // The row stays until the page is drawn again, its button giving way to a tag.
  await expect(row.getByText("Removed", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toContainText("Attribute removed.");
  await page.reload();
  await expect(page.getByText(empty)).toBeVisible();
});

for (const { key, value, field, message } of [
  { key: "", value: "x", field: "attributeKey", message: "Attribute key is required" },
  { key: "not valid", value: "x", field: "attributeKey", message: "Invalid identifier format." },
  { key: "employee_id", value: "x".repeat(251), field: "attributeValue", message: "The attribute value cannot exceed a maximum length of 250 characters" },
  { key: "employee_id", value: "<i>x</i>", field: "attributeValue", message: "The attribute value cannot contain the characters < or >." },
]) {
  test(`the attribute ${JSON.stringify(key)} = ${JSON.stringify(value.slice(0, 10))}… is refused, and the form keeps it`, async ({
    page,
    users,
  }) => {
    const user = await users.create();
    await page.goto(`${env.adminUrl}/admin/users/${user.id}/attributes/add`);
    await submitAttribute(page, { key, value, idToken: false });
    await expectRefusal(page, "attribute-error", field, message);
    await expect(page.locator("#attributeKey")).toHaveValue(key);
    await expect(page.locator('input[name="attributeValue"]')).toHaveValue(value);
    await expect(page.locator('input[name="includeInIdToken"]')).not.toBeChecked();
  });
}

test("a refused edit keeps the typed key, and the title names the stored one", async ({ page, users }) => {
  const user = await users.create();
  await addAttribute(page, user.id, { key: "employee_id", value: "E-1001" });
  await rowWithCell(page, "employee_id").getByRole("link", { name: "employee_id", exact: true }).click();
  await submitAttribute(page, { key: "not valid", value: "E-1001" });
  await expectRefusal(page, "attribute-error", "attributeKey", "Invalid identifier format.");
  await expect(page.getByRole("heading", { name: "Edit attribute employee_id", exact: true })).toBeVisible();
  await expect(page.locator("#attributeKey")).toHaveValue("not valid");
  await page.goto(userUrl(user.id, "attributes"));
  await expect(rowWithCell(page, "employee_id")).toHaveCount(1);
});

test("user attributes reach the attributes claim, and a group's attribute wins a shared key", async ({
  page,
  request,
  clients,
  groups,
  users,
}) => {
  const user = await users.create();
  await addAttribute(page, user.id, { key: "employee_id", value: "E-1001" });
  await addAttribute(page, user.id, { key: "office", value: "Lisbon", accessToken: false });
  await addAttribute(page, user.id, { key: "department", value: "from the user" });
  const group = await groups.create();
  await addGroupAttribute(page, group.id, { key: "department", value: "from the group" });
  await addGroupMember(page, group.id, user.email);

  const { client, secret } = await passwordGrantClient(page, clients);
  const tokens = await userTokens(request, client.identifier, secret, user, "openid attributes");
  expect(tokens.access.attributes).toEqual({ employee_id: "E-1001", department: "from the group" });
  expect(tokens.id.attributes).toEqual({ employee_id: "E-1001", office: "Lisbon", department: "from the group" });
});
