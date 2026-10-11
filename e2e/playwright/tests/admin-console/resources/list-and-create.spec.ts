import { deleteResource, idFromListLink, rowWithCell, submitNewResource } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/resources`;

test("the list shows the system resource, which offers no Delete", async ({ page }) => {
  await page.goto(list);
  const row = rowWithCell(page, "authserver");
  await expect(row).toHaveCount(1);
  await expect(row.getByRole("link", { name: "Manage" })).toBeVisible();
  await expect(row.getByRole("link", { name: "Delete" })).toHaveCount(0);
});

test("a resource is created with its description, trimmed, and listed", async ({ page }) => {
  const identifier = uniqueIdentifier("r");
  await submitNewResource(page, `  ${identifier}  `, "  An e2e resource  ");
  await expect(page).toHaveURL(list);
  const row = rowWithCell(page, identifier);
  await expect(row).toHaveCount(1);
  await expect(row.getByRole("cell", { name: "An e2e resource", exact: true })).toBeVisible();
  await expect(row.getByRole("link", { name: "Delete" })).toBeVisible();

  await deleteResource(page, await idFromListLink(page, list, identifier, "Manage"));
  await expect(rowWithCell(page, identifier)).toHaveCount(0);
});

const tooShort = "The identifier must be at least 3 characters long.";
const badFormat = "Invalid identifier format.";
for (const { identifier, message } of [
  { identifier: "", message: "Resource identifier is required" },
  { identifier: "ab", message: tooShort },
  { identifier: "1abc", message: badFormat },
  { identifier: "abc-", message: badFormat },
  { identifier: "a--bc", message: badFormat },
  { identifier: "has space", message: badFormat },
  { identifier: `e2e-${"x".repeat(35)}`, message: "The identifier cannot exceed a maximum length of 38 characters." },
]) {
  test(`the identifier ${JSON.stringify(identifier)} is refused, and the form keeps what was typed`, async ({ page }) => {
    await submitNewResource(page, identifier, "kept");
    await expect(page).toHaveURL(`${list}/new`);
    await expect(page.getByText(message)).toBeVisible();
    await expect(page.locator("#resourceIdentifier")).toHaveValue(identifier);
    await expect(page.locator('input[name="description"]')).toHaveValue("kept");
  });
}

test("an identifier already in use is refused", async ({ page, resources }) => {
  const existing = await resources.create();
  await submitNewResource(page, existing.identifier);
  await expect(page).toHaveURL(`${list}/new`);
  await expect(page.getByText("The resource identifier is already in use")).toBeVisible();
  await page.goto(list);
  await expect(rowWithCell(page, existing.identifier)).toHaveCount(1);
});

for (const { description, message } of [
  { description: "x".repeat(101), message: "The description cannot exceed a maximum length of 100 characters" },
  { description: "<b>bold</b>", message: "The description cannot contain the characters < or >." },
]) {
  test(`the description ${JSON.stringify(description.slice(0, 12))}… is refused`, async ({ page }) => {
    const identifier = uniqueIdentifier("r");
    await submitNewResource(page, identifier, description);
    await expect(page).toHaveURL(`${list}/new`);
    await expect(page.getByText(message)).toBeVisible();
    await page.goto(list);
    await expect(rowWithCell(page, identifier)).toHaveCount(0);
  });
}
