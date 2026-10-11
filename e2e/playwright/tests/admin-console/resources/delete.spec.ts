import { idFromListLink, resourceUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const list = `${env.adminUrl}/admin/resources`;

test("deleting needs the identifier typed: empty or wrong is refused, the right one deletes", async ({
  page,
  resources,
}) => {
  const resource = await resources.create({ description: "To be deleted", permissions: ["read", "write"] });
  await page.goto(resourceUrl(resource.id, "delete"));
  // The page shows what goes with it.
  await expect(rowWithCell(page, "Resource identifier").getByRole("cell").nth(1)).toHaveText(resource.identifier);
  await expect(rowWithCell(page, "Resource description").getByRole("cell").nth(1)).toHaveText("To be deleted");
  await expect(rowWithCell(page, "Permissions").getByRole("listitem")).toHaveText(["read", "write"]);

  const input = page.locator('input[name="resourceIdentifier"]');
  const deleteButton = page.getByRole("button", { name: "Delete", exact: true });
  await deleteButton.click();
  await expect(page.getByText("Resource identifier is required.")).toBeVisible();

  await input.fill(`${resource.identifier}-wrong`);
  await deleteButton.click();
  await expect(page.getByText("Resource identifier does not match the resource being deleted.")).toBeVisible();
  // The refusal renders the same page, ready for another try.
  await expect(rowWithCell(page, "Permissions").getByRole("listitem")).toHaveText(["read", "write"]);
  await page.goto(list);
  await expect(rowWithCell(page, resource.identifier)).toHaveCount(1);

  await page.goto(resourceUrl(resource.id, "delete"));
  await input.fill(resource.identifier);
  await deleteButton.click();
  await expect(page).toHaveURL(list);
  await expect(rowWithCell(page, resource.identifier)).toHaveCount(0);
  resource.markDeleted();

  // Gone: its pages answer not found.
  const response = await page.goto(resourceUrl(resource.id, "settings"));
  expect(response?.status()).toBe(404);
});

test("the system resource cannot be deleted", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver", "Manage");
  await page.goto(resourceUrl(id, "delete"));
  await expect(page.getByText("This system-level resource cannot be deleted.")).toBeVisible();
  await expect(page.locator('input[name="resourceIdentifier"]')).toHaveAttribute("readonly", "");
  await expect(page.getByRole("button", { name: "Delete", exact: true })).toHaveCount(0);
});
