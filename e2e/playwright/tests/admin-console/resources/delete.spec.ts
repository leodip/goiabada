import { detail, idFromListLink, resourceUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const list = `${env.adminUrl}/admin/resources`;

test("deleting needs the identifier typed: empty or wrong is refused, the right one deletes", async ({
  page,
  resources,
}) => {
  const resource = await resources.create({ description: "To be deleted", permissions: ["read", "write"] });
  // The list's Delete link, named for the resource, opens its delete page, which shows what goes.
  await page.goto(list);
  await rowWithCell(page, resource.identifier).getByRole("link", { name: `Delete ${resource.identifier}`, exact: true }).click();
  await expect(page).toHaveURL(resourceUrl(resource.id, "delete"));
  await expect(page).toHaveTitle(new RegExp(`^Delete resource – ${resource.identifier} – `));
  await expect(detail(page, "Resource identifier")).toHaveText(resource.identifier);
  await expect(detail(page, "Description")).toHaveText("To be deleted");
  await expect(detail(page, "Permissions").getByRole("listitem")).toHaveText(["read", "write"]);

  const input = page.getByLabel("To confirm, type the resource identifier");
  const deleteButton = page.getByRole("button", { name: "Delete resource", exact: true });
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("Type the resource identifier to confirm.");
  await expect(input).toHaveAttribute("aria-invalid", "true");

  await input.fill(`${resource.identifier}-wrong`);
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("That isn't this resource's identifier. Type it as shown above.");
  // The refusal renders the same page, ready for another try.
  await expect(detail(page, "Permissions").getByRole("listitem")).toHaveText(["read", "write"]);
  // Cancel goes back to the list, the resource still in it.
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(list);
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
  const id = await idFromListLink(page, list, "authserver");
  await page.goto(resourceUrl(id, "delete"));
  await expect(page.getByText("This is the auth server's own resource, so it can't be deleted.")).toBeVisible();
  await expect(detail(page, "Resource identifier")).toHaveText("authserver");
  // No field to type into and no Delete button: only the way back.
  await expect(page.locator("#resourceIdentifier")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete resource" })).toHaveCount(0);
  await page.getByRole("link", { name: "Back to resources", exact: true }).click();
  await expect(page).toHaveURL(list);
});
