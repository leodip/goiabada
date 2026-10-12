import { idFromListLink, resourceUrl, rowWithCell, saveAndExpectSaved } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/resources`;
const saved = "Resource settings saved successfully";

test("the description is saved, and shows on the list", async ({ page, resources }) => {
  const resource = await resources.create({ description: "before" });
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator('input[name="description"]')).toHaveValue("before");
  await page.locator('input[name="description"]').fill("after");
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('input[name="description"]')).toHaveValue("after");
  // The one-time message is gone once read.
  await expect(page.getByText(saved)).toHaveCount(0);
  await page.goto(list);
  await expect(rowWithCell(page, resource.identifier).getByRole("cell", { name: "after", exact: true })).toBeVisible();
});

test("renaming asks first: No keeps the old identifier, Yes saves the new one", async ({ page, resources }) => {
  const resource = await resources.create();
  const renamed = uniqueIdentifier("r");
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill(renamed);

  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("You've modified the resource identifier");
  await dialog.getByRole("button", { name: "No" }).click();
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);

  await page.locator("#resourceIdentifier").fill(renamed);
  await page.locator("#btnSave").click();
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator("#resourceIdentifier")).toHaveValue(renamed);

  await page.goto(list);
  await expect(rowWithCell(page, renamed)).toHaveCount(1);
  await expect(rowWithCell(page, resource.identifier)).toHaveCount(0);
  // Same row, new name: the fixture deletes it by id.
  expect(await idFromListLink(page, list, renamed, "Manage")).toBe(resource.id);
});

test("renaming to an identifier already in use is refused", async ({ page, resources }) => {
  const first = await resources.create();
  const second = await resources.create();
  await page.goto(resourceUrl(second.id, "settings"));
  await page.locator("#resourceIdentifier").fill(first.identifier);
  await page.locator("#btnSave").click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("The resource identifier is already in use")).toBeVisible();

  await page.goto(resourceUrl(second.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(second.identifier);
});

test("an invalid identifier or description is refused on save", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill("not valid");
  await page.locator("#btnSave").click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("Invalid identifier format.")).toBeVisible();

  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator('input[name="description"]').fill("a <script> tag");
  await page.locator("#btnSave").click();
  await expect(page.getByText("The description cannot contain the characters < or >.")).toBeVisible();

  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);
  await expect(page.locator('input[name="description"]')).toHaveValue("");
});

test("a refused rename is drawn with the stored identifier, and the same rename asks again", async ({ page, resources }) => {
  const resource = await resources.create();
  const renamed = uniqueIdentifier("r");
  const dialog = page.locator("dialog[open]");
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill(renamed);
  await page.locator('input[name="description"]').fill("a <script> tag");
  await page.locator("#btnSave").click();
  await expect(dialog).toContainText("You've modified the resource identifier");
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("The description cannot contain the characters < or >.")).toBeVisible();
  await expect(page.getByRole("heading", { name: `Resource settings - ${resource.identifier}`, exact: true })).toBeVisible();
  await expect(page.locator("#resourceIdentifier")).toHaveValue(renamed);

  // Still a rename of the stored resource, so Save asks again.
  await page.locator("#btnSave").click();
  await expect(dialog).toContainText("You've modified the resource identifier");
  await dialog.getByRole("button", { name: "No" }).click();
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);
});

test("the system resource warns, keeps its identifier read-only, and asks before saving", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver", "Manage");
  await page.goto(resourceUrl(id, "settings"));
  await expect(page.getByText("This is a system-level resource.")).toBeVisible();
  await expect(page.locator("#resourceIdentifier")).toHaveAttribute("readonly", "");

  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("You are about to modify a system-level resource.");
  // No: nothing of the system resource changes in a shared environment.
  await dialog.getByRole("button", { name: "No" }).click();
  await expect(dialog).toBeHidden();
  await expect(page).toHaveURL(resourceUrl(id, "settings"));
  await expect(page.getByText(saved)).toHaveCount(0);
});
