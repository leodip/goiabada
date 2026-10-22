import {
  cancelDialog,
  confirmDialog,
  expectRefusal,
  idFromListLink,
  type ResourceTab,
  resourceUrl,
  rowWithCell,
  saveAndExpectSaved,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/resources`;
const saved = "Settings saved.";
// What the one confirmation says about a rename.
const renaming = "You're changing the resource identifier";
const systemCaution =
  "This is the auth server's own resource. Its built-in permissions can't be renamed or deleted, and a wrong change can stop administrators from managing Goiabada.";

test("the description is saved, and shows on the list", async ({ page, resources }) => {
  const resource = await resources.create({ description: "before" });
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page).toHaveTitle(new RegExp(`^Settings – ${resource.identifier} – `));
  await expect(page.locator('input[name="description"]')).toHaveValue("before");
  await page.locator('input[name="description"]').fill("after");
  // Nothing renamed, so nothing to ask.
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('input[name="description"]')).toHaveValue("after");
  // The one-time message is gone once read.
  await expect(page.getByText(saved)).toHaveCount(0);
  await page.goto(list);
  await expect(rowWithCell(page, resource.identifier).getByText("after", { exact: true })).toBeVisible();
});

test("renaming asks first: Cancel keeps the old identifier, Save saves the new one", async ({ page, resources }) => {
  const resource = await resources.create();
  const renamed = uniqueIdentifier("r");
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill(renamed);

  await page.locator("#btnSave").click();
  await cancelDialog(page, renaming);
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);

  await page.locator("#resourceIdentifier").fill(renamed);
  await page.locator("#btnSave").click();
  await confirmDialog(page, renaming);
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator("#resourceIdentifier")).toHaveValue(renamed);
  await expect(page.getByRole("heading", { level: 1, name: renamed, exact: true })).toBeVisible();

  await page.goto(list);
  await expect(rowWithCell(page, renamed)).toHaveCount(1);
  await expect(rowWithCell(page, resource.identifier)).toHaveCount(0);
  // Same row, new name: the fixture deletes it by id.
  expect(await idFromListLink(page, list, renamed)).toBe(resource.id);
});

test("renaming to an identifier already in use is refused", async ({ page, resources }) => {
  const first = await resources.create();
  const second = await resources.create();
  await page.goto(resourceUrl(second.id, "settings"));
  await page.locator("#resourceIdentifier").fill(first.identifier);
  await page.locator("#btnSave").click();
  await confirmDialog(page, renaming);
  await expectRefusal(page, "resource-error", "resourceIdentifier", "The resource identifier is already in use");

  await page.goto(resourceUrl(second.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(second.identifier);
});

test("an invalid identifier or description is refused on save", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill("not valid");
  await page.locator("#btnSave").click();
  await confirmDialog(page, renaming);
  await expectRefusal(page, "resource-error", "resourceIdentifier", "Invalid identifier format.");

  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator('input[name="description"]').fill("a <script> tag");
  await page.locator("#btnSave").click();
  await expectRefusal(page, "resource-error", "description", "The description cannot contain the characters < or >.");

  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);
  await expect(page.locator('input[name="description"]')).toHaveValue("");
});

test("a refused rename is drawn with the stored identifier, and the same rename asks again", async ({ page, resources }) => {
  const resource = await resources.create();
  const renamed = uniqueIdentifier("r");
  await page.goto(resourceUrl(resource.id, "settings"));
  await page.locator("#resourceIdentifier").fill(renamed);
  await page.locator('input[name="description"]').fill("a <script> tag");
  await page.locator("#btnSave").click();
  await confirmDialog(page, renaming);
  await expectRefusal(page, "resource-error", "description", "The description cannot contain the characters < or >.");
  await expect(page.getByRole("heading", { level: 1, name: resource.identifier, exact: true })).toBeVisible();
  await expect(page).toHaveTitle(new RegExp(`^Settings – ${resource.identifier} – `));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(renamed);

  // Still a rename of the stored resource, so Save asks again.
  await page.locator("#btnSave").click();
  await cancelDialog(page, renaming);
  await page.goto(resourceUrl(resource.id, "settings"));
  await expect(page.locator("#resourceIdentifier")).toHaveValue(resource.identifier);
});

test("the system resource warns, keeps its identifier read-only, and asks before saving", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver");
  await page.goto(resourceUrl(id, "settings"));
  await expect(page.getByText(systemCaution)).toBeVisible();
  await expect(page.locator("#resourceIdentifier")).toHaveAttribute("readonly", "");

  await page.locator("#btnSave").click();
  // Cancel: nothing of the system resource changes in a shared environment.
  await cancelDialog(page, "This is the auth server's own resource: a wrong change can stop administrators from managing Goiabada.");
  await expect(page).toHaveURL(resourceUrl(id, "settings"));
  await expect(page.getByText(saved)).toHaveCount(0);
});

test("the system resource's caution shows on every tab", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver");
  for (const tab of ["settings", "permissions", "groups-with-permission", "users-with-permission"] satisfies ResourceTab[]) {
    await page.goto(resourceUrl(id, tab));
    await expect(page.getByText(systemCaution)).toBeVisible();
  }
});
