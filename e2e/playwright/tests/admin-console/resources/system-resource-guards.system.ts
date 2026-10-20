// The system resource past the admin console's read-only field and hidden buttons, the way a crafted
// request reaches it: only the auth server's guards stop these changes, so they are tried here through
// the console. Were a guard broken the change would land, and the other tests depend on these names,
// so this file runs after all of them, alone (the "system" project in playwright.config.ts), and puts
// back whatever landed before it fails.
//
// The permission tried is admin-read: nobody holds it in this environment, so even a deletion that
// landed is undone in full by creating it again.
import type { Page } from "@playwright/test";
import {
  addResourcePermission,
  confirmDialog,
  idFromListLink,
  resourcePermissionRow,
  resourceUrl,
  rowWithCell,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

test.describe.configure({ mode: "serial" });

const list = `${env.adminUrl}/admin/resources`;
const builtIn = "admin-read";
// What every save of the system resource asks first.
const systemSave = "This is the auth server's own resource: a wrong change can stop administrators from managing Goiabada.";

// Submits the system resource's settings form with this identifier, past the read-only field and the
// page's own confirmation, as a crafted request would.
async function submitIdentifier(page: Page, id: number, identifier: string) {
  await page.goto(resourceUrl(id, "settings"));
  const input = page.locator("#resourceIdentifier");
  await input.evaluate((element) => element.removeAttribute("readonly"));
  await input.fill(identifier);
  await page.locator("form:has(#resourceIdentifier)").evaluate((form: HTMLFormElement) => form.submit());
  await page.waitForLoadState();
}

// Saves the system resource's permissions with one of them renamed to `to`, or removed when `to` is
// null, past the hidden buttons, by changing the row the page's Save reads it from; then answers the
// confirmation every save of the system resource asks with Save.
async function savePermissionChange(page: Page, id: number, from: string, to: string | null) {
  await page.goto(resourceUrl(id, "permissions"));
  await resourcePermissionRow(page, from).evaluate((row: HTMLTableRowElement, to) => {
    if (to === null) row.remove();
    else row.dataset.identifier = to;
  }, to);
  await page.locator("#btnSave").click();
  await confirmDialog(page, systemSave);
}

test("the system resource's identifier cannot be changed, even past the read-only field", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver");
  const attempted = "authserver-renamed";
  try {
    await submitIdentifier(page, id, attempted);
    await expect(page.locator("#resource-error")).toContainText("The identifier of a system-level resource cannot be changed.");
    await expect(page.locator("#resourceIdentifier")).toHaveAttribute("aria-invalid", "true");
    await page.goto(list);
    await expect(rowWithCell(page, "authserver")).toHaveCount(1);
    await expect(rowWithCell(page, attempted)).toHaveCount(0);
  } finally {
    await page.goto(list);
    if ((await rowWithCell(page, attempted).count()) > 0) await submitIdentifier(page, id, "authserver");
  }
});

test("a built-in permission cannot be renamed, even past the hidden edit button", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver");
  const attempted = `${builtIn}-renamed`;
  try {
    await savePermissionChange(page, id, builtIn, attempted);
    await expect(page.locator("#resourcePermissionsStatus")).toContainText(`Built-in permission '${builtIn}' cannot be renamed.`);
    await page.reload();
    await expect(resourcePermissionRow(page, builtIn)).toHaveCount(1);
    await expect(resourcePermissionRow(page, attempted)).toHaveCount(0);
  } finally {
    await page.goto(resourceUrl(id, "permissions"));
    if ((await resourcePermissionRow(page, attempted).count()) > 0) {
      await savePermissionChange(page, id, attempted, builtIn);
    }
  }
});

test("a built-in permission cannot be removed, even past the hidden remove button", async ({ page }) => {
  const id = await idFromListLink(page, list, "authserver");
  try {
    await savePermissionChange(page, id, builtIn, null);
    await expect(page.locator("#resourcePermissionsStatus")).toContainText(`Built-in permission '${builtIn}' cannot be deleted.`);
    await page.reload();
    await expect(resourcePermissionRow(page, builtIn)).toHaveCount(1);
  } finally {
    await page.goto(resourceUrl(id, "permissions"));
    if ((await resourcePermissionRow(page, builtIn).count()) === 0) {
      await addResourcePermission(page, builtIn, "Read-only access to all admin API endpoints");
      await page.locator("#btnSave").click();
      await confirmDialog(page, systemSave);
      await expect(page.getByText("Permissions saved.")).toBeVisible();
    }
  }
});
