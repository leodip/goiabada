import { clientRow, clientUrl, confirmDialog, saveAndExpectSaved } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const saved = "Client settings saved successfully";

test("description, website and display name are saved and shown again", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="description"]').fill("Made by the e2e suite");
  await page.locator('input[name="websiteUrl"]').fill("https://example.com/app");
  await page.locator('input[name="displayName"]').fill("E2E app");
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('input[name="description"]')).toHaveValue("Made by the e2e suite");
  await expect(page.locator('input[name="websiteUrl"]')).toHaveValue("https://example.com/app");
  await expect(page.locator('input[name="displayName"]')).toHaveValue("E2E app");

  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Made by the e2e suite" })).toBeVisible();
});

test("a disabled client shows as disabled in the list, and can be enabled again", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').uncheck();
  // Disabling asks first.
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You've disabled the client");
  await expect(page.getByText(saved)).toBeVisible();

  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Disabled", exact: true })).toBeVisible();

  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').check();
  await saveAndExpectSaved(page, saved);
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Enabled", exact: true })).toBeVisible();
});

test("the default ACR level and consent are saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('select[name="defaultAcrLevel"]').selectOption({ label: "ACR level 3 - password + mandatory OTP" });
  await page.locator('input[name="consentRequired"]').check();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('select[name="defaultAcrLevel"] option:checked')).toHaveText(
    "ACR level 3 - password + mandatory OTP",
  );
  await expect(page.locator('input[name="consentRequired"]')).toBeChecked();
});

test("renaming a client asks first, and the new identifier is what the list shows", async ({ page, clients }) => {
  const client = await clients.create();
  const renamed = `${client.identifier}-r`;
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill(renamed);
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, renamed)).toHaveCount(1);
  await expect(clientRow(page, client.identifier)).toHaveCount(0);
});

// Two confirmations in a row: the rename's, then the administrative scopes'. Both share one <dialog>,
// and the second is opened from the first's Yes, before that Yes closes the dialog.
test("renaming and allowing administrative scopes in one save asks both, then saves both", async ({ page, clients }) => {
  const client = await clients.create();
  const renamed = `${client.identifier}-r`;
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill(renamed);
  await page.locator("#administrativeScopesAllowed").check();
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("You've modified the client identifier");
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(dialog).toContainText("You are allowing this client to request the administrative scopes");
  await dialog.getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(renamed);
  await expect(page.locator("#administrativeScopesAllowed")).toBeChecked();
});

test("an invalid identifier is refused on save, and nothing changes", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill("not valid!");
  await page.locator("#btnSave").click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText(/^Invalid identifier format\./)).toBeVisible();

  await page.goto(clientUrl(client.id, "settings"));
  await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(client.identifier);
});

test("the system client warns that it is system-level", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await clientRow(page, "admin-console-client").getByRole("link", { name: "Manage" }).click();
  await expect(page.getByRole("alert")).toContainText("This is a system-level client.");
  // Saving it asks first. No is pressed: the suite never changes the system client.
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("system-level client");
  await dialog.getByRole("button", { name: "No" }).click();
  await expect(page.getByText(saved)).toHaveCount(0);
});
