import { cancelDialog, clientIdFromList, clientRow, clientUrl, confirmDialog, saveAndExpectSaved } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const saved = "Settings saved.";

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

  // The list shows the description beneath the identifier.
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByText("Made by the e2e suite", { exact: true })).toBeVisible();
});

test("a website URL that is not http or https is refused at its field, and nothing changes", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="websiteUrl"]').fill("ftp://files.example.com");
  await page.locator("#btnSave").click();
  await expect(page.locator("#client-error")).toContainText("Website URL must use http or https scheme.");
  await expect(page.locator("#websiteUrl")).toHaveAttribute("aria-invalid", "true");

  await page.goto(clientUrl(client.id, "settings"));
  await expect(page.locator('input[name="websiteUrl"]')).toHaveValue("");
});

test("a disabled client shows as disabled in the list, and can be enabled again", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').uncheck();
  // Disabling asks first.
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're disabling the client");
  await expect(page.getByText(saved)).toBeVisible();

  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByText("Disabled", { exact: true })).toBeVisible();

  // Enabling asks nothing.
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').check();
  await saveAndExpectSaved(page, saved);
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByText("Disabled", { exact: true })).toHaveCount(0);
});

test("the default ACR level and consent are saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('select[name="defaultAcrLevel"]').selectOption({ label: "Level 3: password and a one-time code, always" });
  await page.getByRole("checkbox", { name: /^Ask users for consent/ }).check();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('select[name="defaultAcrLevel"] option:checked')).toHaveText("Level 3: password and a one-time code, always");
  await expect(page.locator('input[name="consentRequired"]')).toBeChecked();
});

test("renaming a client asks first, and the new identifier is what the list shows", async ({ page, clients }) => {
  const client = await clients.create();
  const renamed = `${client.identifier}-r`;
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill(renamed);
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're changing the client identifier");
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: renamed })).toBeVisible();

  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, renamed)).toHaveCount(1);
  await expect(clientRow(page, client.identifier)).toHaveCount(0);
});

// Every consequence of one save is asked in one question, one sentence each.
test("renaming and allowing administrative scopes in one save asks about both at once, then saves both", async ({ page, clients }) => {
  const client = await clients.create();
  const renamed = `${client.identifier}-r`;
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill(renamed);
  await page.locator("#administrativeScopesAllowed").check();
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog.getByRole("heading", { name: "Save these changes?" })).toBeVisible();
  await expect(dialog.getByRole("listitem")).toHaveCount(2);
  await expect(dialog).toContainText("You're changing the client identifier");
  await confirmDialog(page, "You're allowing the client to request the administrative scopes");
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(renamed);
  await expect(page.locator("#administrativeScopesAllowed")).toBeChecked();
});

test("disabling and allowing administrative scopes in one save asks about both at once, then saves both", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').uncheck();
  await page.locator("#administrativeScopesAllowed").check();
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog.getByRole("listitem")).toHaveCount(2);
  await expect(dialog).toContainText("You're disabling the client");
  await confirmDialog(page, "You're allowing the client to request the administrative scopes");
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="enabled"]')).not.toBeChecked();
  await expect(page.locator("#administrativeScopesAllowed")).toBeChecked();
});

test("an invalid identifier is refused on save, and nothing changes", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="clientIdentifier"]').fill("not valid!");
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're changing the client identifier");
  await expect(page.locator("#client-error")).toContainText(/^Invalid identifier format\./);
  await expect(page.locator("#clientIdentifier")).toHaveAttribute("aria-invalid", "true");
  // The heading still names the client as stored.
  await expect(page.getByRole("heading", { level: 1, name: client.identifier })).toBeVisible();

  await page.goto(clientUrl(client.id, "settings"));
  await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(client.identifier);
});

test("the system client warns that it is the admin console's own, and keeps its identifier and allowance", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await clientRow(page, "admin-console-client").getByRole("link", { name: "admin-console-client", exact: true }).click();
  await expect(
    page.getByText("This is the admin console's own client. A wrong change here can stop administrators from signing in to the admin console."),
  ).toBeVisible();
  await expect(page.locator("#clientIdentifier")).not.toBeEditable();
  await expect(page.locator("#administrativeScopesAllowed")).toBeDisabled();
  await expect(page.getByText("The admin console's client may always request the administrative scopes.")).toBeVisible();
  // Saving it asks first. Cancel is pressed: the suite never changes the system client.
  await page.locator("#btnSave").click();
  await cancelDialog(page, "This is the admin console's own client: a wrong change can stop administrators");
  await expect(page.getByText(saved)).toHaveCount(0);
});

// The system client's disable is asked together with the warning every save of it carries. Cancel
// saves nothing: the suite never changes the system client.
test("disabling the system client asks with the system warning too, and Cancel saves nothing", async ({ page }) => {
  await page.goto(clientUrl(await clientIdFromList(page, "admin-console-client"), "settings"));
  await page.locator('input[name="enabled"]').uncheck();
  await page.locator("#btnSave").click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog.getByRole("listitem")).toHaveCount(2);
  await expect(dialog).toContainText("You're disabling the client");
  await cancelDialog(page, "This is the admin console's own client: a wrong change");
  await expect(page.getByText(saved)).toHaveCount(0);

  // A fresh navigation, not a reload, which could restore the unchecked box from the page.
  await page.goto(page.url());
  await expect(page.locator('input[name="enabled"]')).toBeChecked();
});
