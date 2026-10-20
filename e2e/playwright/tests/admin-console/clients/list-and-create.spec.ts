import { clientIdFromList, clientRow, clientUrl, deleteClient, expectRefusal, submitNewClient } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

test("the list shows the seeded admin console client as the system's, and its identifier opens it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(page.getByRole("heading", { level: 1, name: "Clients" })).toBeVisible();
  const row = clientRow(page, "admin-console-client");
  await expect(row.getByText("System", { exact: true })).toBeVisible();
  await expect(row.getByRole("cell", { name: "Confidential", exact: true })).toBeVisible();

  await row.getByRole("link", { name: "admin-console-client", exact: true }).click();
  await expect(page).toHaveURL(/\/admin\/clients\/\d+\/settings$/);
  await expect(page.getByRole("heading", { level: 1, name: "admin-console-client" })).toBeVisible();
  await expect(page).toHaveTitle(/^Settings – admin-console-client – /);
  const tabs = page.getByRole("navigation", { name: "Sections" });
  await expect(tabs.getByRole("link", { name: "Settings", exact: true })).toHaveAttribute("aria-current", "page");
});

test("New client opens the form with the authorization code flow ticked, and Cancel goes back to the list", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await page.getByRole("link", { name: "New client" }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients/new`);
  await expect(page.getByRole("heading", { level: 1, name: "New client" })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: /^Authorization code with PKCE/ })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: /^Client credentials/ })).not.toBeChecked();

  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
});

test("a new client with the defaults lands in the list, confidential, with the authorization code flow", async ({
  page,
  clients,
}) => {
  const client = await clients.create();
  await page.goto(`${env.adminUrl}/admin/clients`);
  const row = clientRow(page, client.identifier);
  await expect(row.getByRole("cell", { name: "Confidential", exact: true })).toBeVisible();
  // Only a disabled client carries a tag saying so.
  await expect(row.getByText("Disabled", { exact: true })).toHaveCount(0);

  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await expect(page.locator('input[name="authCodeEnabled"]')).toBeChecked();
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).not.toBeChecked();
});

test("a new client can have the client credentials flow alone", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await expect(page.locator('input[name="authCodeEnabled"]')).not.toBeChecked();
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).toBeChecked();
});

test("a new client's display name is kept", async ({ page, clients }) => {
  const client = await clients.create({ displayName: "E2E display name" });
  await page.goto(clientUrl(client.id, "settings"));
  await expect(page.locator('input[name="displayName"]')).toHaveValue("E2E display name");
});

for (const { identifier, message } of [
  { identifier: "", message: "Client identifier is required." },
  { identifier: "ab", message: "The identifier must be at least 3 characters long." },
  { identifier: "has space", message: /^Invalid identifier format\./ },
  { identifier: "1starts-with-a-digit", message: /^Invalid identifier format\./ },
  { identifier: "ends-with-a-dash-", message: /^Invalid identifier format\./ },
  { identifier: `e2e-${"x".repeat(40)}`, message: "The identifier cannot exceed a maximum length of 38 characters." },
]) {
  test(`creating a client is refused for the identifier ${JSON.stringify(identifier)}`, async ({ page }) => {
    await submitNewClient(page, { identifier });
    await expect(page).toHaveURL(`${env.adminUrl}/admin/clients/new`);
    await expectRefusal(page, "client-error", "clientIdentifier", message);
    // The form keeps what was typed, so it can be corrected.
    await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(identifier);
  });
}

test("creating a client is refused when the identifier is taken", async ({ page, clients }) => {
  const existing = await clients.create();
  await submitNewClient(page, { identifier: existing.identifier });
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients/new`);
  await expectRefusal(page, "client-error", "clientIdentifier", "The client identifier is already in use.");
  // Still exactly one client by that name.
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, existing.identifier)).toHaveCount(1);
});

test("a client created and deleted by hand leaves the list", async ({ page }) => {
  const identifier = uniqueIdentifier("c");
  await submitNewClient(page, { identifier });
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, identifier)).toHaveCount(1);

  await deleteClient(page, await clientIdFromList(page, identifier));
  await expect(clientRow(page, identifier)).toHaveCount(0);
});
