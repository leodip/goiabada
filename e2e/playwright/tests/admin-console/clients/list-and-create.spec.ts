import { clientRow, deleteClient, clientIdFromList, submitNewClient, clientUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

test("the list shows the seeded admin console client, and Manage opens it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  const row = clientRow(page, "admin-console-client");
  await expect(row.getByRole("cell", { name: "Enabled", exact: true })).toBeVisible();
  await expect(row.getByRole("cell", { name: "Confidential", exact: true })).toBeVisible();

  await row.getByRole("link", { name: "Manage" }).click();
  await expect(page).toHaveURL(/\/admin\/clients\/\d+\/settings$/);
  await expect(page.getByRole("heading", { name: "Client settings - admin-console-client" })).toBeVisible();
});

test("a new client with the defaults lands in the list, confidential, with the authorization code flow", async ({
  page,
  clients,
}) => {
  const client = await clients.create();
  await page.goto(`${env.adminUrl}/admin/clients`);
  const row = clientRow(page, client.identifier);
  await expect(row.getByRole("cell", { name: "Enabled", exact: true })).toBeVisible();
  await expect(row.getByRole("cell", { name: "Confidential", exact: true })).toBeVisible();

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
    await expect(page.locator("main").getByText(message)).toBeVisible();
    // The form keeps what was typed, so it can be corrected.
    await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue(identifier);
  });
}

test("creating a client is refused when the identifier is taken", async ({ page, clients }) => {
  const existing = await clients.create();
  await submitNewClient(page, { identifier: existing.identifier });
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients/new`);
  await expect(page.getByText("The client identifier is already in use.")).toBeVisible();
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
