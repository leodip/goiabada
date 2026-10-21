import { clientIdFromList, clientRow, clientUrl, detail, expectRefusal, grantClientPermission, readClientSecret } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

test("deleting needs the identifier typed: a wrong one is refused, the right one deletes", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  const secret = await readClientSecret(page, client.id);

  // The list's Delete link, named for the client, opens the page, which lists what is deleted.
  await page.goto(`${env.adminUrl}/admin/clients`);
  await page.getByRole("link", { name: `Delete ${client.identifier}`, exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "delete"));
  await expect(page.getByRole("heading", { level: 1, name: "Delete client" })).toBeVisible();
  await expect(detail(page, "Client identifier")).toHaveText(client.identifier);
  await expect(detail(page, "Status")).toHaveText("Enabled");
  await expect(detail(page, "Type")).toHaveText("Confidential");
  await expect(detail(page, "OAuth2 flows")).toHaveText("Client credentials");

  await page.getByLabel("To confirm, type the client identifier").fill(`${client.identifier}-wrong`);
  await page.getByRole("button", { name: "Delete client", exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "delete"));
  await expectRefusal(page, "delete-error", "clientIdentifier", "That isn't this client's identifier. Type it as shown above.");
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier)).toHaveCount(1);

  await page.goto(clientUrl(client.id, "delete"));
  await page.getByLabel("To confirm, type the client identifier").fill(client.identifier);
  await page.getByRole("button", { name: "Delete client", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier)).toHaveCount(0);
  client.markDeleted();

  // Gone from the auth server too: its credentials no longer authenticate.
  const answer = await clientCredentialsToken(request, client.identifier, secret);
  expect(answer.status).toBe(401);
  expect(answer.body.error).toBe("invalid_client");
});

test("deleting with the identifier left empty is refused on the page, which still lists the permissions", async ({
  page,
  clients,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");

  await page.goto(clientUrl(client.id, "delete"));
  await expect(page.locator('input[name="clientIdentifier"]')).toHaveValue("");
  await page.getByRole("button", { name: "Delete client", exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "delete"));
  await expectRefusal(page, "delete-error", "clientIdentifier", "Client identifier is required.");
  // Drawn as the first draw is, the permissions the page warns about included.
  await expect(detail(page, "Permissions")).toContainText("authserver:manage-account");
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier)).toHaveCount(1);
});

test("the system client cannot be deleted", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  // The list offers no Delete link for it.
  await expect(clientRow(page, "admin-console-client").getByRole("link", { name: /^Delete/ })).toHaveCount(0);

  const id = await clientIdFromList(page, "admin-console-client");
  await page.goto(clientUrl(id, "delete"));
  await expect(page.getByText("This is the admin console's own client, so it can't be deleted.")).toBeVisible();
  await expect(page.locator("#clientIdentifier")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete client", exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Back to clients" }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
});
