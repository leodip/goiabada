import { clientRow, clientUrl, grantClientPermission, readClientSecret, rowWithCell } from "../../../lib/admin-console";
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

  await page.goto(clientUrl(client.id, "delete"));
  await expect(page.getByRole("cell", { name: client.identifier, exact: true })).toBeVisible();
  await page.locator('input[name="clientIdentifier"]').fill(`${client.identifier}-wrong`);
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "delete"));
  await expect(page.getByText("Client identifier does not match the client being deleted.")).toBeVisible();
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier)).toHaveCount(1);

  await page.goto(clientUrl(client.id, "delete"));
  await page.locator('input[name="clientIdentifier"]').fill(client.identifier);
  await page.getByRole("button", { name: "Delete", exact: true }).click();
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
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "delete"));
  await expect(page.getByText("Client identifier is required.")).toBeVisible();
  // Drawn as the first draw is, the permissions the page warns about included.
  await expect(rowWithCell(page, "Assigned permissions")).toContainText("authserver:manage-account");
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier)).toHaveCount(1);
});

test("the system client cannot be deleted", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  // The list offers no Delete link for it.
  await expect(clientRow(page, "admin-console-client").getByRole("link", { name: "Delete" })).toHaveCount(0);

  const href = await clientRow(page, "admin-console-client").getByRole("link", { name: "Manage" }).getAttribute("href");
  const id = Number(href!.match(/\/admin\/clients\/(\d+)\//)![1]);
  await page.goto(clientUrl(id, "delete"));
  await expect(page.getByText("This system-level client cannot be deleted.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete", exact: true })).toHaveCount(0);
});
