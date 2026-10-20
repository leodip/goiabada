// What the admin console configures, as the auth server's token endpoint answers it.
import { clientUrl, confirmDialog, grantClientPermission, readClientSecret, saveAndExpectSaved } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

const grantManageAccount = (page: import("@playwright/test").Page, id: number) =>
  grantClientPermission(page, id, "authserver", "manage-account");

test("a client credentials client gets a token with its secret, and not with a wrong one", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantManageAccount(page, client.id);
  const secret = await readClientSecret(page, client.id);

  const ok = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  expect(ok.body.access_token).toBeTruthy();

  const wrong = await clientCredentialsToken(request, client.identifier, `${secret}x`, "authserver:manage-account");
  expect(wrong.status).toBe(401);
  expect(wrong.body.error).toBe("invalid_client");
});

test("a disabled client is refused at the token endpoint, and works again once enabled", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantManageAccount(page, client.id);
  const secret = await readClientSecret(page, client.id);

  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').uncheck();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're disabling the client");
  await expect(page.getByText("Settings saved.")).toBeVisible();
  const refused = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(refused.status).toBeGreaterThanOrEqual(400);
  expect(refused.body.access_token).toBeUndefined();

  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('input[name="enabled"]').check();
  await saveAndExpectSaved(page, "Settings saved.");
  const again = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(again.status, JSON.stringify(again.body)).toBe(200);
});

test("a client without the client credentials flow is refused that grant", async ({ page, clients, request }) => {
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
  const answer = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(answer.status).toBeGreaterThanOrEqual(400);
  expect(answer.body.error).toBe("unauthorized_client");
});
