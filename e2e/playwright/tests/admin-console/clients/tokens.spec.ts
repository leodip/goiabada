import { clientUrl, grantClientPermission, readClientSecret, saveAndExpectSaved } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

const saved = "Client settings saved successfully";

test("token durations and the OIDC claim options are saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#tokenExpirationInSeconds").fill("600");
  await page.locator("#refreshTokenOfflineIdleTimeoutInSeconds").fill("3600");
  await page.locator("#refreshTokenOfflineMaxLifetimeInSeconds").fill("86400");
  await page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]').check();
  await page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]').check();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("600");
  await expect(page.locator("#refreshTokenOfflineIdleTimeoutInSeconds")).toHaveValue("3600");
  await expect(page.locator("#refreshTokenOfflineMaxLifetimeInSeconds")).toHaveValue("86400");
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]')).toBeChecked();
});

test("a new client's Tokens tab shows an ID token choice, and saves as loaded", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  // Both three-way choices start on the global setting.
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="default"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
  await saveAndExpectSaved(page, saved);
});

test("the token expiration set here is the lifetime the token endpoint gives", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");

  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#tokenExpirationInSeconds").fill("123");
  await saveAndExpectSaved(page, saved);

  const secret = await readClientSecret(page, client.id);
  const answer = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  expect(answer.body.expires_in).toBe(123);
});

for (const { value, message } of [
  { value: "-5", message: "Token expiration in seconds must be between 0 and 160000000." },
  { value: "abc", message: "Invalid value for token expiration in seconds." },
]) {
  test(`a token expiration of ${JSON.stringify(value)} is refused`, async ({ page, clients }) => {
    const client = await clients.create();
    await page.goto(clientUrl(client.id, "tokens"));
    await page.locator("#tokenExpirationInSeconds").fill(value);
    await page.locator("#btnSave").click();
    await expect(page.getByText(message)).toBeVisible();
    await page.goto(clientUrl(client.id, "tokens"));
    await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("0");
  });
}

test("a refused save keeps what was typed, both claim choices included", async ({ page, clients }) => {
  const client = await clients.create();
  const accessOff = page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]');
  const idOn = page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]');
  await page.goto(clientUrl(client.id, "tokens"));
  await accessOff.check();
  await idOn.check();
  await page.locator("#tokenExpirationInSeconds").fill("abc");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Invalid value for token expiration in seconds.")).toBeVisible();
  await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("abc");
  await expect(accessOff).toBeChecked();
  await expect(idOn).toBeChecked();

  // Nothing was saved: the tab opens on the stored choices again.
  await page.goto(clientUrl(client.id, "tokens"));
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="default"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
});
