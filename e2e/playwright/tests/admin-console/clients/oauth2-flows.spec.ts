import { clientUrl, confirmDialog, saveAndExpectSaved } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

const saved = "Client OAuth2 flows saved successfully";

test("flows and the PKCE requirement are saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await page.locator('input[name="pkceRequired"][value="on"]').check();
  await page.locator('input[name="clientCredentialsEnabled"]').check();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator('input[name="pkceRequired"][value="on"]')).toBeChecked();
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).toBeChecked();

  await page.locator('input[name="authCodeEnabled"]').uncheck();
  await saveAndExpectSaved(page, saved);
  await page.reload();
  await expect(page.locator('input[name="authCodeEnabled"]')).not.toBeChecked();
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).toBeChecked();
});

test("a public client cannot turn on the client credentials flow", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Public client" }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You are switching from confidential to public client");
  await expect(page.getByText("Client authentication saved successfully")).toBeVisible();

  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).toBeDisabled();
  await expect(page.getByText(/^Your client authentication must be configured as\s*confidential/)).toBeVisible();
});
