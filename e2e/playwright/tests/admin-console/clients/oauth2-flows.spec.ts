import { clientUrl, confirmDialog, saveAndExpectSaved } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

const saved = "OAuth2 flows saved.";

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

test("the PKCE choice shows only while the authorization code flow is on", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  const pkce = page.getByRole("group", { name: "PKCE", exact: true });
  await expect(pkce).toBeVisible();
  await page.getByRole("checkbox", { name: /^Authorization code with PKCE/ }).uncheck();
  await expect(pkce).toBeHidden();
  await page.getByRole("checkbox", { name: /^Authorization code with PKCE/ }).check();
  await expect(pkce).toBeVisible();
});

// The values are chosen outright, so what the global settings say does not decide what shows.
test("PKCE made optional and each legacy flow turned on show their warning while chosen", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "oauth2-flows"));
  for (const { name, quiet, warns, warning, text } of [
    { name: "pkceRequired", quiet: "on", warns: "off", warning: "#pkceWarning", text: "Without PKCE, an intercepted authorization code can be redeemed" },
    { name: "implicitGrantEnabled", quiet: "off", warns: "on", warning: "#implicitWarning", text: "The implicit flow puts tokens in URLs" },
    { name: "ropcEnabled", quiet: "off", warns: "on", warning: "#ropcWarning", text: "The client sees the user's password" },
  ]) {
    await page.locator(`input[name="${name}"][value="${quiet}"]`).check();
    await expect(page.locator(warning)).toBeHidden();
    await page.locator(`input[name="${name}"][value="${warns}"]`).check();
    await expect(page.locator(warning)).toBeVisible();
    await expect(page.locator(warning)).toContainText(text);
  }
});

test("a public client cannot turn on the client credentials flow, nor make PKCE optional", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  await page.locator("#publicClientRadio").check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();

  await page.goto(clientUrl(client.id, "oauth2-flows"));
  await expect(page.locator('input[name="clientCredentialsEnabled"]')).toBeDisabled();
  await expect(page.getByText("Only a confidential client can use it. Change the type on the Authentication tab.")).toBeVisible();
  for (const value of ["on", "off", "global"]) await expect(page.locator(`input[name="pkceRequired"][value="${value}"]`)).toBeDisabled();
  await expect(page.getByText("A public client always requires PKCE. Make the client confidential, on the Authentication tab, to change this.")).toBeVisible();
});
