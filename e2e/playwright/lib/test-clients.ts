// Clients a test sets up to get a user's tokens or browser sign-ins, through the clients fixture so
// they are removed afterwards.
import { expect, type Page } from "@playwright/test";
import { addRedirectUri, clientUrl, confirmDialog, enablePasswordGrant, readClientSecret } from "./admin-console";
import { testRedirectUri } from "./browser-sign-in";
import type { TestClient } from "./fixtures";

interface ClientsFixture {
  create(): Promise<TestClient>;
}

// A confidential client that may use the password grant, and its secret: the shortest way to a
// user's tokens.
export async function passwordGrantClient(page: Page, clients: ClientsFixture) {
  const client = await clients.create();
  await enablePasswordGrant(page, client.id);
  return { client, secret: await readClientSecret(page, client.id) };
}

// A confidential authorization code client with the tests' redirect URI, and its secret; with
// consent required when asked.
export async function browserSignInClient(page: Page, clients: ClientsFixture, { consentRequired = false } = {}) {
  const client = await clients.create();
  await addRedirectUri(page, client.id, testRedirectUri);
  if (consentRequired) {
    await page.goto(clientUrl(client.id, "settings"));
    await page.locator('input[name="consentRequired"]').check();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Settings saved.")).toBeVisible();
  }
  return { client, secret: await readClientSecret(page, client.id) };
}

// A public authorization code client with the tests' redirect URI: it holds no secret, so it names
// itself with client_id alone.
export async function publicSignInClient(page: Page, clients: ClientsFixture) {
  const client = await clients.create();
  await addRedirectUri(page, client.id, testRedirectUri);
  await page.goto(clientUrl(client.id, "authentication"));
  await page.locator("#publicClientRadio").check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();
  return client;
}
