// Helpers for driving the admin console as the signed-in administrator.
import { expect, type Page } from "@playwright/test";
import { env } from "./environment";

export type ClientTab =
  | "settings"
  | "logo"
  | "tokens"
  | "authentication"
  | "oauth2-flows"
  | "redirect-uris"
  | "web-origins"
  | "user-sessions"
  | "permissions"
  | "delete";

export function clientUrl(id: number, tab: ClientTab): string {
  return `${env.adminUrl}/admin/clients/${id}/${tab}`;
}

// The admin console's confirmation dialog: a <dialog> with No and Yes, or Cancel and OK.
export async function confirmDialog(page: Page, expectedText?: string | RegExp) {
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toBeVisible();
  if (expectedText) await expect(dialog).toContainText(expectedText);
  await dialog.getByRole("button", { name: /^(Yes|OK)$/ }).click();
}

// The admin console's error dialog: a <dialog> with a single Close button.
export async function expectErrorDialog(page: Page, expectedText: string | RegExp) {
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText(expectedText);
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toBeHidden();
}

export interface NewClient {
  identifier: string;
  authorizationCode?: boolean;
  clientCredentials?: boolean;
  displayName?: string;
}

// Fills and submits the new client form, leaving the page wherever the console answers.
export async function submitNewClient(page: Page, client: NewClient) {
  await page.goto(`${env.adminUrl}/admin/clients/new`);
  await page.locator('input[name="clientIdentifier"]').fill(client.identifier);
  if (client.displayName) await page.locator('input[name="displayName"]').fill(client.displayName);
  await page.locator('input[name="authorizationCodeEnabled"]').setChecked(client.authorizationCode ?? true);
  await page.locator('input[name="clientCredentialsEnabled"]').setChecked(client.clientCredentials ?? false);
  await page.locator("#btnCreate").click();
}

// The client list's row for an identifier.
export function clientRow(page: Page, identifier: string) {
  return page.getByRole("row").filter({ has: page.getByRole("cell", { name: identifier, exact: true }) });
}

// The database id of a client, read from its Manage link on the list.
export async function clientIdFromList(page: Page, identifier: string): Promise<number> {
  await page.goto(`${env.adminUrl}/admin/clients`);
  const href = await clientRow(page, identifier).getByRole("link", { name: "Manage" }).getAttribute("href");
  const match = href?.match(/\/admin\/clients\/(\d+)\//);
  if (!match) throw new Error(`no Manage link for client ${identifier}`);
  return Number(match[1]);
}

// Signs the administrator in from the admin console, in a page with no session.
export async function signInAsAdmin(page: Page) {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await page.locator('input[name="email"]').fill(env.adminEmail);
  await page.locator('input[name="password"]').fill(env.adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
}

// Deletes a client the way an administrator does: type its identifier, press Delete. The identifier
// is read from the delete page, so a client a test renamed is deleted all the same.
export async function deleteClient(page: Page, id: number) {
  await page.goto(clientUrl(id, "delete"));
  const identifier = await page
    .getByRole("row")
    .filter({ has: page.getByRole("cell", { name: "Client identifier", exact: true }) })
    .getByRole("cell")
    .nth(1)
    .innerText();
  await page.locator('input[name="clientIdentifier"]').fill(identifier.trim());
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
}

// The confidential client's secret, as the Authentication tab holds it.
export async function readClientSecret(page: Page, id: number): Promise<string> {
  await page.goto(clientUrl(id, "authentication"));
  const secret = await page.locator("#clientSecret").inputValue();
  expect(secret, "a confidential client has a secret").not.toBe("");
  return secret;
}

// Saves a form page whose Save submits the whole form, and waits for the console's confirmation.
export async function saveAndExpectSaved(page: Page, message: string | RegExp) {
  await page.locator("#btnSave").click();
  await expect(page.getByText(message)).toBeVisible();
}

// Grants a resource's permission on a client's Permissions tab and saves. The permission list loads
// after the resource is chosen, so wait for it.
export async function grantClientPermission(page: Page, id: number, resource: string, permission: string) {
  await page.goto(clientUrl(id, "permissions"));
  await addPermissionRow(page, resource, permission);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client permissions saved successfully")).toBeVisible();
}

// Adds resource:permission to the Permissions tab's table, without saving. Choosing a resource
// reloads the permission list from /admin/get-permissions, and that reload resets the choice, so the
// permission is picked only once the list has arrived.
export async function addPermissionRow(page: Page, resource: string, permission: string) {
  const resources = page.locator("#resourcesSelect");
  const resourceValue = (await resources
    .locator("option")
    .filter({ hasText: new RegExp(`^${resource}\\b`) })
    .getAttribute("value"))!;
  // The page loads the list for whatever is selected when it opens; let that land first.
  await page.waitForLoadState("networkidle");
  if ((await resources.inputValue()) === resourceValue) await resources.selectOption("");
  const loaded = page.waitForResponse((r) => r.url().includes("/admin/get-permissions"));
  await resources.selectOption(resourceValue);
  await loaded;
  const permissions = page.locator("#permissionsSelect");
  const option = permissions.locator("option").filter({ hasText: new RegExp(`\\b${permission}\\b`) });
  await expect(option).toHaveCount(1);
  await permissions.selectOption((await option.getAttribute("value"))!);
  await page.getByRole("button", { name: "Grant permission" }).click();
}
