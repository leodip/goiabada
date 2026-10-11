// Helpers for driving the admin console as the signed-in administrator.
import { expect, type Page } from "@playwright/test";
import { submitPassword } from "./browser-sign-in";
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

// A table row holding a cell with exactly this text: a list's row for an identifier.
export function rowWithCell(page: Page, text: string) {
  return page.getByRole("row").filter({ has: page.getByRole("cell", { name: text, exact: true }) });
}

// The client list's row for an identifier.
export function clientRow(page: Page, identifier: string) {
  return rowWithCell(page, identifier);
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
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
}

// Deletes something the way an administrator does on a delete page that asks for its identifier:
// type it, press Delete. The identifier is read from the page's own table (the row labelled
// rowLabel), so something a test renamed is deleted all the same.
async function deleteTypingIdentifier(page: Page, deleteUrl: string, rowLabel: string, inputName: string, listUrl: string) {
  await page.goto(deleteUrl);
  const identifier = await rowWithCell(page, rowLabel).getByRole("cell").nth(1).innerText();
  await page.locator(`input[name="${inputName}"]`).fill(identifier.trim());
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page).toHaveURL(listUrl);
}

export async function deleteClient(page: Page, id: number) {
  await deleteTypingIdentifier(page, clientUrl(id, "delete"), "Client identifier", "clientIdentifier", `${env.adminUrl}/admin/clients`);
}

export async function deleteResource(page: Page, id: number) {
  await deleteTypingIdentifier(page, resourceUrl(id, "delete"), "Resource identifier", "resourceIdentifier", `${env.adminUrl}/admin/resources`);
}

export async function deleteGroup(page: Page, id: number) {
  await deleteTypingIdentifier(page, `${env.adminUrl}/admin/groups/${id}/delete`, "Group identifier", "groupIdentifier", `${env.adminUrl}/admin/groups`);
}

// A user's delete page asks for no identifier.
export async function deleteUser(page: Page, id: number) {
  await page.goto(`${env.adminUrl}/admin/users/${id}/delete`);
  await page.getByRole("button", { name: "Delete user" }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`));
}

// The database id in a list row's link, such as /admin/resources/7/settings.
export async function idFromListLink(page: Page, listUrl: string, text: string, linkName: string): Promise<number> {
  await page.goto(listUrl);
  const href = await rowWithCell(page, text).getByRole("link", { name: linkName }).getAttribute("href");
  const match = href?.match(/\/admin\/\w+\/(\d+)\//);
  if (!match) throw new Error(`no ${linkName} link for ${text} on ${listUrl}`);
  return Number(match[1]);
}

export type ResourceTab = "settings" | "permissions" | "users-with-permission" | "groups-with-permission" | "delete";

export function resourceUrl(id: number, tab: ResourceTab): string {
  return `${env.adminUrl}/admin/resources/${id}/${tab}`;
}

// Fills and submits the new resource form, leaving the page wherever the console answers.
export async function submitNewResource(page: Page, identifier: string, description = "") {
  await page.goto(`${env.adminUrl}/admin/resources/new`);
  await page.locator("#resourceIdentifier").fill(identifier);
  await page.locator('input[name="description"]').fill(description);
  await page.locator("#btnCreate").click();
}

export type UserTab =
  | "details"
  | "profile"
  | "email"
  | "phone"
  | "address"
  | "authentication"
  | "attributes"
  | "consents"
  | "sessions"
  | "groups"
  | "permissions"
  | "picture"
  | "delete";

export function userUrl(id: number, tab: UserTab): string {
  return `${env.adminUrl}/admin/users/${id}/${tab}`;
}

export interface NewUser {
  email: string;
  givenName?: string;
  familyName?: string;
  emailVerified?: boolean;
  password?: string;
}

// Fills and submits the new user form with the password set now, leaving the page wherever the
// console answers. The choice between setting the password now and emailing a link is offered only
// when SMTP is configured; without it the password is set now.
export async function submitNewUser(page: Page, user: NewUser) {
  await page.goto(`${env.adminUrl}/admin/users/new`);
  await page.locator("#email").fill(user.email);
  await page.locator('input[name="emailVerified"]').setChecked(user.emailVerified ?? false);
  await page.locator("#givenName").fill(user.givenName ?? "");
  await page.locator("#familyName").fill(user.familyName ?? "");
  const setNow = page.locator("#setPasswordTypeNow");
  if ((await setNow.count()) > 0) await setNow.check();
  await page.locator("#password").fill(user.password ?? "");
  await page.locator("#btnCreate").click();
}

// Registers a redirect URI on a client's Redirect URIs tab and saves.
export async function addRedirectUri(page: Page, id: number, uri: string) {
  await page.goto(clientUrl(id, "redirect-uris"));
  await page.locator("#redirectURI").fill(uri);
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client redirect uris saved successfully")).toBeVisible();
}

export type GroupTab = "settings" | "attributes" | "members" | "permissions" | "delete";

export function groupUrl(id: number, tab: GroupTab): string {
  return `${env.adminUrl}/admin/groups/${id}/${tab}`;
}

export interface NewGroup {
  identifier: string;
  description?: string;
  includeInAccessToken?: boolean;
  includeInIdToken?: boolean;
}

// Fills and submits the new group form, leaving the page wherever the console answers. Both include
// switches start on, as the form opens.
export async function submitNewGroup(page: Page, group: NewGroup) {
  await page.goto(`${env.adminUrl}/admin/groups/new`);
  await page.locator("#groupIdentifier").fill(group.identifier);
  await page.locator('input[name="description"]').fill(group.description ?? "");
  await page.locator('input[name="includeInAccessToken"]').setChecked(group.includeInAccessToken ?? true);
  await page.locator('input[name="includeInIdToken"]').setChecked(group.includeInIdToken ?? true);
  await page.locator("#btnCreate").click();
}

export interface GroupAttribute {
  key: string;
  value: string;
  includeInAccessToken?: boolean;
  includeInIdToken?: boolean;
}

// Fills and submits an attribute form (add or edit) already open, leaving the page wherever the
// console answers.
export async function submitGroupAttributeForm(page: Page, attribute: GroupAttribute) {
  await page.locator("#attributeKey").fill(attribute.key);
  await page.locator('input[name="attributeValue"]').fill(attribute.value);
  await page.locator('input[name="includeInAccessToken"]').setChecked(attribute.includeInAccessToken ?? true);
  await page.locator('input[name="includeInIdToken"]').setChecked(attribute.includeInIdToken ?? true);
  await page.locator("#btnSave").click();
}

export async function addGroupAttribute(page: Page, groupId: number, attribute: GroupAttribute) {
  await page.goto(`${env.adminUrl}/admin/groups/${groupId}/attributes/add`);
  await submitGroupAttributeForm(page, attribute);
  await expect(page).toHaveURL(groupUrl(groupId, "attributes"));
}

// Adds a user to a group the way the Members tab does: search, Add to group, confirm.
export async function addGroupMember(page: Page, groupId: number, email: string) {
  await page.goto(`${env.adminUrl}/admin/groups/${groupId}/members/add`);
  await page.locator("#search").pressSequentially(email.split("@")[0]);
  const row = rowWithCell(page, email);
  await row.getByRole("button", { name: "Add to group" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(row.getByText("In group")).toBeVisible();
}

// The Permissions tab's table row for a permission identifier.
export function resourcePermissionRow(page: Page, identifier: string) {
  return page.locator("#permissionsTable tbody tr").filter({ has: page.getByRole("cell", { name: identifier, exact: true }) });
}

// Adds a permission to the Permissions tab's table, without saving. The console validates it on the
// server first, so wait for that answer.
export async function addResourcePermission(page: Page, identifier: string, description = "") {
  await page.locator("#permissionIdentifier").fill(identifier);
  await page.locator("#permissionDescription").fill(description);
  const validated = page.waitForResponse((r) => r.url().endsWith("/admin/resources/validate-permission"));
  await page.getByRole("button", { name: "Create permission" }).click();
  await validated;
}

export async function saveResourcePermissions(page: Page) {
  await page.locator("#btnSave").click();
  await expect(page.getByText("Resource permissions saved successfully")).toBeVisible();
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

// The same on a group's Permissions tab, which shares the client tab's controls.
export async function grantGroupPermission(page: Page, id: number, resource: string, permission: string) {
  await page.goto(groupUrl(id, "permissions"));
  await addPermissionRow(page, resource, permission);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Group permissions saved successfully")).toBeVisible();
}

// Sets the client's resource owner password credentials grant to on, whatever the global setting.
export async function enablePasswordGrant(page: Page, id: number) {
  await page.goto(clientUrl(id, "oauth2-flows"));
  await page.locator('input[name="ropcEnabled"][value="on"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client OAuth2 flows saved successfully")).toBeVisible();
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
  // The label is the identifier, then the description in parentheses when there is one.
  const option = permissions.locator("option").filter({ hasText: new RegExp(`^${permission}( \\(|$)`) });
  await expect(option).toHaveCount(1);
  await permissions.selectOption((await option.getAttribute("value"))!);
  await page.getByRole("button", { name: "Grant permission" }).click();
}
