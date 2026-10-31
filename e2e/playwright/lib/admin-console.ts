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
  | "sign-out-redirect-uris"
  | "web-origins"
  | "user-sessions"
  | "permissions"
  | "introspection"
  | "delete";

export function clientUrl(id: number, tab: ClientTab): string {
  return `${env.adminUrl}/admin/clients/${id}/${tab}`;
}

// The admin console's confirmation dialog: Cancel, then the action it asks about ("Save", "Revoke
// consent", "End session" and so on), which this presses.
export async function confirmDialog(page: Page, expectedText?: string | RegExp) {
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toBeVisible();
  if (expectedText) await expect(dialog).toContainText(expectedText);
  await dialog.locator('[id$="_btnModal2"]').click();
  await expect(dialog).toBeHidden();
}

// The same dialog, answered with Cancel.
export async function cancelDialog(page: Page, expectedText?: string | RegExp) {
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toBeVisible();
  if (expectedText) await expect(dialog).toContainText(expectedText);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).toBeHidden();
}

// The hint the baseline's nist password policy draws under a new password's field, on the console's
// change-password, new user and Authentication tab pages as on the auth server's forms (#550
// decisions 10 and 11).
export const nistPasswordRules =
  "At least 15 characters. A few unrelated words make a long password that's easy to remember. Common passwords, and the account's email address or the app's name, are refused.";

// The stored policy's rules stated under the new password's field (#password-rules), and the field
// described by them, so a screen reader reads them on reaching it.
export async function expectPasswordRules(page: Page, fieldId: string) {
  await expect(page.locator("#password-rules")).toHaveText(nistPasswordRules);
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("aria-describedby", /(^| )password-rules( |$)/);
  // The description holds the rules whole, beside a refusal or another hint the field names too.
  const rules = new RegExp(nistPasswordRules.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  await expect(page.locator(`#${fieldId}`)).toHaveAccessibleDescription(rules);
}

// A refusal a form is drawn again with: the message in the form's notice (#<noticeId>), and the field
// it is about marked invalid and focused. A form whose refusal leaves every password to be typed again
// focuses the first password field instead, so its caller says focused: false.
export async function expectRefusal(
  page: Page,
  noticeId: string,
  fieldId: string,
  expectedText: string | RegExp,
  { focused = true }: { focused?: boolean } = {},
) {
  await expect(page.locator(`#${noticeId}`)).toContainText(expectedText);
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("aria-invalid", "true");
  if (focused) await expect(page.locator(`#${fieldId}`)).toBeFocused();
}

// A refusal the page shows at the field it is about: the message under the field (#<id>-error), and
// the field marked invalid.
export async function expectFieldError(page: Page, fieldId: string, expectedText: string | RegExp) {
  await expect(page.locator(`#${fieldId}-error`)).toBeVisible();
  await expect(page.locator(`#${fieldId}-error`)).toContainText(expectedText);
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("aria-invalid", "true");
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

// Adds a resource, by its identifier, to the introspection resources a client's Introspection tab
// shows, without saving.
export async function addIntrospectionResource(page: Page, identifier: string) {
  const select = page.locator("#introspectionResourcesSelect");
  await select.selectOption((await select.locator(`option[data-resource-identifier="${identifier}"]`).getAttribute("value"))!);
  await page.locator("#addIntrospectionResourceBtn").click();
}

// The value a page's record (a dl.detail-list, as on the delete pages and a user's details) lists
// under this term.
export function detail(page: Page, term: string) {
  return page.locator(`dl.detail-list > dt:text-is("${term}") + dd`);
}

// Chooses an entry of a searchable list (time zone, language, country), a field with role combobox
// over #<id>-options: types to narrow the list, then picks the entry.
export async function choose(page: Page, id: string, typed: string, entry: string | RegExp) {
  await page.locator(`#${id}`).fill(typed);
  await page.locator(`#${id}-options`).getByRole("option", { name: entry, exact: typeof entry === "string" }).click();
}

// A table row naming exactly this text, in a cell of its own or as a line of one (a link, with a
// description or a name beneath it): a list's row for an identifier or an email.
export function rowWithCell(page: Page, text: string) {
  return page.getByRole("row").filter({ has: page.getByText(text, { exact: true }) });
}

// The client list's row for an identifier.
export function clientRow(page: Page, identifier: string) {
  return rowWithCell(page, identifier);
}

// The database id of a client, read from the link its identifier is on the list.
export async function clientIdFromList(page: Page, identifier: string): Promise<number> {
  return idFromListLink(page, `${env.adminUrl}/admin/clients`, identifier);
}

// Signs the administrator in from the admin console, in a page with no session.
export async function signInAsAdmin(page: Page) {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
}

// Deletes something the way an administrator does on a delete page: type what the page asks for,
// press the delete button. Every delete page lists the record first, its identifier (a user's email)
// the first entry, which is what is typed, so something a test renamed is deleted all the same.
async function deleteTyping(page: Page, deleteUrl: string, inputId: string, listUrl: string | RegExp) {
  await page.goto(deleteUrl);
  const identifier = await page.locator("dl.detail-list dd").first().innerText();
  await page.locator(`#${inputId}`).fill(identifier.trim());
  await page.locator("#btnDelete").click();
  await expect(page).toHaveURL(listUrl);
}

export async function deleteClient(page: Page, id: number) {
  await deleteTyping(page, clientUrl(id, "delete"), "clientIdentifier", `${env.adminUrl}/admin/clients`);
}

export async function deleteResource(page: Page, id: number) {
  await deleteTyping(page, resourceUrl(id, "delete"), "resourceIdentifier", `${env.adminUrl}/admin/resources`);
}

export async function deleteGroup(page: Page, id: number) {
  await deleteTyping(page, `${env.adminUrl}/admin/groups/${id}/delete`, "groupIdentifier", `${env.adminUrl}/admin/groups`);
}

// A user's delete page asks for the user's email.
export async function deleteUser(page: Page, id: number) {
  await deleteTyping(page, `${env.adminUrl}/admin/users/${id}/delete`, "email", new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`));
}

// The database id in the link a list names a row by, its identifier or email, such as
// /admin/resources/7/settings.
export async function idFromListLink(page: Page, listUrl: string, text: string): Promise<number> {
  await page.goto(listUrl);
  const href = await page.getByRole("table").getByRole("link", { name: text, exact: true }).getAttribute("href");
  const match = href?.match(/\/admin\/\w+\/(\d+)\//);
  if (!match) throw new Error(`no link for ${text} on ${listUrl}`);
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
  await page.locator("#addURIBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Redirect URIs saved.")).toBeVisible();
}

// Registers a sign-out redirect URI on a client's Sign-out redirect URIs tab and saves.
export async function addSignOutRedirectUri(page: Page, id: number, uri: string) {
  await page.goto(clientUrl(id, "sign-out-redirect-uris"));
  await page.locator("#signOutRedirectURI").fill(uri);
  await page.locator("#addURIBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Sign-out redirect URIs saved.")).toBeVisible();
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

// Adds a user to a group the way the Members tab does: search, then Add to group, which acts at once.
export async function addGroupMember(page: Page, groupId: number, email: string) {
  await page.goto(`${env.adminUrl}/admin/groups/${groupId}/members/add`);
  await page.locator("#search").pressSequentially(email.split("@")[0]);
  const row = rowWithCell(page, email);
  await row.getByRole("button", { name: "Add to group" }).click();
  await expect(row.getByText("In group")).toBeVisible();
}

// The Permissions tab's table row for a permission identifier.
export function resourcePermissionRow(page: Page, identifier: string) {
  return page.locator(`#permissionsTable tbody tr[data-identifier="${identifier}"]`);
}

// Adds a permission to the Permissions tab's table, without saving. The console validates it on the
// server first (by path: the console adds the page's ui_locales to the address), then adds the row and
// empties the form once it has read the answer, or shows the refusal under its field: wait for one or
// the other, since a next permission filled in before the form is emptied would be emptied with it.
export async function addResourcePermission(page: Page, identifier: string, description = "") {
  await page.locator("#permissionIdentifier").fill(identifier);
  await page.locator("#permissionDescription").fill(description);
  const validated = page.waitForResponse((r) => new URL(r.url()).pathname === "/admin/resources/validate-permission");
  await page.locator("#addPermissionBtn").click();
  await validated;
  await page.waitForFunction(
    () =>
      (document.getElementById("permissionIdentifier") as HTMLInputElement).value === "" ||
      document.querySelector("#permissionIdentifier-error:not([hidden]), #permissionDescription-error:not([hidden])") !== null,
  );
}

export async function saveResourcePermissions(page: Page) {
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
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
  await expect(page.getByText("Permissions saved.")).toBeVisible();
}

// The same on a group's Permissions tab, which shares the client tab's controls.
export async function grantGroupPermission(page: Page, id: number, resource: string, permission: string) {
  await page.goto(groupUrl(id, "permissions"));
  await addPermissionRow(page, resource, permission);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
}

// Sets the client's resource owner password credentials grant to on, whatever the global setting.
export async function enablePasswordGrant(page: Page, id: number) {
  await page.goto(clientUrl(id, "oauth2-flows"));
  await page.locator('input[name="ropcEnabled"][value="on"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("OAuth2 flows saved.")).toBeVisible();
}

// Sets the client's implicit grant to on or off, whatever the global setting.
export async function setImplicitGrant(page: Page, id: number, value: "on" | "off") {
  await page.goto(clientUrl(id, "oauth2-flows"));
  await page.locator(`input[name="implicitGrantEnabled"][value="${value}"]`).check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("OAuth2 flows saved.")).toBeVisible();
}

// Sets whether the client must use PKCE: on, off, or as the global setting says.
export async function setPkceRequired(page: Page, id: number, value: "global" | "on" | "off") {
  await page.goto(clientUrl(id, "oauth2-flows"));
  await page.locator(`input[name="pkceRequired"][value="${value}"]`).check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("OAuth2 flows saved.")).toBeVisible();
}

// Adds resource:permission to the Permissions tab's table, without saving. Choosing a resource
// reloads the permission list from /admin/get-permissions, and that reload resets the choice, so the
// permission is picked only once the list has arrived. Each option carries its identifier, its label
// the identifier and a shortened description.
export async function addPermissionRow(page: Page, resource: string, permission: string) {
  const resources = page.locator("#resourcesSelect");
  const resourceValue = (await resources.locator(`option[data-resource-identifier="${resource}"]`).getAttribute("value"))!;
  // The page loads the list for whatever is selected when it opens; let that land first.
  await page.waitForLoadState("networkidle");
  if ((await resources.inputValue()) === resourceValue) await resources.selectOption("");
  const loaded = page.waitForResponse((r) => r.url().includes("/admin/get-permissions"));
  await resources.selectOption(resourceValue);
  await loaded;
  const permissions = page.locator("#permissionsSelect");
  const option = permissions.locator(`option[data-permission-identifier="${permission}"]`);
  await expect(option).toHaveCount(1);
  await permissions.selectOption((await option.getAttribute("value"))!);
  await page.locator("#grantPermissionBtn").click();
}

// Grants a resource's permission on a user's Permissions tab and saves.
export async function grantUserPermission(page: Page, id: number, resource: string, permission: string) {
  await page.goto(userUrl(id, "permissions"));
  await addPermissionRow(page, resource, permission);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved.")).toBeVisible();
}

export type LegalDocumentTab = "draft" | "versions" | "delete";

export function legalDocumentUrl(id: number, tab: LegalDocumentTab): string {
  return `${env.adminUrl}/admin/legal-documents/${id}/${tab}`;
}

export type LegalDocumentKind = "must_accept" | "for_information";

export interface NewLegalDocument {
  kind?: LegalDocumentKind;
  title: string;
  // Typed over the short name the console suggests from the title, when given.
  shortName?: string;
}

// Fills and submits the new legal document form, leaving the page wherever the console answers. No
// kind is chosen unless one is given, as the form opens.
export async function submitNewLegalDocument(page: Page, doc: NewLegalDocument) {
  await page.goto(`${env.adminUrl}/admin/legal-documents/new`);
  if (doc.kind) await page.locator(doc.kind === "must_accept" ? "#kindMustAccept" : "#kindForInformation").check();
  await page.locator("#title").fill(doc.title);
  if (doc.shortName !== undefined) await page.locator("#shortName").fill(doc.shortName);
  await page.locator("#btnCreate").click();
}

// The id in a legal document page's address, such as /admin/legal-documents/7/draft.
export function legalDocumentIdFrom(url: string): number {
  const match = url.match(/\/admin\/legal-documents\/(\d+)\//);
  if (!match) throw new Error(`no legal document id in ${url}`);
  return Number(match[1]);
}

// Saves a legal document's draft with this text, and its title when given.
export async function saveLegalDocumentDraft(page: Page, id: number, { title, markdown }: { title?: string; markdown: string }) {
  await page.goto(legalDocumentUrl(id, "draft"));
  if (title !== undefined) await page.locator("#title").fill(title);
  await page.locator("#markdown").fill(markdown);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Draft saved.", { exact: true })).toBeVisible();
}

// Publishes a legal document's saved draft, answering the question with Publish.
export async function publishLegalDocument(page: Page, id: number) {
  await page.goto(legalDocumentUrl(id, "draft"));
  await page.locator("#btnPublish").click();
  await confirmDialog(page);
  await expect(page).toHaveURL(legalDocumentUrl(id, "versions"));
}

// Retires a published legal document, answering the question with Retire.
export async function retireLegalDocument(page: Page, id: number) {
  await page.goto(legalDocumentUrl(id, "versions"));
  await page.locator("#btnRetire").click();
  await confirmDialog(page);
  await expect(page.getByText("Document retired.", { exact: true })).toBeVisible();
}

// A legal document's delete page asks for its short name.
export async function deleteLegalDocument(page: Page, id: number) {
  await deleteTyping(page, legalDocumentUrl(id, "delete"), "shortName", `${env.adminUrl}/admin/legal-documents`);
}

// Takes a legal document out of effect the one way its state allows: one never published is
// deleted, a published one retired, since a published document is never deleted. A retired one,
// and one already deleted, are left as they are.
export async function putAwayLegalDocument(page: Page, id: number) {
  const response = await page.goto(legalDocumentUrl(id, "versions"));
  if (response?.status() === 404) return;
  if ((await page.locator("#btnRetire").count()) > 0) {
    await retireLegalDocument(page, id);
  } else if ((await page.locator('.page-actions a[href$="/delete"]').count()) > 0) {
    await deleteLegalDocument(page, id);
  }
}
