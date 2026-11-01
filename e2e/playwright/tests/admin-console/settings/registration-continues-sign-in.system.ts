// Registration carries on the sign-in that started it (#622): someone who registers from an app's
// sign-in page, through its Create an account link, is signed straight in with the new account and
// taken on into the app, through the acceptance step, without typing the password again. With email
// verification, the mailed link does the same when it is opened in the same browser; opened in
// another, it activates the account and the page sends the person back to the app.
//
// Registration is a setting, so this runs alone, as a system test, and puts the settings back. The
// app is a client of the test's own, with a must-accept document for it alone, which the fixture
// retires; the accounts registered are deleted when the test ends.
import type { Browser, Page } from "@playwright/test";
import { deleteUser, idFromListLink, publishLegalDocument, setLegalDocumentApps } from "../../../lib/admin-console";
import { openSignIn, redirectParams, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { linksIn, waitForMail } from "../../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const general = "/admin/settings/general";
const password = "a-registered-password";

// Opens the client's sign-in in a browser of its own and follows the password page's Create an
// account link.
async function createAnAccountFrom(browser: Browser, client: TestClient) {
  const { context, page } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(page).toHaveURL(/\/auth\/pwd/);
  await page.getByRole("link", { name: "Create an account" }).click();
  await expect(page).toHaveTitle(/^Create an account – /);
  return { context, page };
}

// Chooses the password on the form in front of the user, the registration form or the mailed link's.
async function choosePassword(page: Page) {
  await page.locator("#password").fill(password);
  await page.locator("#passwordConfirmation").fill(password);
  await page.getByRole("button", { name: "Create account", exact: true }).click();
}

// Accepts the app's terms on the step, the one document it lists, and expects the app to get its code.
async function acceptAndReachTheApp(page: Page, terms: string) {
  await expect(page).toHaveURL(/\/auth\/legal-acceptance/);
  await expect(page.locator("form").getByRole("link", { name: terms })).toBeVisible();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Accept", exact: true }).click();
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expect(redirectParams(new URL(page.url())).get("code"), "the app gets its code").toBeTruthy();
}

async function deleteRegistered(page: Page, email: string) {
  await deleteUser(page, await idFromListLink(page, `${env.adminUrl}/admin/users?query=${email.split("@")[0]}`, email));
}

test("registering from an app's sign-in signs the new user in, and on through the acceptance step into the app", async ({
  page,
  browser,
  clients,
  legalDocuments,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const terms = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice to each other." });
  await setLegalDocumentApps(page, terms.id, [client.identifier]);
  await publishLegalDocument(page, terms.id);
  const email = `${uniqueIdentifier("u")}@example.com`;

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);

    const { context, page: user } = await createAnAccountFrom(browser, client);
    await user.locator("#email").fill(email);
    await choosePassword(user);
    // No "Account created" page and no password typed again: straight on to the app's terms.
    await acceptAndReachTheApp(user, terms.title);
    await context.close();
  });
  await deleteRegistered(page, email);
});

test("with email verification, the mailed link carries on the sign-in in the same browser, and anywhere else sends the person back", async ({
  page,
  browser,
  request,
  clients,
  legalDocuments,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const terms = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice to each other." });
  await setLegalDocumentApps(page, terms.id, [client.identifier]);
  await publishLegalDocument(page, terms.id);
  const sameBrowser = `${uniqueIdentifier("u")}@example.com`;
  const otherBrowser = `${uniqueIdentifier("u")}@example.com`;

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
    await saveSettings(page);

    // Opened in the browser that started the sign-in: on into the app.
    const own = await createAnAccountFrom(browser, client);
    await own.page.locator("#email").fill(sameBrowser);
    await own.page.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(own.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
    const link = linksIn(await waitForMail(request, sameBrowser)).find((l) => l.includes("/account/activate"))!;
    await own.page.goto(link);
    await expect(own.page.getByRole("heading", { name: "Choose your password" })).toBeVisible();
    await choosePassword(own.page);
    await acceptAndReachTheApp(own.page, terms.title);
    await own.context.close();

    // Opened in another browser: the account is activated, and the page sends the person back.
    const started = await createAnAccountFrom(browser, client);
    await started.page.locator("#email").fill(otherBrowser);
    await started.page.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(started.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
    const otherLink = linksIn(await waitForMail(request, otherBrowser)).find((l) => l.includes("/account/activate"))!;
    const elsewhere = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const other = await elsewhere.newPage();
    await other.goto(otherLink);
    await choosePassword(other);
    await expect(other.getByRole("heading", { name: "Account activated" })).toBeVisible();
    await expect(other.getByText("Go back to the application you were signing in to")).toBeVisible();
    await expect(other.locator("code.auth-address")).toHaveText(otherBrowser);
    await expect(other.getByRole("link", { name: "Sign in to your account" })).toHaveAttribute("href", `${env.adminUrl}/account/profile`);
    await elsewhere.close();
    await started.context.close();
  });
  await deleteRegistered(page, sameBrowser);
  await deleteRegistered(page, otherBrowser);
});
