// Where a legal document for all apps shows (#622): My Account's footer, every sign-in page's footer,
// and the registration form, beside the fields it asks for, which also links the app's own documents
// when registration came from that app's sign-in. A document for all apps reaches every sign-in, so
// this runs alone, as a system test; every document is for information, and the fixture retires it
// when the test ends.
import type { Page } from "@playwright/test";
import { publishLegalDocument, retireLegalDocument, setLegalDocumentApps } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { testapp, userBrowser } from "../../../lib/testapp";

const general = "/admin/settings/general";
const registerUrl = `${env.authUrl}/account/register`;

function footer(page: Page) {
  return page.getByRole("navigation", { name: "Legal documents" });
}

test("a document for all apps is linked from My Account and every sign-in page until it is retired", async ({
  page,
  browser,
  legalDocuments,
}) => {
  const doc = await legalDocuments.create({ markdown: "For everyone." });
  await publishLegalDocument(page, doc.id);

  // My Account links its page on the auth server; the admin pages draw no footer.
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(footer(page).getByRole("link", { name: doc.title })).toHaveAttribute("href", `${env.authUrl}/legal/${doc.shortName}`);
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(footer(page)).toHaveCount(0);

  // Every sign-in page links it, an app's and one with no app behind it alike.
  const { context, page: user } = await userBrowser(browser);
  await user.goto(`${testapp.web.url}/login`);
  await expect(user).toHaveURL(/\/auth\/pwd/);
  await expect(footer(user).getByRole("link", { name: doc.title })).toHaveAttribute("href", `/legal/${doc.shortName}`);
  await user.goto(`${env.authUrl}/no-such-page`);
  await expect(user.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await footer(user).getByRole("link", { name: doc.title }).click();
  await expect(user).toHaveURL(`${env.authUrl}/legal/${doc.shortName}`);
  await expect(user.locator(".legal-text")).toHaveText("For everyone.");

  await retireLegalDocument(page, doc.id);
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(footer(page).getByRole("link", { name: doc.title })).toHaveCount(0);
  await user.goto(`${testapp.web.url}/login`);
  await expect(user).toHaveURL(/\/auth\/pwd/);
  await expect(footer(user).getByRole("link", { name: doc.title })).toHaveCount(0);
  await context.close();
});

test("the registration form links the documents for all apps, and the app's own when it came from the app's sign-in", async ({
  page,
  browser,
  legalDocuments,
}) => {
  const everyone = await legalDocuments.create({ markdown: "For everyone." });
  const own = await legalDocuments.create({ markdown: "For the web app." });
  await setLegalDocumentApps(page, own.id, [testapp.web.clientId]);
  await publishLegalDocument(page, everyone.id);
  await publishLegalDocument(page, own.id);

  await withSettingsRestored(page, general, async () => {
    await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: false });
    await saveSettings(page);

    // From the web app's sign-in: Create an account carries the sign-in on.
    const { context, page: user } = await userBrowser(browser);
    await user.goto(`${testapp.web.url}/login`);
    await expect(user).toHaveURL(/\/auth\/pwd/);
    await user.getByRole("link", { name: "Create an account" }).click();
    await expect(user).toHaveTitle(/^Create an account – /);
    const linked = user.locator("form #legal-documents");
    await expect(linked).toContainText("Before you create your account, read:");
    await expect(linked.getByRole("link", { name: everyone.title })).toHaveAttribute("href", `/legal/${everyone.shortName}`);
    await expect(linked.getByRole("link", { name: own.title })).toHaveAttribute("href", `/legal/${own.shortName}`);
    await expect(footer(user).getByRole("link", { name: own.title })).toBeVisible();
    await context.close();

    // Reached from anywhere else, it names no app.
    const { context: other, page: visitor } = await userBrowser(browser);
    await visitor.goto(registerUrl);
    const elsewhere = visitor.locator("form #legal-documents");
    await expect(elsewhere.getByRole("link", { name: everyone.title })).toBeVisible();
    await expect(elsewhere.getByRole("link", { name: own.title })).toHaveCount(0);
    await other.close();
  });
});
