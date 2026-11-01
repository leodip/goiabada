// The registration form links the legal documents for all apps beside the fields it asks for, and
// the app's own documents when registration came from that app's sign-in (#622). A document for all
// apps reaches every sign-in, so this runs alone, as a system test; every document is for
// information, and the fixture retires it when the test ends.
import { publishLegalDocument, setLegalDocumentApps } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { testapp, userBrowser } from "../../../lib/testapp";

const general = "/admin/settings/general";
const registerUrl = `${env.authUrl}/account/register`;

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
