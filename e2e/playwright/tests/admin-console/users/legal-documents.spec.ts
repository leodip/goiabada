// A user's Legal documents tab (#622): each version the user accepted at sign-in, the latest first,
// opening the exact text accepted in the console, a retired document's included.
//
// The document is set to selected apps, a client of the test's own, before it is published, so no
// other test's sign-in owes it. The clients fixture deletes the client, and the legal documents
// fixture retires the document.
import { publishLegalDocument, retireLegalDocument, saveLegalDocumentDraft, setLegalDocumentApps, userUrl } from "../../../lib/admin-console";
import { openSignIn, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";

test("the tab lists each version the user accepted and opens its text, the document retired or not", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice to each other." });
  await setLegalDocumentApps(page, doc.id, [client.identifier]);
  await publishLegalDocument(page, doc.id);

  const { context, page: own } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await submitPassword(own, user.email, user.password);
  await expect(own).toHaveURL(/\/auth\/legal-acceptance/);
  await own.getByRole("checkbox").check();
  await own.getByRole("button", { name: "Accept", exact: true }).click();
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await context.close();
  // A later version the user never accepted is not listed.
  await saveLegalDocumentDraft(page, doc.id, { markdown: "Be even nicer to each other." });
  await publishLegalDocument(page, doc.id);

  await page.goto(userUrl(user.id, "legal-documents"));
  await expect(page.locator(".tab-bar").getByRole("link", { name: "Legal documents" })).toHaveAttribute("aria-current", "page");
  const rows = page.locator("#acceptancesTable tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(doc.title);
  await expect(rows.first()).toContainText(doc.shortName);
  await expect(rows.first().locator("td").nth(1)).toHaveText("1");

  await rows.first().getByRole("link", { name: /^View text/ }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/legal-documents/${doc.id}/versions/1`);
  await expect(page.locator("#versionMarkdown")).toHaveText("Be nice to each other.");

  // Retired, the document is marked so, and the accepted text still opens.
  await retireLegalDocument(page, doc.id);
  await page.goto(userUrl(user.id, "legal-documents"));
  await expect(rows.first().getByText("Retired", { exact: true })).toBeVisible();
  await rows.first().getByRole("link", { name: /^View text/ }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/legal-documents/${doc.id}/versions/1`);
  await expect(page.locator("#versionMarkdown")).toHaveText("Be nice to each other.");
});

test("a user who accepted nothing has an empty tab", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "legal-documents"));
  await expect(page.getByText("This user hasn't accepted any legal documents.")).toBeVisible();
});
