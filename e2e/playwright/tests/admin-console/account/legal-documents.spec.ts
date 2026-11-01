// My Account's Legal documents page (#622): each version the user accepted at sign-in, the latest
// first, linked to that version's public page, and marked no longer in effect once its document is
// retired.
//
// The document is set to selected apps, a client of the test's own, before it is published, so no
// other test's sign-in owes it. The clients fixture deletes the client, and the legal documents
// fixture retires the document.
import type { Browser } from "@playwright/test";
import { publishLegalDocument, retireLegalDocument, saveLegalDocumentDraft, setLegalDocumentApps } from "../../../lib/admin-console";
import { openSignIn, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";

// Signs in to the client in a browser of its own and accepts what the step lists.
async function signInAndAccept(browser: Browser, client: TestClient, user: { email: string; password: string }) {
  const { context, page } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await submitPassword(page, user.email, user.password);
  await expect(page).toHaveURL(/\/auth\/legal-acceptance/);
  for (const box of await page.getByRole("checkbox").all()) await box.check();
  await page.getByRole("button", { name: "Accept", exact: true }).click();
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await context.close();
}

test("the user sees each version they accepted, linked to its public page, until the document is retired", async ({
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
  await signInAndAccept(browser, client, user);
  await saveLegalDocumentDraft(page, doc.id, { markdown: "Be even nicer to each other." });
  await publishLegalDocument(page, doc.id);
  await signInAndAccept(browser, client, user);

  const own = await signInToConsole(browser, user, "/account/legal-documents");
  await expect(own.page.getByRole("heading", { level: 1, name: "Legal documents" })).toBeVisible();
  await expect(own.page.locator(".sidebar").getByRole("link", { name: "Legal documents" })).toHaveAttribute("aria-current", "page");
  const rows = own.page.locator("#acceptancesTable tbody tr");
  await expect(rows).toHaveCount(2);
  // The latest acceptance first: version 2, then version 1.
  await expect(rows.nth(0).locator("td").nth(1)).toHaveText("2");
  await expect(rows.nth(0).getByRole("link", { name: doc.title })).toHaveAttribute("href", `${env.authUrl}/legal/${doc.shortName}/versions/2`);
  await expect(rows.nth(1).locator("td").nth(1)).toHaveText("1");
  await expect(rows.nth(1).getByRole("link", { name: doc.title })).toHaveAttribute("href", `${env.authUrl}/legal/${doc.shortName}/versions/1`);

  // The link opens the accepted version's public page.
  await rows.nth(1).getByRole("link", { name: doc.title }).click();
  await expect(own.page).toHaveURL(`${env.authUrl}/legal/${doc.shortName}/versions/1`);
  await expect(own.page.getByText("Be nice to each other.")).toBeVisible();

  // Retired, the document's pages answer not found, so the page says so instead of linking.
  await retireLegalDocument(page, doc.id);
  await own.page.goto(`${env.adminUrl}/account/legal-documents`);
  await expect(rows).toHaveCount(2);
  await expect(rows.getByRole("link", { name: doc.title })).toHaveCount(0);
  await expect(rows.nth(0)).toContainText("No longer in effect");
  await expect(rows.nth(1)).toContainText("No longer in effect");
  await own.context.close();
});

test("a user who accepted nothing is told so", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/legal-documents");
  await expect(own.page.getByText("You haven't accepted any legal documents.")).toBeVisible();
  await expect(own.page.locator("#acceptancesTable")).toHaveCount(0);
  await own.context.close();
});
