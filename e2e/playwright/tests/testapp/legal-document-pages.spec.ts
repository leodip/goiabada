// A legal document's public pages (#622): /legal/<short-name> shows the version in effect and links
// every version, readable with no sign-in, and a retired document's pages are not found. Every
// document here is for information and set to selected apps, the test app's web app, before it is
// published, so no other test's sign-in is asked anything.
import { publishLegalDocument, retireLegalDocument, saveLegalDocumentDraft, setLegalDocumentApps } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, type TestLegalDocument, test } from "../../lib/fixtures";
import { testapp, userBrowser } from "../../lib/testapp";

function publicPage(doc: TestLegalDocument, version?: number) {
  return `${env.authUrl}/legal/${doc.shortName}${version === undefined ? "" : `/versions/${version}`}`;
}

test("a document's page shows the version in effect and every earlier one, with no sign-in", async ({ page, browser, legalDocuments }) => {
  const doc = await legalDocuments.create({ markdown: "## What we keep\n\nYour **email address**." });
  await setLegalDocumentApps(page, doc.id, [testapp.web.clientId]);
  await publishLegalDocument(page, doc.id);
  await saveLegalDocumentDraft(page, doc.id, { title: `${doc.title}, revised`, markdown: "We keep your *postal address* too." });
  await publishLegalDocument(page, doc.id);

  const { context, page: reader } = await userBrowser(browser);
  await reader.goto(publicPage(doc));
  await expect(reader).toHaveTitle(new RegExp(`^${doc.title}, revised – `));
  await expect(reader.getByRole("heading", { level: 1 })).toHaveText(`${doc.title}, revised`);
  await expect(reader.locator("#legal-document-version")).toContainText("Version 2");
  await expect(reader.locator(".legal-text em")).toHaveText("postal address");
  await expect(reader.locator("#legal-document-superseded")).toHaveCount(0);
  const versions = reader.locator("#legal-document-versions");
  await expect(versions.getByRole("link", { name: "Version 2" })).toHaveAttribute("aria-current", "page");

  await versions.getByRole("link", { name: "Version 1" }).click();
  await expect(reader).toHaveURL(publicPage(doc, 1));
  await expect(reader.getByRole("heading", { level: 1 })).toHaveText(doc.title);
  await expect(reader.getByRole("heading", { name: "What we keep" })).toBeVisible();
  await expect(reader.locator(".legal-text strong")).toHaveText("email address");
  await expect(reader.locator("#legal-document-superseded")).toContainText("This version is no longer in effect. Version 2 is the current one.");
  await reader.getByRole("link", { name: "Read the current version" }).click();
  await expect(reader).toHaveURL(publicPage(doc));

  // A version not published yet has no page.
  const missing = await reader.goto(publicPage(doc, 3));
  expect(missing?.status()).toBe(404);
  await expect(reader.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await context.close();
});

test("a draft is never public, and a retired document's pages are not found", async ({ page, browser, legalDocuments }) => {
  const doc = await legalDocuments.create({ markdown: "Published text." });
  const { context, page: reader } = await userBrowser(browser);
  expect((await reader.goto(publicPage(doc)))?.status(), "never published").toBe(404);

  await setLegalDocumentApps(page, doc.id, [testapp.web.clientId]);
  await publishLegalDocument(page, doc.id);
  await saveLegalDocumentDraft(page, doc.id, { markdown: "The draft's unpublished text." });
  expect((await reader.goto(publicPage(doc)))?.status()).toBe(200);
  await expect(reader.locator(".legal-text")).toHaveText("Published text.");
  await expect(reader.getByText("unpublished text")).toHaveCount(0);

  await retireLegalDocument(page, doc.id);
  expect((await reader.goto(publicPage(doc)))?.status()).toBe(404);
  await expect(reader.getByRole("heading", { name: "Page not found" })).toBeVisible();
  expect((await reader.goto(publicPage(doc, 1)))?.status(), "nor any of its versions").toBe(404);
  await context.close();
});
