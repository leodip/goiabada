// A legal document's public pages and the sign-in pages' footer (#622): /legal/<short-name> shows the
// version in effect and links every version, readable with no sign-in; a retired document's pages
// are not found; and the footer of an app's sign-in links that app's own documents and no other
// app's. Every document here is for information and set to selected apps, the test app's web apps,
// before it is published, so no other test's sign-in is asked anything.
import type { Page } from "@playwright/test";
import { publishLegalDocument, retireLegalDocument, saveLegalDocumentDraft, setLegalDocumentApps } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, type TestLegalDocument, test } from "../../lib/fixtures";
import { testapp, userBrowser } from "../../lib/testapp";

function publicPage(doc: TestLegalDocument, version?: number) {
  return `${env.authUrl}/legal/${doc.shortName}${version === undefined ? "" : `/versions/${version}`}`;
}

// The links of the legal documents' footer on the page the browser shows.
function footer(page: Page) {
  return page.getByRole("navigation", { name: "Legal documents" });
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

test("an app's sign-in pages link that app's documents, and no other app's", async ({ page, browser, legalDocuments }) => {
  const web = await legalDocuments.create({ markdown: "For the web app." });
  const web2 = await legalDocuments.create({ markdown: "For the second web app." });
  await setLegalDocumentApps(page, web.id, [testapp.web.clientId]);
  await setLegalDocumentApps(page, web2.id, [testapp.web2.clientId]);
  await publishLegalDocument(page, web.id);
  await publishLegalDocument(page, web2.id);

  const { context, page: user } = await userBrowser(browser);
  await user.goto(`${testapp.web.url}/login`);
  await expect(user).toHaveURL(/\/auth\/pwd/);
  await expect(footer(user).getByRole("link", { name: web.title })).toHaveAttribute("href", `/legal/${web.shortName}`);
  await expect(footer(user).getByRole("link", { name: web2.title })).toHaveCount(0);

  await user.goto(`${testapp.web2.url}/login`);
  await expect(user).toHaveURL(/\/auth\/pwd/);
  await expect(footer(user).getByRole("link", { name: web2.title })).toBeVisible();
  await expect(footer(user).getByRole("link", { name: web.title })).toHaveCount(0);

  // The link opens the document's page, whose own footer names no app.
  await footer(user).getByRole("link", { name: web2.title }).click();
  await expect(user).toHaveURL(publicPage(web2));
  await expect(user.locator(".legal-text")).toHaveText("For the second web app.");
  await expect(footer(user).getByRole("link", { name: web2.title })).toHaveCount(0);
  await context.close();
});
