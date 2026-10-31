import type { Page } from "@playwright/test";
import {
  clientUrl,
  deleteClient,
  legalDocumentUrl,
  publishLegalDocument,
  retireLegalDocument,
  rowWithCell,
  setLegalDocumentApps,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

// A legal document's Applies to (#622): all apps, the default, or the clients ticked. Every document
// here is set to selected apps with clients of the test's own before anything is published, so no
// other test's sign-in meets it.

const list = `${env.adminUrl}/admin/legal-documents`;

// The Applies to cell of a document's row in the list, or on a client's Legal documents tab.
function appliesToCell(page: Page, title: string) {
  return rowWithCell(page, title).locator('td[data-label="Applies to"]');
}

test("a document applies to all apps until its apps are chosen, never the admin console's own", async ({
  page,
  clients,
  legalDocuments,
}) => {
  const shop = await clients.create();
  const blog = await clients.create();
  const doc = await legalDocuments.create({ kind: "must_accept" });

  await page.goto(legalDocumentUrl(doc.id, "apps"));
  await expect(page).toHaveTitle(new RegExp(`^Applies to – ${doc.title} – `));
  await expect(page.getByRole("link", { name: "Applies to", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.locator("#appliesToAllApps")).toBeChecked();
  const apps = page.locator("#appsList");
  await expect(apps.getByText(shop.identifier, { exact: true })).toBeVisible();
  await expect(apps.getByText(blog.identifier, { exact: true })).toBeVisible();
  await expect(apps.getByText("admin-console-client", { exact: true })).toHaveCount(0);
  await page.goto(list);
  await expect(appliesToCell(page, doc.title)).toHaveText("All apps");

  await setLegalDocumentApps(page, doc.id, [shop.identifier]);
  await expect(page.locator("#appliesToSelectedApps")).toBeChecked();
  await expect(page.locator("#appsList label.check-row").filter({ hasText: shop.identifier }).locator("input")).toBeChecked();
  await expect(page.locator("#appsList label.check-row").filter({ hasText: blog.identifier }).locator("input")).not.toBeChecked();
  await page.goto(list);
  await expect(appliesToCell(page, doc.title)).toHaveText("Selected apps");

  // Each client's own tab lists, read only, the documents that apply to it.
  await page.goto(clientUrl(shop.id, "legal-documents"));
  await expect(page.getByRole("link", { name: "Legal documents", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(appliesToCell(page, doc.title)).toHaveText("Selected apps");
  await expect(rowWithCell(page, doc.title).getByRole("link", { name: doc.title })).toHaveAttribute(
    "href",
    `/admin/legal-documents/${doc.id}/draft`,
  );
  await page.goto(clientUrl(blog.id, "legal-documents"));
  await expect(rowWithCell(page, doc.title)).toHaveCount(0);

  // Back to all apps: every client has it, and no box stays ticked.
  await setLegalDocumentApps(page, doc.id, "all");
  await expect(page.locator('#appsList input[type="checkbox"]:checked')).toHaveCount(0);
  await page.goto(clientUrl(blog.id, "legal-documents"));
  await expect(appliesToCell(page, doc.title)).toHaveText("All apps");
});

test("a document whose last app is deleted applies to nobody and is flagged", async ({ page, clients, legalDocuments }) => {
  const kept = await clients.create();
  const gone = await clients.create();
  const both = await legalDocuments.create({ kind: "must_accept" });
  const only = await legalDocuments.create({ kind: "must_accept" });
  await setLegalDocumentApps(page, both.id, [kept.identifier, gone.identifier]);
  await setLegalDocumentApps(page, only.id, [gone.identifier]);

  await deleteClient(page, gone.id);
  gone.markDeleted();

  await page.goto(list);
  await expect(appliesToCell(page, both.title)).toHaveText("Selected apps");
  await expect(appliesToCell(page, only.title)).toHaveText(/^\s*No apps\s*Applies to nobody\s*$/);
  await expect(appliesToCell(page, only.title).locator(".tag-caution")).toHaveText("No apps");

  await page.goto(legalDocumentUrl(only.id, "apps"));
  await expect(page.locator("#appliesToSelectedApps")).toBeChecked();
  await expect(page.locator("#noAppsNotice")).toContainText("No app is selected, so this document applies to nobody.");
  await page.goto(legalDocumentUrl(both.id, "apps"));
  await expect(page.locator("#appsList label.check-row").filter({ hasText: kept.identifier }).locator("input")).toBeChecked();
  await expect(page.locator("#noAppsNotice")).toHaveCount(0);
});

test("a save from a page another save has outdated is refused", async ({ page, context, clients, legalDocuments }) => {
  const shop = await clients.create();
  const blog = await clients.create();
  const doc = await legalDocuments.create({ kind: "must_accept" });
  await setLegalDocumentApps(page, doc.id, [shop.identifier]);

  // A second tab opens the same page, and a save from the first changes the list under it.
  const other = await context.newPage();
  await other.goto(legalDocumentUrl(doc.id, "apps"));
  await setLegalDocumentApps(page, doc.id, [blog.identifier]);

  await other.locator("#appsList label.check-row").filter({ hasText: shop.identifier }).locator("input").uncheck();
  await other.locator("#btnSaveApps").click();
  await expect(other.locator("#apps-error")).toBeVisible();
  await other.close();

  await page.goto(legalDocumentUrl(doc.id, "apps"));
  await expect(page.locator("#appsList label.check-row").filter({ hasText: blog.identifier }).locator("input")).toBeChecked();
});

test("a retired document's apps are read only until it is restored", async ({ page, clients, legalDocuments }) => {
  const shop = await clients.create();
  const doc = await legalDocuments.create({ markdown: "Shop notice." });
  await setLegalDocumentApps(page, doc.id, [shop.identifier]);
  await publishLegalDocument(page, doc.id);
  await retireLegalDocument(page, doc.id);

  await page.goto(legalDocumentUrl(doc.id, "apps"));
  await expect(page.getByText("This document is retired, so the apps it applies to can't be changed. Restore it to change them.")).toBeVisible();
  await expect(page.locator("#appliesToSelectedApps")).toBeDisabled();
  await expect(page.locator("#btnSaveApps")).toHaveCount(0);

  // A retired document applies to no app, so the client's tab leaves it out.
  await page.goto(clientUrl(shop.id, "legal-documents"));
  await expect(rowWithCell(page, doc.title)).toHaveCount(0);
});
