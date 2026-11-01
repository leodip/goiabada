import { confirmDialog, detail, legalDocumentUrl, rowWithCell } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const list = `${env.adminUrl}/admin/legal-documents`;

test("a document never published is deleted once its short name is typed", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create({ markdown: "Never seen." });

  await page.goto(list);
  await rowWithCell(page, doc.title).getByRole("link", { name: `Delete ${doc.title}`, exact: true }).click();
  await expect(page).toHaveURL(legalDocumentUrl(doc.id, "delete"));
  await expect(page).toHaveTitle(new RegExp(`^Delete legal document – ${doc.title} – `));
  await expect(detail(page, "Short name")).toHaveText(doc.shortName);
  await expect(detail(page, "Title")).toHaveText(doc.title);
  await expect(detail(page, "Kind")).toHaveText("For information");

  const input = page.getByLabel("To confirm, type the short name");
  const deleteButton = page.getByRole("button", { name: "Delete document", exact: true });
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("Type the short name to confirm.");
  await expect(input).toHaveAttribute("aria-invalid", "true");
  await input.fill(`${doc.shortName}-wrong`);
  await deleteButton.click();
  await expect(page.locator("#delete-error")).toContainText("That isn't this document's short name. Type it as shown above.");
  await page.getByRole("link", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(list);
  await expect(rowWithCell(page, doc.title)).toHaveCount(1);

  // The draft's own page offers it too.
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator(".page-actions").getByRole("link", { name: "Delete", exact: true }).click();
  await input.fill(doc.shortName);
  await deleteButton.click();
  await expect(page).toHaveURL(list);
  await expect(rowWithCell(page, doc.title)).toHaveCount(0);
  const response = await page.goto(legalDocumentUrl(doc.id, "draft"));
  expect(response?.status()).toBe(404);
});

// Set to a client of the test's own before it is published, so no other test's sign-in shows it.
test("a published document is retired and restored, and is never deleted", async ({ page, clients, legalDocuments }) => {
  const client = await clients.create();
  const doc = await legalDocuments.create({ markdown: "In effect.", apps: [client.identifier], publish: true });

  // Neither its page nor the list offers to delete it, and its delete page says why.
  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await expect(page.locator(".page-actions").getByRole("link", { name: "Delete" })).toHaveCount(0);
  await page.goto(list);
  await expect(rowWithCell(page, doc.title).getByRole("link", { name: `Delete ${doc.title}` })).toHaveCount(0);
  await page.goto(legalDocumentUrl(doc.id, "delete"));
  await expect(page.getByText("A published document cannot be deleted, so the record of what users accepted is kept. Retire it instead.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete document" })).toHaveCount(0);

  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await page.getByRole("button", { name: "Retire", exact: true }).click();
  await confirmDialog(page, "It will no longer be in effect");
  await expect(page.getByText("Document retired.", { exact: true })).toBeVisible();
  await expect(page.getByText(/^Retired on .+\. It isn't in effect until it's restored\.$/)).toBeVisible();
  await expect(page.locator(".page-header .tag")).toHaveText(["For information", "Retired"]);
  // Its versions stay, readable.
  await expect(page.locator("#versionsTable tbody tr")).toHaveCount(1);
  await page.getByRole("link", { name: "Version 1", exact: true }).click();
  await expect(page.locator("#versionMarkdown")).toHaveText("In effect.");

  // Read only until it's restored.
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await expect(page.getByText("This document is retired, so its draft can't be changed. Restore it to edit it.")).toBeVisible();
  await expect(page.locator("#markdown")).toHaveAttribute("readonly", "");
  await expect(page.locator("#btnSave")).toHaveCount(0);
  await expect(page.locator("#btnPublish")).toHaveCount(0);
  await page.goto(list);
  await expect(rowWithCell(page, doc.title).getByRole("cell").nth(1)).toHaveText(/For information\s*Retired/);

  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  await confirmDialog(page, "It will be in effect again as it was, at version 1.");
  await expect(page.getByText("Document restored.", { exact: true })).toBeVisible();
  await expect(page.locator(".page-header .tag")).toHaveText(["For information", "Version 1"]);
  await expect(page.getByRole("button", { name: "Retire", exact: true })).toBeVisible();
});
