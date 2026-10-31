import { randomBytes } from "node:crypto";
import {
  deleteLegalDocument,
  expectRefusal,
  legalDocumentIdFrom,
  legalDocumentUrl,
  rowWithCell,
  submitNewLegalDocument,
} from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { testPrefix, uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/legal-documents`;

test("a legal document is created with its kind, a title and the short name suggested from it, and listed", async ({ page }) => {
  const suffix = randomBytes(4).toString("hex");
  const title = `E2E Política de Privacidade ${suffix}`;
  const shortName = `${testPrefix}politica-de-privacidade-${suffix}`;

  await page.goto(list);
  await expect(page.getByRole("link", { name: "Legal documents", exact: true })).toHaveAttribute("aria-current", "page");
  await page.getByRole("link", { name: "New legal document", exact: true }).click();
  await expect(page).toHaveURL(`${list}/new`);
  await expect(page.getByRole("heading", { level: 1, name: "New legal document", exact: true })).toBeVisible();
  // Which kind a document is can't change later, so the form chooses neither.
  await expect(page.locator("#kindMustAccept")).not.toBeChecked();
  await expect(page.locator("#kindForInformation")).not.toBeChecked();

  await page.getByLabel("Users must accept").check();
  // Typed as a person types, so the suggestion follows each keystroke.
  await page.locator("#title").pressSequentially(title);
  await expect(page.locator("#shortName")).toHaveValue(shortName);
  await page.locator("#btnCreate").click();

  await expect(page).toHaveURL(/\/admin\/legal-documents\/\d+\/draft$/);
  const id = legalDocumentIdFrom(page.url());
  await expect(page.getByRole("heading", { level: 1, name: title, exact: true })).toBeVisible();
  await expect(page.locator(".page-header .tag")).toHaveText(["Users must accept", "Not published"]);
  await expect(page.locator(".page-header .code-hint")).toHaveText(`/legal/${shortName}`);
  await expect(page.getByRole("link", { name: "Draft", exact: true })).toHaveAttribute("aria-current", "page");

  await page.goto(list);
  const row = rowWithCell(page, title);
  await expect(row.getByRole("link", { name: title, exact: true })).toHaveAttribute("href", `/admin/legal-documents/${id}/draft`);
  await expect(row.getByText(shortName, { exact: true })).toBeVisible();
  await expect(row.getByRole("cell").nth(1)).toHaveText(/Users must accept\s*Not published/);
  await expect(row.getByRole("cell").nth(2)).toHaveText("Never");
  await expect(row.getByRole("link", { name: `Delete ${title}`, exact: true })).toBeVisible();

  await deleteLegalDocument(page, id);
  await expect(rowWithCell(page, title)).toHaveCount(0);
});

test("a short name the administrator types stays as the title changes", async ({ page }) => {
  const shortName = uniqueIdentifier("ld");
  await page.goto(`${list}/new`);
  await page.locator("#title").pressSequentially("Terms of use");
  await expect(page.locator("#shortName")).toHaveValue("terms-of-use");
  await page.locator("#shortName").fill(shortName);
  await page.locator("#title").pressSequentially(" for partners");
  await expect(page.locator("#shortName")).toHaveValue(shortName);
  // Emptied, it follows the title again.
  await page.locator("#shortName").fill("");
  await page.locator("#title").pressSequentially("!");
  await expect(page.locator("#shortName")).toHaveValue("terms-of-use-for-partners");
});

test("a document with no kind chosen is refused at the kind, keeping what was typed", async ({ page }) => {
  const shortName = uniqueIdentifier("ld");
  await submitNewLegalDocument(page, { title: "No kind", shortName });
  await expect(page).toHaveURL(`${list}/new`);
  await expectRefusal(page, "legal-document-error", "kindMustAccept",
    "Choose whether users must accept the document or it is for information.");
  await expect(page.locator("#title")).toHaveValue("No kind");
  await expect(page.locator("#shortName")).toHaveValue(shortName);
});

test("a document with no title is refused at the title", async ({ page }) => {
  await submitNewLegalDocument(page, { kind: "for_information", title: "", shortName: uniqueIdentifier("ld") });
  await expectRefusal(page, "legal-document-error", "title", "Title is required.");
  // The kind chosen is kept.
  await expect(page.locator("#kindForInformation")).toBeChecked();
});

for (const shortName of ["Has Capitals", "ends-with-", "-starts", "under_score"]) {
  test(`the short name ${JSON.stringify(shortName)} is refused`, async ({ page }) => {
    await submitNewLegalDocument(page, { kind: "for_information", title: "Bad short name", shortName });
    await expectRefusal(page, "legal-document-error", "shortName",
      "The short name can hold only lowercase letters, digits and hyphens, and must start and end with a letter or a digit.");
    await expect(page.locator("#shortName")).toHaveValue(shortName);
  });
}

test("a short name another document holds is refused", async ({ page, legalDocuments }) => {
  const existing = await legalDocuments.create();
  await submitNewLegalDocument(page, { kind: "for_information", title: "Taken", shortName: existing.shortName });
  await expectRefusal(page, "legal-document-error", "shortName", "Another document already uses this short name.");
  await page.goto(list);
  await expect(page.locator("#legalDocumentsTable").getByText(existing.shortName, { exact: true })).toHaveCount(1);
});

test("a document's short name can change on its draft until it is published", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create();
  const renamed = uniqueIdentifier("ld");
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator("#shortName").fill(renamed);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Draft saved.", { exact: true })).toBeVisible();
  await expect(page.locator("#shortName")).toHaveValue(renamed);
  await expect(page.locator(".page-header .code-hint")).toHaveText(`/legal/${renamed}`);
});
