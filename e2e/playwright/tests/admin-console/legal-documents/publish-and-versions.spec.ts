import { cancelDialog, confirmDialog, legalDocumentUrl, saveLegalDocumentDraft } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

// The documents here are notices for information, published, and retired once each test ends, by
// the fixture.

test("the preview shows the text as the document's page will, following the editor", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create();
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  const preview = page.locator("#legalDocumentPreview");

  await page.locator("#markdown").fill(
    [
      "# Our privacy notice",
      "",
      "We keep **your email** and [nothing else](https://example.com/more).",
      "",
      "| Data | Kept for |",
      "|---|---|",
      "| Email | A year |",
      "",
      "<b>raw</b> and <script>alert(1)</script>",
      "",
      "[a trap](javascript:alert(1))",
      "",
      "![our logo](https://example.com/logo.png)",
    ].join("\n"),
  );

  await expect(preview.getByRole("heading", { level: 1, name: "Our privacy notice" })).toBeVisible();
  await expect(preview.locator("strong")).toHaveText("your email");
  await expect(preview.getByRole("link", { name: "nothing else" })).toHaveAttribute("href", "https://example.com/more");
  await expect(preview.getByRole("cell", { name: "A year" })).toBeVisible();
  // Raw HTML is left out, a script address dropped, and an image drawn as a link to it, never loaded.
  await expect(preview.locator("b, script")).toHaveCount(0);
  await expect(preview.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(preview.locator("img")).toHaveCount(0);
  await expect(preview.getByRole("link", { name: "our logo" })).toHaveAttribute("href", "https://example.com/logo.png");

  // It follows the text as it changes, saved or not.
  await page.locator("#markdown").fill("## Shorter now");
  await expect(preview.getByRole("heading", { level: 2, name: "Shorter now" })).toBeVisible();
  await expect(preview.getByRole("heading", { level: 1 })).toHaveCount(0);
});

test("a saved draft is published as version 1, the next one as version 2, and each stays as published", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create({ markdown: "First text." });

  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator("#btnPublish").click();
  await confirmDialog(page, "The saved draft will become version 1, which never changes, and will be shown from then on.");
  await expect(page).toHaveURL(legalDocumentUrl(doc.id, "versions"));
  await expect(page.getByText("Version 1 published.", { exact: true })).toBeVisible();
  await expect(page.locator(".page-header .tag")).toHaveText(["For information", "Version 1"]);
  await expect(page.locator("#versionsTable tbody tr")).toHaveCount(1);
  await expect(page.locator("#versionsTable tbody tr").first()).toContainText("Current");

  // With no draft, the editor opens on version 1's text, and the short name is fixed.
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await expect(page.getByText("There's no draft: the text below is version 1. Saving it starts a draft.")).toBeVisible();
  await expect(page.locator("#markdown")).toHaveValue("First text.");
  await expect(page.locator("#shortName")).toHaveAttribute("readonly", "");
  await expect(page.locator("#btnPublish")).toHaveCount(0);

  await saveLegalDocumentDraft(page, doc.id, { title: `${doc.title} (revised)`, markdown: "Second text." });
  await expect(page.locator(".page-header .tag")).toHaveText(["For information", "Version 1", "Draft"]);
  await page.locator("#btnPublish").click();
  await confirmDialog(page, "The saved draft will become version 2");
  await expect(page.getByText("Version 2 published.", { exact: true })).toBeVisible();
  const rows = page.locator("#versionsTable tbody tr");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0).getByRole("cell").nth(0)).toHaveText("Version 1");
  await expect(rows.nth(0).getByRole("cell").nth(1)).toHaveText(doc.title);
  await expect(rows.nth(1).getByRole("cell").nth(0)).toHaveText("Version 2 Current");
  await expect(rows.nth(1).getByRole("cell").nth(1)).toHaveText(`${doc.title} (revised)`);
  await expect(page.getByRole("heading", { level: 1, name: `${doc.title} (revised)`, exact: true })).toBeVisible();

  // Version 1 reads as it was published.
  await rows.nth(0).getByRole("link", { name: "Version 1", exact: true }).click();
  await expect(page).toHaveURL(`${legalDocumentUrl(doc.id, "versions")}/1`);
  await expect(page.getByRole("heading", { level: 1, name: "Version 1", exact: true })).toBeVisible();
  await expect(page.locator("#versionMarkdown")).toHaveText("First text.");
  await expect(page.locator("#legalDocumentPreview")).toHaveText("First text.");
});

test("Publish publishes the draft as saved, not the changes typed since", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create({ markdown: "Saved text." });
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator("#markdown").fill("Typed but never saved.");
  await page.locator("#btnPublish").click();
  await confirmDialog(page, "Changes not saved aren't published.");
  await expect(page.getByText("Version 1 published.", { exact: true })).toBeVisible();

  await page.goto(`${legalDocumentUrl(doc.id, "versions")}/1`);
  await expect(page.locator("#versionMarkdown")).toHaveText("Saved text.");
});

test("a draft with no text is refused at the text", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create();
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator("#btnPublish").click();
  await confirmDialog(page);
  await expect(page).toHaveURL(`${env.adminUrl}/admin/legal-documents/${doc.id}/publish`);
  await expect(page.locator("#draft-error")).toContainText("The draft has no text to publish.");
  await expect(page.locator("#markdown")).toHaveAttribute("aria-invalid", "true");

  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await expect(page.getByText("Not published yet. Publishing the draft makes it version 1.", { exact: true })).toBeVisible();
});

// Asked, and answered Cancel: a must-accept document is never published here, so no sign-in of
// another test is asked to accept it.
test("publishing a document users must accept says they'll be asked to accept it again", async ({ page, legalDocuments }) => {
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "Be kind." });
  await page.goto(legalDocumentUrl(doc.id, "draft"));
  await page.locator("#btnPublish").click();
  await cancelDialog(page, "users will be asked to accept it at their next sign-in");
  await expect(page).toHaveURL(legalDocumentUrl(doc.id, "draft"));

  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await expect(page.locator(".page-header .tag")).toHaveText(["Users must accept", "Not published"]);
});
