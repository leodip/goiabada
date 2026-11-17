// The email template editor under Admin - Email (#818), as far as it goes without saving, which
// changes what every email in a language says and is email-templates.system.ts's: the placeholder
// buttons insert at the cursor of the subject or the body, whichever was focused last, the button on a
// line of its own; another language asks before it drops text that is not saved; the preview draws
// the email in the brand chosen for it (#817); and the body's format renders its marks, writes
// markup and a link to another scheme as typed text, which a test email sent from the form shows as a
// recipient would get it.
//
// Nothing here is saved, and the brand is the test's own, so this is an ordinary parallel spec.
import type { Page } from "@playwright/test";
import { cancelDialog, confirmDialog } from "../../lib/admin-console";
import { brandKitToken, setBrandKit, uploadBrandAsset, withBrand } from "../../lib/brands";
import { emailTemplateUrl } from "../../lib/email-templates";
import { expect, test } from "../../lib/fixtures";
import { solidPng } from "../../lib/images";
import { waitForMail } from "../../lib/mailpit";
import { uniqueIdentifier } from "../../lib/unique";

// An editor holding text that is not saved asks before it is left, which these tests answer yes.
function leaveWithoutAsking(page: Page) {
  page.on("dialog", (dialog) => {
    if (dialog.type() === "beforeunload") void dialog.accept();
  });
}

// The placeholder button for name, such as {{name}}.
function placeholder(page: Page, name: string) {
  return page.locator(`button[data-placeholder="${name}"]`);
}

// Puts the cursor of a field at offset.
async function cursorAt(page: Page, field: string, offset: number) {
  await page.locator(field).evaluate((element: HTMLInputElement | HTMLTextAreaElement, at) => {
    element.focus();
    element.setSelectionRange(at, at);
  }, offset);
}

test("a placeholder button inserts at the cursor of the subject or the body, and the button on a line of its own", async ({ page }) => {
  leaveWithoutAsking(page);
  await page.goto(emailTemplateUrl("password_reset_link", "en"));
  await expect(placeholder(page, "link")).toContainText("required");

  // In the body, at the cursor, replacing nothing.
  await page.locator("#body").fill("Hello ,\n\nBye.");
  await cursorAt(page, "#body", "Hello ".length);
  await placeholder(page, "name").click();
  await expect(page.locator("#body")).toHaveValue("Hello {{name}},\n\nBye.");
  await expect(page.locator("#body")).toBeFocused();

  // The button, at the end of a line, goes on a line of its own.
  await cursorAt(page, "#body", "Hello {{name}},".length);
  await placeholder(page, "button").click();
  await expect(page.locator("#body")).toHaveValue("Hello {{name}},\n{{button}}\n\nBye.");

  // In the subject, at its cursor, once the subject was the field focused last.
  await page.locator("#subject").fill("Reset your password");
  await cursorAt(page, "#subject", "Reset your".length);
  await placeholder(page, "app_name").click();
  await expect(page.locator("#subject")).toHaveValue("Reset your{{app_name}} password");

  // The link is not the subject's: it goes into the body, at the body's cursor, and the subject is
  // left as it was.
  await cursorAt(page, "#subject", 0);
  await placeholder(page, "link").click();
  await expect(page.locator("#subject")).toHaveValue("Reset your{{app_name}} password");
  await expect(page.locator("#body")).toHaveValue(/\{\{link\}\}/);
  await expect(page.locator("#body")).toBeFocused();
});

test("another language asks before it drops text that is not saved: Cancel keeps the text, Discard changes goes", async ({ page }) => {
  leaveWithoutAsking(page);
  const english = emailTemplateUrl("password_reset_link", "en");
  const german = emailTemplateUrl("password_reset_link", "de");
  const toGerman = page.locator('#emailTemplateLanguages a[href$="/password_reset_link/de"]');

  // Nothing typed: another language opens at once.
  await page.goto(english);
  await toGerman.click();
  await expect(page).toHaveURL(german);

  await page.goto(english);
  const typed = `Your password ${uniqueIdentifier("mark")}`;
  await page.locator("#subject").fill(typed);
  await toGerman.click();
  await cancelDialog(page, "The changes to this email are not saved, and will be lost.");
  await expect(page).toHaveURL(english);
  await expect(page.locator("#subject")).toHaveValue(typed);

  await toGerman.click();
  await confirmDialog(page, "The changes to this email are not saved, and will be lost.");
  await expect(page).toHaveURL(german);
  await page.goto(english);
  await expect(page.locator("#subject"), "nothing was saved").toHaveValue("Password reset");
});

// Plum's dark canvas and brand color, and Blueberry's light ones, as an email writes them inline.
const plumDark = { canvas: "#120f15", brand: "#cda4f0" };
const blueberryLight = { canvas: "#f4f5f7", brand: "#2456c4" };

test("the preview draws the email in the brand chosen for it, a Dark brand's in its dark palette with its logo", async ({ page, request, clients }) => {
  const token = await brandKitToken(page, request, clients);
  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    const logo = await uploadBrandAsset(request, token, "logo", solidPng(240, 80, [250, 200, 60]));
    await setBrandKit(request, token, brand.id, { logo });

    await page.goto(emailTemplateUrl("password_reset_link", "en"));
    const frame = page.frameLocator('iframe[name="emailTemplatePreviewFrame"]');
    // The default brand first, the seeded Blueberry, light.
    await expect(page.locator("#previewBrand option:checked")).toHaveText(/^Default brand \(/);
    await expect(frame.locator("body")).toHaveAttribute("style", new RegExp(`background-color: ${blueberryLight.canvas};`));
    await expect(frame.locator("[data-email-button] td")).toHaveAttribute("bgcolor", blueberryLight.brand);

    await page.locator("#previewBrand").selectOption({ label: brand.name });
    await expect(frame.locator("body")).toHaveAttribute("style", new RegExp(`background-color: ${plumDark.canvas};`));
    await expect(frame.locator("[data-email-button] td")).toHaveAttribute("bgcolor", plumDark.brand);
    await expect(frame.locator("img")).toHaveAttribute("src", logo.url);
    await expect(frame.locator('meta[name="color-scheme"]')).toHaveAttribute("content", "dark");
  });
});

test("the body's marks render, and markup and a link to another scheme arrive as typed text, in the preview and in a test email", async ({
  page,
  request,
}) => {
  leaveWithoutAsking(page);
  const mark = uniqueIdentifier("mark");
  const body = [
    "Hi {{name}},",
    "",
    `*${mark} in italics*, **bold**, a [guide](https://example.com/guide) and [a script](javascript:alert(1)).`,
    "",
    "<script>alert(1)</script> <b>not bold</b>",
    "",
    "- first",
    "- second",
    "",
    "1. one",
    "2. two",
    "",
    "{{button}}",
    "",
    "{{link}}",
  ].join("\n");

  await page.goto(emailTemplateUrl("password_reset_link", "en"));
  await page.locator("#body").fill(body);

  // The preview, drawn in its sandboxed frame.
  const frame = page.frameLocator('iframe[name="emailTemplatePreviewFrame"]');
  await expect(frame.locator("em", { hasText: `${mark} in italics` })).toBeVisible();
  await expect(frame.getByRole("link", { name: "guide", exact: true })).toHaveAttribute("href", "https://example.com/guide");
  await expect(frame.getByRole("link", { name: "a script" })).toHaveCount(0);
  await expect(frame.getByText("<script>alert(1)</script> <b>not bold</b>", { exact: true })).toBeVisible();
  await expect(frame.locator("ul li")).toHaveText(["first", "second"]);
  await expect(frame.locator("ol li")).toHaveText(["one", "two"]);
  await expect(frame.locator("script")).toHaveCount(0);

  // The same text, sent as a test email.
  const to = `${uniqueIdentifier("t")}@example.com`;
  await page.locator("#testAddress").fill(to);
  await page.locator("#btnSendTest").click();
  await expect(page.locator("#sendTestStatus")).toContainText(`Test email sent to ${to}.`);
  const mail = await waitForMail(request, to);
  expect(mail.html).toMatch(new RegExp(`<em[^>]*>${mark} in italics</em>`));
  expect(mail.html).toMatch(/<strong[^>]*>bold<\/strong>/);
  expect(mail.html).toMatch(/<a href="https:\/\/example\.com\/guide"[^>]*>guide<\/a>/);
  expect(mail.html, "a link to another scheme keeps its text and loses its link").toContain("a script");
  expect(mail.html).not.toContain("javascript:");
  expect(mail.html).toContain("&lt;script&gt;alert(1)&lt;/script&gt; &lt;b&gt;not bold&lt;/b&gt;");
  expect(mail.html).not.toMatch(/<script/i);
  expect(mail.html).toMatch(/<ul[^>]*>\s*<li[^>]*>first<\/li>\s*<li[^>]*>second<\/li>\s*<\/ul>/);
  expect(mail.html).toMatch(/<ol[^>]*>\s*<li[^>]*>one<\/li>\s*<li[^>]*>two<\/li>\s*<\/ol>/);
  expect(mail.text).toContain("<script>alert(1)</script> <b>not bold</b>");
});
