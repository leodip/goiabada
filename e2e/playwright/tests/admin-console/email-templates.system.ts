// The email templates under Admin - Email (#818), read from the environment's Mailpit. The tab is
// reached from Branding and lists the emails. An edit of the password reset link's English text
// shows in the editor's preview, reaches a test email sent from the editor before it is saved, and
// once saved reaches the reset a user asks for; Reset to default brings the built-in text back to
// the next one. A text breaking a rule is refused naming the placeholder, in the preview and on
// save, and nothing is saved. An edit is global, so this runs alone, and resets what it saved.
import type { Browser, Page } from "@playwright/test";
import { emailTemplatesPath, emailTemplateUrl, resetEmailTemplate } from "../../lib/email-templates";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, type Mail, waitForMail } from "../../lib/mailpit";
import { uniqueIdentifier } from "../../lib/unique";

const listUrl = `${env.adminUrl}${emailTemplatesPath}`;

// The editor's own page title ends with the app name the emails are signed with.
async function appNameFromEditor(page: Page): Promise<string> {
  const title = await page.title();
  const match = title.match(/^Password reset link – Email templates – (.+)$/);
  expect(match, title).toBeTruthy();
  return match![1];
}

// Asks for a password reset for address on the forgot password page, in a browser holding no session.
async function askForReset(browser: Browser, address: string) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(`${env.authUrl}/forgot-password`);
  await forgot.locator("#email").fill(address);
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(forgot.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await context.close();
}

// The reset link a password reset carries.
function resetLink(mail: Mail): string {
  const link = linksIn(mail).find((l) => l.startsWith(`${env.authUrl}/reset-password?`));
  expect(link, mail.text).toBeTruthy();
  return link!;
}

// An editor holding text that is not saved asks before it is left, which these tests answer yes.
function leaveWithoutAsking(page: Page) {
  page.on("dialog", (dialog) => {
    if (dialog.type() === "beforeunload") void dialog.accept();
  });
}

test("the Email templates tab is reachable from Branding, and lists each email with when it's sent", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/settings/branding`);
  await page.locator("#brandingEmailsNote").getByRole("link", { name: "Go to Email templates", exact: true }).click();
  await expect(page).toHaveURL(listUrl);
  const tabs = page.getByRole("navigation", { name: "Sections", exact: true });
  await expect(tabs.getByRole("link", { name: "Email templates", exact: true })).toHaveAttribute("aria-current", "page");
  // And back: how the emails look is their brand's.
  await expect(page.getByRole("link", { name: "Go to Branding", exact: true })).toHaveAttribute("href", "/admin/settings/branding");

  for (const group of ["Registration", "Password", "Email verification", "Two-factor authentication", "Account", "Test email"]) {
    await expect(page.getByRole("heading", { level: 2, name: group, exact: true })).toBeVisible();
  }
  const reset = page.getByRole("link", { name: "Password reset link", exact: true });
  const row = page.locator("tbody tr").filter({ has: reset });
  await expect(row).toContainText("Sent when someone asks to reset a forgotten password.");
  await expect(row).toContainText("Built-in text");

  // The editor opens in the console's language, English here.
  await reset.click();
  await expect(page).toHaveURL(emailTemplateUrl("password_reset_link", "en"));
  await expect(page.getByRole("heading", { level: 1, name: "Password reset link", exact: true })).toBeVisible();
  await expect(page.locator("#subject")).toHaveValue("Password reset");
  await expect(page.locator("#buttonLabel")).toHaveValue("Reset password");
  await expect(page.locator("#btnReset")).toHaveCount(0);
});

test("an edit shows in the preview, reaches a test email and a sent reset, and Reset to default restores the built-in text", async ({
  page,
  browser,
  request,
  users,
}) => {
  const mark = uniqueIdentifier("mark");
  const subject = `Reset your {{app_name}} password ${mark}`;
  const label = "Choose a new password";
  const body = ["Hi {{name}},", "", `**${mark}**: choose a new password below.`, "", "{{button}}", "", "{{link}}", "", "It works for {{expiry}}."].join("\n");

  await page.goto(emailTemplateUrl("password_reset_link", "en"));
  const appName = await appNameFromEditor(page);
  const sentSubject = `Reset your ${appName} password ${mark}`;

  try {
    await page.locator("#subject").fill(subject);
    await page.locator("#buttonLabel").fill(label);
    await page.locator("#body").fill(body);

    // The preview follows the form before it's saved, with the sample values.
    await expect(page.locator("#previewSubject")).toHaveText(sentSubject);
    const text = page.locator("#previewText");
    await expect(text).toContainText("Hi Jane Doe,");
    await expect(text).toContainText(`${mark}: choose a new password below.`);
    await expect(text).toContainText("https://example.invalid/sample-link");
    await expect(text).toContainText("It works for 5 minutes.");
    const frame = page.frameLocator('iframe[name="emailTemplatePreviewFrame"]');
    await expect(frame.locator("strong", { hasText: mark })).toBeVisible();
    await expect(frame.getByRole("link", { name: label, exact: true })).toBeVisible();

    // Send test email sends the text in the form, not yet saved, as a recipient would get it.
    const to = `${uniqueIdentifier("t")}@example.com`;
    await page.locator("#testAddress").fill(to);
    await page.locator("#btnSendTest").click();
    await expect(page.locator("#sendTestStatus")).toContainText(`Test email sent to ${to}.`);
    const testMail = await waitForMail(request, to);
    expect(testMail.subject).toBe(sentSubject);
    expect(testMail.html).toContain(`<strong>${mark}</strong>`);
    expect(testMail.html).toContain(`>${label}</a>`);
    expect(testMail.text).toContain("Hi Jane Doe,");
    expect(testMail.text).toContain("https://example.invalid/sample-link");

    // Saved, it is the text every reset in English is sent with.
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(emailTemplateUrl("password_reset_link", "en"));
    await expect(page.getByText("Saved. This email is sent in this language with the text below.", { exact: true })).toBeVisible();
    await expect(page.locator("#subject")).toHaveValue(subject);
    await expect(page.locator("#emailTemplateLanguages").getByRole("link", { name: /^English/ })).toContainText("Edited");
    await expect(page.locator("#btnReset")).toBeVisible();

    const edited = await users.create({ emailVerified: true });
    await askForReset(browser, edited.email);
    const mail = await waitForMail(request, edited.email);
    expect(mail.subject).toBe(sentSubject);
    expect(mail.html).toContain(`<title>${sentSubject}</title>`);
    expect(mail.html).toContain(`<strong>${mark}</strong>`);
    expect(mail.html).toMatch(new RegExp(`data-email-button[\\s\\S]*?>${label}</a>`));
    expect(mail.text).toContain("Hi Playwright Tester,");
    expect(mail.text).toContain(`${mark}: choose a new password below.`);
    expect(mail.text).toContain(resetLink(mail));
    expect(mail.text).toContain("It works for 5 minutes.");
    expect(mail.text).not.toContain("You can reset your password by clicking the link below:");

    // The list tags the edited language.
    await page.goto(listUrl);
    const row = page.locator("tbody tr").filter({ has: page.getByRole("link", { name: "Password reset link", exact: true }) });
    await expect(row.locator(".tag")).toContainText("English");

    // Reset to default asks first, then the built-in text is back, in the form and in the next email.
    expect(await resetEmailTemplate(page, "password_reset_link", "en")).toBe(true);
    await expect(page.locator("#subject")).toHaveValue("Password reset");
    await expect(page.locator("#btnReset")).toHaveCount(0);

    const builtIn = await users.create({ emailVerified: true });
    await askForReset(browser, builtIn.email);
    const after = await waitForMail(request, builtIn.email);
    expect(after.subject).toBe("Password reset");
    expect(after.text).toContain("You can reset your password by clicking the link below:");
    expect(after.text).not.toContain(mark);
  } finally {
    await resetEmailTemplate(page, "password_reset_link", "en");
  }
});

test("a text breaking a rule is refused naming the placeholder, in the preview and on save, and nothing is saved", async ({ page }) => {
  leaveWithoutAsking(page);

  // A placeholder the email doesn't offer: the welcome email has no name to write.
  await page.goto(emailTemplateUrl("welcome", "en"));
  const builtInBody = await page.locator("#body").inputValue();
  const unoffered = "Hello {{name}},\n\n{{button}}";
  const unofferedRefusal = "This email does not offer {{name}}. It offers {{app_name}}, {{link}}, {{button}}.";
  await page.locator("#body").fill(unoffered);
  await expect(page.locator("#previewStatus")).toContainText(unofferedRefusal);
  await page.locator("#btnSave").click();
  await expect(page.locator("#emailTemplate-error")).toHaveText(unofferedRefusal);
  await expect(page.locator("#body")).toHaveAttribute("aria-invalid", "true");
  await expect(page.locator("#body")).toHaveValue(unoffered);
  await expect(page.locator("#btnReset")).toHaveCount(0);

  await page.goto(emailTemplateUrl("welcome", "en"));
  await expect(page.locator("#body")).toHaveValue(builtInBody);

  // A required placeholder left out: the password reset link can't do without its link, and the
  // button doesn't count as one.
  await page.goto(emailTemplateUrl("password_reset_link", "en"));
  const missing = "Hello {{name}},\n\n{{button}}\n\nIt works for {{expiry}}.";
  const missingRefusal =
    "The body must use {{link}}, which this email cannot do without. It offers {{app_name}}, {{name}}, {{link}}, {{button}}, {{expiry}}.";
  await page.locator("#body").fill(missing);
  await expect(page.locator("#previewStatus")).toContainText(missingRefusal);
  await page.locator("#btnSave").click();
  await expect(page.locator("#emailTemplate-error")).toHaveText(missingRefusal);
  await expect(page.locator("#body")).toHaveValue(missing);
  await expect(page.locator("#btnReset")).toHaveCount(0);
});
