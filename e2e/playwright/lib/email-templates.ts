// The email templates under Admin - Email (#818). An edit is global, every email in its language
// is sent with it, so a test that saves one lives in a *.system.ts file and resets it afterwards,
// pass or fail; the setup step resets any a run that crashed left (restoreBaselineEmailTemplates).
import { expect, type Page } from "@playwright/test";
import { confirmDialog } from "./admin-console";
import { env } from "./environment";

export const emailTemplatesPath = "/admin/settings/email/templates";

// The editor of one email in one language, such as password_reset_link in en.
export function emailTemplateUrl(email: string, language: string): string {
  return `${env.adminUrl}${emailTemplatesPath}/${email}/${language}`;
}

// Resets the email's edit in the language to the built-in text, through the editor's Reset to default
// and its question, and answers whether there was an edit to reset. An editor holding unsaved text
// asks before it is left, which is answered yes.
export async function resetEmailTemplate(page: Page, email: string, language: string): Promise<boolean> {
  const leave = (dialog: { type(): string; accept(): Promise<void> }) => {
    if (dialog.type() === "beforeunload") void dialog.accept();
  };
  page.on("dialog", leave);
  try {
    await page.goto(emailTemplateUrl(email, language));
  } finally {
    page.off("dialog", leave);
  }
  const reset = page.locator("#btnReset");
  if ((await reset.count()) === 0) return false;
  await reset.click();
  await confirmDialog(page, "Reset to the built-in text?");
  await expect(page.getByText("The edit was deleted. This email is sent in this language with the built-in text.", { exact: true })).toBeVisible();
  return true;
}

// Every run starts with no email template edited: each email and language the list or an editor
// marks as edited, or as needing attention, is reset. Answers what it had to reset.
export async function restoreBaselineEmailTemplates(page: Page): Promise<string[]> {
  await page.goto(`${env.adminUrl}${emailTemplatesPath}`);
  const edited = await page
    .locator("tbody tr")
    .filter({ has: page.locator(".tag") })
    .locator("td:first-child a")
    .evaluateAll((links) => links.map((link) => (link.getAttribute("href") ?? "").split("/").pop() ?? ""));
  const drifted: string[] = [];
  for (const email of edited) {
    await page.goto(`${env.adminUrl}${emailTemplatesPath}/${email}/en`);
    const languages = await page
      .locator("#emailTemplateLanguages a")
      .filter({ has: page.locator(".tag") })
      .evaluateAll((links) => links.map((link) => (link.getAttribute("href") ?? "").split("/").pop() ?? ""));
    for (const language of languages) {
      if (await resetEmailTemplate(page, email, language)) drifted.push(`${emailTemplatesPath}: ${email} in ${language}`);
    }
  }
  return drifted;
}
