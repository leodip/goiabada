// The email templates under Admin - Email (#818), read from the environment's Mailpit. The tab is
// reached from Branding and lists the emails. An edit of the password reset link's English text
// shows in the editor's preview, reaches a test email sent from the editor before it is saved, and
// once saved reaches the reset a user asks for; Reset to default brings the built-in text back to
// the next one. A text breaking a rule is refused naming the placeholder, in the preview and on
// save, and nothing is saved; each other rule is refused at the field it is about. An edit in German
// reaches a user who reads German, and every other language keeps the built-in text; an edited
// email is still drawn in its brand (#817); the editor's language tabs, an edited one marked, fit a
// narrow page (#902); and the audit log lists each save, reset and test email. An edit is global, so
// this runs alone, and resets what it saved.
import type { Browser, Page } from "@playwright/test";
import { setClientBrand, userUrl } from "../../lib/admin-console";
import { mailLook, plumDarkMail, withBrand } from "../../lib/brands";
import { openSignIn } from "../../lib/browser-sign-in";
import { emailTemplatesPath, emailTemplateUrl, resetEmailTemplate } from "../../lib/email-templates";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, type Mail, waitForMail } from "../../lib/mailpit";
import { expectNewestAuditEvent } from "../../lib/sessions";
import { browserSignInClient } from "../../lib/test-clients";
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

// Each other rule of the editor, one at a time, refused at the field it is about, which is marked and
// takes the focus, the form keeping what was typed and nothing saved.
const fieldRefusals: { name: string; email: string; field: "subject" | "buttonLabel" | "body"; value: string; says: string | RegExp }[] = [
  { name: "an empty subject", email: "password_reset_link", field: "subject", value: "", says: "Subject is required." },
  {
    name: "the button in the subject",
    email: "password_reset_link",
    field: "subject",
    value: "Press {{button}}",
    says: /^\s*The subject cannot use \{\{button\}\}\. In the subject, this email offers /,
  },
  { name: "an empty button label", email: "password_reset_link", field: "buttonLabel", value: "", says: "Button label is required." },
  {
    name: "the button inside a sentence",
    email: "password_reset_link",
    field: "body",
    value: "Hello {{name}}, press {{button}} now.\n\n{{link}}",
    says: "Put {{button}} on a line of its own.",
  },
  {
    name: "a placeholder inside a link's address",
    email: "password_reset_link",
    field: "body",
    value: "Read [this](https://example.com/{{name}}).\n\n{{link}}",
    says: "A link's address can hold a placeholder only as {{link}} on its own, the whole address. This one holds {{name}}.",
  },
  { name: "a body with nothing to read but the button", email: "welcome", field: "body", value: "{{button}}", says: "The body needs something to read besides the button." },
  {
    name: "the verification code left out",
    email: "verification_code",
    field: "body",
    value: "Hello {{name}}, here is no code.",
    says: /^\s*The body must use \{\{code\}\}, which this email cannot do without\. It offers /,
  },
];

test("each other rule is refused at the field it is about, and nothing is saved", async ({ page }) => {
  leaveWithoutAsking(page);
  for (const refusal of fieldRefusals) {
    await test.step(refusal.name, async () => {
      await page.goto(emailTemplateUrl(refusal.email, "en"));
      const field = page.locator(`#${refusal.field}`);
      await field.fill(refusal.value);
      await page.locator("#btnSave").click();
      await expect(page.locator("#emailTemplate-error")).toHaveText(refusal.says);
      await expect(field).toHaveAttribute("aria-invalid", "true");
      await expect(field).toHaveAttribute("aria-describedby", /^emailTemplate-error /);
      await expect(field).toBeFocused();
      await expect(field).toHaveValue(refusal.value);
      await expect(page.locator("#btnReset"), "nothing was saved").toHaveCount(0);
    });
  }
});

// Sets a user's Page language on their Profile tab, the language their emails are written in.
async function setPageLanguage(page: Page, userId: number, language: string) {
  await page.goto(userUrl(userId, "profile"));
  await page.getByLabel("Page language", { exact: true }).selectOption(language);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Profile saved.")).toBeVisible();
}

test("an edit in German reaches a user who reads German, and a user who reads English still gets the built-in text", async ({
  page,
  browser,
  request,
  users,
}) => {
  const mark = uniqueIdentifier("mark");
  const german = await users.create({ emailVerified: true });
  const english = await users.create({ emailVerified: true });
  await setPageLanguage(page, german.id, "de");

  try {
    await page.goto(emailTemplateUrl("password_reset_link", "de"));
    await page.locator("#subject").fill(`Passwort zurücksetzen ${mark}`);
    await page.locator("#body").fill(`Hallo {{name}}, ${mark}.\n\n{{button}}\n\n{{link}}`);
    await page.locator("#btnSave").click();
    await expect(page.locator("#subject")).toHaveValue(`Passwort zurücksetzen ${mark}`);
    await expect(page.locator("#emailTemplateLanguages").locator('a[href$="/password_reset_link/de"]')).toContainText("Edited");
    await expect(page.locator("#emailTemplateLanguages").locator('a[href$="/password_reset_link/en"] .tag')).toHaveCount(0);

    await askForReset(browser, german.email);
    const inGerman = await waitForMail(request, german.email);
    expect(inGerman.subject).toBe(`Passwort zurücksetzen ${mark}`);
    expect(inGerman.html).toContain(`<html lang="de">`);
    expect(inGerman.text).toContain(`Hallo Playwright Tester, ${mark}.`);

    await askForReset(browser, english.email);
    const inEnglish = await waitForMail(request, english.email);
    expect(inEnglish.subject).toBe("Password reset");
    expect(inEnglish.text).toContain("You can reset your password by clicking the link below:");
    expect(inEnglish.text).not.toContain(mark);
  } finally {
    await resetEmailTemplate(page, "password_reset_link", "de");
  }
});

test("an edited email is still drawn in the brand of the sign-in it was asked from", async ({ page, browser, request, clients, users }) => {
  const mark = uniqueIdentifier("mark");
  const { client } = await browserSignInClient(page, clients);
  const user = await users.create({ emailVerified: true });

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    await setClientBrand(page, client.id, brand);
    try {
      await page.goto(emailTemplateUrl("password_reset_link", "en"));
      await page.locator("#body").fill(`Hi {{name}}, **${mark}**.\n\n{{button}}\n\n{{link}}`);
      await page.locator("#btnSave").click();
      await expect(page.getByText("Saved. This email is sent in this language with the text below.", { exact: true })).toBeVisible();

      const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      await signIn.page.getByRole("link", { name: "Forgot your password?" }).click();
      await signIn.page.locator("#email").fill(user.email);
      await signIn.page.getByRole("button", { name: "Send reset link", exact: true }).click();
      await expect(signIn.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
      await signIn.context.close();

      const mail = await waitForMail(request, user.email);
      expect(mail.html).toMatch(new RegExp(`<strong[^>]*>${mark}</strong>`));
      expect(mailLook(mail.html)).toMatchObject({ canvas: plumDarkMail.canvas, colorScheme: "dark" });
      expect(mail.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${plumDarkMail.brand}"`));
    } finally {
      await resetEmailTemplate(page, "password_reset_link", "en");
    }
  });
});

// The editor's language tabs are labelled with each language's own name beside its English name,
// which no catalog can shorten, and an edited language's tab adds its marker. Once the bar has
// wrapped into pills, a pill's text breaks inside it, so every tab fits a narrow page in any console
// language (#902): a 320 px phone, and 305 px, a 320 px desktop window less a classic scrollbar,
// where the Portuguese (Brazil) pill, the widest, used to end at 308 px. The edit is of that
// language, so the widest tab carries the marker.
const narrowWidths = [
  { name: "a 320 px phone", width: 320 },
  { name: "a 305 px usable width", width: 305 },
];
const editedMarkers = [
  { tag: "en", marker: "Edited" },
  { tag: "id", marker: "Diubah" },
  { tag: "ru", marker: "Изменен" },
  { tag: "ja", marker: "編集済み" },
];

// Opens the editor in the console language at the usable width, which a classic scrollbar, where
// the browser draws one, would narrow, and answers each language tab's overflow: how far it, or its
// marker, reaches past the page or its text past the tab. The page does not scroll sideways.
async function languageTabsAt(page: Page, consoleLanguage: string, width: number) {
  await page.setViewportSize({ width, height: 740 });
  await page.goto(`${emailTemplateUrl("password_reset_link", "en")}?ui_locales=${consoleLanguage}`);
  await expect(page.locator("html")).toHaveAttribute("lang", consoleLanguage);
  const scrollbar = await page.evaluate(() => window.innerWidth - document.documentElement.clientWidth);
  if (scrollbar > 0) await page.setViewportSize({ width: width + scrollbar, height: 740 });
  const bar = page.locator("#emailTemplateLanguages");
  await expect(bar, "the tabs have wrapped into pills").toHaveAttribute("data-wrapped", "");
  // Let a resize's re-measure of the bar settle.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  const layout = await page.evaluate(() => ({
    usable: document.documentElement.clientWidth,
    sidewaysScroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect(layout.usable).toBe(width);
  expect(layout.sidewaysScroll, "the page scrolls sideways").toBe(0);
  return bar.locator("a.tab-item").evaluateAll((tabs) =>
    tabs.map((tab) => {
      const usable = document.documentElement.clientWidth;
      const box = tab.getBoundingClientRect();
      const marker = tab.querySelector(".tag");
      const markerBox = marker?.getBoundingClientRect();
      return {
        href: tab.getAttribute("href") ?? "",
        marker: marker?.textContent?.trim() ?? "",
        past: Math.max(0, -box.left, box.right - usable, tab.scrollWidth - tab.clientWidth, markerBox ? Math.max(box.left - markerBox.left, markerBox.right - box.right) : 0),
      };
    }),
  );
}

test("the editor's language tabs, with and without a marker, fit a 320 px phone and a 305 px usable width in English, Indonesian, Russian and Japanese", async ({ page }) => {
  leaveWithoutAsking(page);
  const edited = "/admin/settings/email/templates/password_reset_link/pt-BR";
  const check = async (marked: boolean) => {
    for (const { name, width } of narrowWidths) {
      for (const { tag, marker } of editedMarkers) {
        await test.step(`${marked ? "an edited" : "no"} language, ${name}, in ${tag}`, async () => {
          const tabs = await languageTabsAt(page, tag, width);
          expect(tabs.map((tab) => tab.href.split("/").pop())).toEqual(expect.arrayContaining(["en", "pt-BR", "id", "ru", "ja"]));
          expect(tabs.find((tab) => tab.href === edited)?.marker).toBe(marked ? marker : "");
          expect(tabs.filter((tab) => tab.past > 0.5)).toEqual([]);
        });
      }
    }
  };

  await check(false);
  try {
    await page.goto(emailTemplateUrl("password_reset_link", "pt-BR"));
    await page.locator("#subject").fill(`Redefinição de senha ${uniqueIdentifier("mark")}`);
    await page.locator("#btnSave").click();
    await expect(page.locator("#btnReset")).toBeVisible();
    await check(true);
  } finally {
    await resetEmailTemplate(page, "password_reset_link", "pt-BR");
  }
});

test("a saved edit, its reset and a test email are each listed in the audit log", async ({ page }) => {
  leaveWithoutAsking(page);
  const to = `${uniqueIdentifier("t")}@example.com`;
  const named = { email_template: "account_deleted", language: "it" };
  try {
    await page.goto(emailTemplateUrl("account_deleted", "it"));
    await page.locator("#subject").fill(`Account eliminato ${uniqueIdentifier("mark")}`);
    await page.locator("#btnSave").click();
    await expect(page.locator("#btnReset")).toBeVisible();
    await expectNewestAuditEvent(page, "updated_email_template", named);

    await page.goto(emailTemplateUrl("account_deleted", "it"));
    await page.locator("#testAddress").fill(to);
    await page.locator("#btnSendTest").click();
    await expect(page.locator("#sendTestStatus")).toContainText(to);
    await expectNewestAuditEvent(page, "sent_test_email", named);
  } finally {
    await resetEmailTemplate(page, "account_deleted", "it");
  }
  await expectNewestAuditEvent(page, "reset_email_template", named);
});
