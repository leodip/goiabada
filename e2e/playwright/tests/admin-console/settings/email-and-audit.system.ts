// Settings - Email and Audit logging. The baseline sends through the environment's Mailpit
// (lib/settings.ts); what is mailed is tested in email.spec.ts. Runs alone, and every test puts the
// settings back.
import type { Page } from "@playwright/test";
import { cancelDialog, expectRefusal } from "../../../lib/admin-console";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, readSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";
import { auditRows } from "../../../lib/sessions";

const email = "/admin/settings/email";
const auditLogs = "/admin/settings/audit-logs";

test("SMTP settings are refused when incomplete, out of range, or unreachable", async ({ page }) => {
  await withSettingsRestored(page, email, async () => {
    for (const { values, field, message } of [
      { values: { smtpEnabled: true, hostOrIP: "", port: "587", fromEmail: "noreply@example.com" }, field: "hostOrIP", message: "SMTP host is required." },
      { values: { smtpEnabled: true, hostOrIP: "smtp.example.com", port: "70000", fromEmail: "noreply@example.com" }, field: "port", message: "SMTP port must be between 1 and 65535." },
      // Not a whole number: refused by the console itself.
      { values: { smtpEnabled: true, hostOrIP: "smtp.example.com", port: "abc", fromEmail: "noreply@example.com" }, field: "port", message: "Enter the port as a whole number." },
      { values: { smtpEnabled: true, hostOrIP: "smtp.example.com", port: "587", fromEmail: "" }, field: "fromEmail", message: "Enter the sender email." },
      // Nothing listens there: the auth server tries to connect before it saves.
      { values: { smtpEnabled: true, hostOrIP: "127.0.0.1", port: "2", fromEmail: "noreply@example.com" }, field: "hostOrIP", message: /Unable to connect to the SMTP server/ },
    ]) {
      await page.goto(`${env.adminUrl}${email}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expectRefusal(page, "email-error", field, message);
    }
    // Nothing refused was saved: still Mailpit.
    await page.goto(`${env.adminUrl}${email}`);
    await expect(page.locator("#hostOrIP")).toHaveValue("mailpit");
  });
});

test("turning email off hides the server's settings and asks first, and Cancel keeps email on", async ({ page }) => {
  const before = await readSettingsForm(page, email);
  expect(before.smtpEnabled).toBe(true);
  const sections = page.locator("[data-smtp-section]");
  await expect(sections.first()).toBeVisible();

  await page.locator("#smtpEnabled").uncheck();
  for (const section of await sections.all()) await expect(section).toBeHidden();
  await page.locator("#btnSave").click();
  await cancelDialog(page, "Turning email off will clear every SMTP setting");

  expect(await readSettingsForm(page, email)).toEqual(before);
});

test("with SMTP off, the features that mail are withdrawn", async ({ page, browser, users }) => {
  const user = await users.create();
  await withSettingsRestored(page, email, async () => {
    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);

    // The test email says email is off, and links to the configuration.
    await page.goto(`${env.adminUrl}${email}/send-test-email`);
    await expect(page.getByText("Email is off. Turn it on and set up the SMTP server to send a test email:")).toBeVisible();
    await expect(page.locator(".notice").getByRole("link", { name: "Configuration", exact: true })).toHaveAttribute("href", email);
    await expect(page.locator("#btnSend")).toHaveCount(0);
    // The new user form sets the password, with no emailed link to choose.
    await page.goto(`${env.adminUrl}/admin/users/new`);
    await expect(page.locator("#setPasswordTypeEmail")).toHaveCount(0);
    await expect(page.locator("#password")).toBeVisible();
    // A user's email verification page is not offered.
    const own = await signInToConsole(browser, user);
    await expect(own.page.locator('a[href="/account/email-verification"]')).toHaveCount(0);
    expect((await own.page.goto(`${env.adminUrl}/account/email-verification`))?.status()).toBe(404);
    await expect(own.page.getByRole("heading", { name: "Page not found" })).toBeVisible();
    await own.context.close();
  });
});

test("a verification code sent after SMTP is turned off is refused on the page", async ({ page, browser, users }) => {
  const user = await users.create();
  await withSettingsRestored(page, email, async () => {
    // The user opens the page while email is on, so it draws the code form.
    const own = await signInToConsole(browser, user, "/account/email-verification");
    const code = own.page.locator("#verificationCode");
    await expect(code).toBeVisible();

    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);

    // The auth server refuses it before it compares the code. The page now draws no code form, and
    // draws the refusal all the same, with the reason the address can't be verified.
    await code.fill("ABCD1234");
    await own.page.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(own.page.locator("#verification-error")).toHaveText("SMTP is not enabled");
    await expect(own.page).toHaveURL(`${env.adminUrl}/account/email-verification`);
    await expect(code).toHaveCount(0);
    await expect(own.page.getByText("This server can't send email, so your address can't be verified here.")).toBeVisible();
    await own.context.close();
  });
});

test("audit log retention is saved, and refused when out of range", async ({ page }) => {
  await withSettingsRestored(page, auditLogs, async () => {
    for (const { value, message } of [
      { value: "-1", message: "The retention can't be negative. Use 0 to keep stored events forever." },
      { value: "3651", message: "The retention can't be more than 3650 days (10 years)." },
      // Not a whole number: refused by the console itself.
      { value: "abc", message: "Enter the retention as a whole number of days." },
    ]) {
      await page.goto(`${env.adminUrl}${auditLogs}`);
      await fillSettingsForm(page, { auditLogRetentionDays: value });
      await page.locator("#btnSave").click();
      await expectRefusal(page, "audit-logs-error", "auditLogRetentionDays", message);
    }
    await page.goto(`${env.adminUrl}${auditLogs}`);
    await fillSettingsForm(page, { auditLogRetentionDays: "30" });
    await saveSettings(page);
    await expect(page.locator("#auditLogRetentionDays")).toHaveValue("30");
  });
});

test("with database persistence off, new audit events are not listed in the viewer, which says so", async ({ page, groups }) => {
  await withSettingsRestored(page, auditLogs, async () => {
    await fillSettingsForm(page, { auditLogsInDatabaseEnabled: false });
    await saveSettings(page);
    const group = await groups.create();
    await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?auditEvent=created_group`);
    await expect(page.getByText("The auth server isn't storing audit events in the database, so no new ones appear here.")).toBeVisible();
    await expect(page.locator(".notice").getByRole("link", { name: "Audit logging", exact: true })).toHaveAttribute("href", auditLogs);
    await expect(auditRows(page, { group_identifier: group.identifier })).toHaveCount(0);
  });
});
