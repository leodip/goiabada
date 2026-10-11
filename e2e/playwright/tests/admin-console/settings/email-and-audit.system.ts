// Settings - Email - SMTP and Audit logs. There is no SMTP server in the e2e environment, so what is
// tested of email is what the console refuses. Runs alone, and every test puts the settings back.
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";

const email = "/admin/settings/email";

test("SMTP settings are refused when incomplete, out of range, or unreachable", async ({ page }) => {
  await withSettingsRestored(page, email, async () => {
    for (const { values, message } of [
      { values: { smtpEnabled: true, hostOrIP: "", port: "587", fromEmail: "noreply@example.com" }, message: "SMTP host is required." },
      { values: { smtpEnabled: true, hostOrIP: "smtp.example.com", port: "70000", fromEmail: "noreply@example.com" }, message: "SMTP port must be between 1 and 65535." },
      { values: { smtpEnabled: true, hostOrIP: "smtp.example.com", port: "587", fromEmail: "" }, message: "SMTP from email is required." },
      // Nothing listens there: the auth server tries to connect before it saves.
      { values: { smtpEnabled: true, hostOrIP: "127.0.0.1", port: "2", fromEmail: "noreply@example.com" }, message: /connect|reach|refused/i },
    ]) {
      await page.goto(`${env.adminUrl}${email}`);
      await fillSettingsForm(page, values);
      await page.locator("#btnSave").click();
      await expect(page.getByText(message).first()).toBeVisible();
    }
    await page.goto(`${env.adminUrl}${email}`);
    await expect(page.locator('input[name="smtpEnabled"]')).not.toBeChecked();
  });
});

test("with SMTP off, the send test email page says so", async ({ page }) => {
  await page.goto(`${env.adminUrl}${email}/send-test-email`);
  await expect(page.getByText("SMTP is currently")).toBeVisible();
  await expect(page.getByText("disabled", { exact: true })).toBeVisible();
});

test("audit log retention is saved, and refused when out of range", async ({ page }) => {
  const path = "/admin/settings/audit-logs";
  await withSettingsRestored(page, path, async () => {
    for (const { value, message } of [
      { value: "-1", message: "Audit log retention days cannot be negative. Use 0 for infinite retention." },
      { value: "3651", message: "Audit log retention days cannot exceed 3650 days (10 years)." },
      { value: "abc", message: "Audit log retention days must be a valid number." },
    ]) {
      await page.goto(`${env.adminUrl}${path}`);
      await fillSettingsForm(page, { auditLogRetentionDays: value });
      await page.locator("#btnSave").click();
      await expect(page.getByText(message)).toBeVisible();
    }
    await page.goto(`${env.adminUrl}${path}`);
    await fillSettingsForm(page, { auditLogRetentionDays: "30" });
    await saveSettings(page);
    await expect(page.locator('input[name="auditLogRetentionDays"]')).toHaveValue("30");
  });
});

test("with database persistence off, new audit events are not listed in the viewer", async ({ page, groups }) => {
  await withSettingsRestored(page, "/admin/settings/audit-logs", async () => {
    await fillSettingsForm(page, { auditLogsInDatabaseEnabled: false });
    await saveSettings(page);
    const group = await groups.create();
    await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?auditEvent=created_group`);
    await expect(page.locator("#auditLogsTable")).not.toContainText(group.identifier);
  });
});
