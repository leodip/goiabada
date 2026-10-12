// Settings - Email - SMTP and Audit logs. The baseline sends through the environment's Mailpit
// (lib/settings.ts); what is mailed is tested in email.spec.ts. Runs alone, and every test puts the
// settings back.
import { signInToConsole } from "../../../lib/console-user";
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
    // Nothing refused was saved: still Mailpit.
    await page.goto(`${env.adminUrl}${email}`);
    await expect(page.locator('input[name="hostOrIP"]')).toHaveValue("mailpit");
  });
});

test("with SMTP off, the features that mail are withdrawn", async ({ page, browser, users }) => {
  const user = await users.create();
  await withSettingsRestored(page, email, async () => {
    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);

    await page.goto(`${env.adminUrl}${email}/send-test-email`);
    await expect(page.getByText("SMTP is currently")).toBeVisible();
    // The new user form sets the password, with no emailed link to choose.
    await page.goto(`${env.adminUrl}/admin/users/new`);
    await expect(page.locator("#setPasswordTypeEmail")).toHaveCount(0);
    // A user's email verification page is not offered.
    const own = await signInToConsole(browser, user);
    await expect(own.page.locator('a[href="/account/email-verification"]')).toHaveCount(0);
    expect((await own.page.goto(`${env.adminUrl}/account/email-verification`))?.status()).toBe(404);
    await own.context.close();
  });
});

test("a verification code sent after SMTP is turned off is refused on the page", async ({ page, browser, users }) => {
  const user = await users.create();
  await withSettingsRestored(page, email, async () => {
    // The user opens the page while email is on, so it draws the code form.
    const own = await signInToConsole(browser, user, "/account/email-verification");
    const code = own.page.locator('input[name="verificationCode"]');
    await expect(code).toBeVisible();

    await fillSettingsForm(page, { smtpEnabled: false });
    await saveSettings(page);

    // The auth server refuses it before it compares the code. The page now draws no code form, and
    // draws the refusal all the same: it used to draw it only inside that form, so it showed nothing.
    await code.fill("ABCD1234");
    await own.page.getByRole("button", { name: "Verify email" }).click();
    await expect(own.page.getByText("SMTP is not enabled")).toBeVisible();
    await expect(own.page).toHaveURL(`${env.adminUrl}/account/email-verification`);
    await expect(code).toHaveCount(0);
    await own.context.close();
  });
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
