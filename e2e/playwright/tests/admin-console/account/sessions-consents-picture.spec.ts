// The user's own sessions, consents and picture.
import { signInThroughClient } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { browserSignInClient } from "../../../lib/test-clients";

test("the user sees their sessions, the current one marked, and ends another", async ({ browser, users }) => {
  const user = await users.create();
  const other = await signInToConsole(browser, user);
  const own = await signInToConsole(browser, user, "/account/sessions");
  const rows = own.page.locator("table tbody tr");
  await expect(rows).toHaveCount(2);
  const current = rows.filter({ hasText: "Current session" });
  await expect(current).toHaveCount(1);

  await rows.filter({ hasNotText: "Current session" }).getByRole("button", { name: "End session" }).click();
  await own.page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("Current session");

  // The other device is signed out of the auth server: its next sign-in asks for the password.
  await other.context.clearCookies({ domain: new URL(env.adminUrl).hostname });
  await other.page.goto(`${env.adminUrl}/account/profile`);
  await expect(other.page.locator('input[name="password"]')).toBeVisible();
  await other.context.close();
  await own.context.close();
});

test("the user sees the consent they gave a client, and revokes it", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const signIn = await signInThroughClient(browser, {
    clientId: client.identifier,
    email: user.email,
    password: user.password,
    scope: "openid email",
  });
  await signIn.context.close();

  const own = await signInToConsole(browser, user, "/account/manage-consents");
  const row = own.page.getByRole("row").filter({ hasText: client.identifier });
  await expect(row).toContainText("openid email");
  await row.getByRole("button", { name: "Revoke" }).click();
  await own.page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(row.getByText("Removed")).toBeVisible();
  await own.page.reload();
  await expect(own.page.getByText("You haven't granted any consents")).toBeVisible();
  await own.context.close();
});

test("the user uploads and deletes their picture", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/picture");
  await expect(own.page.locator("#deleteImageBtn")).toBeHidden();
  await own.page.locator("#imageUploadInput").setInputFiles({ name: "me.png", mimeType: "image/png", buffer: solidPng(300, 300, [90, 160, 60]) });
  await own.page.locator("#confirmCropBtn").click();
  await expect(own.page.locator("#deleteImageBtn")).toBeVisible();
  await own.page.reload();
  await expect(own.page.locator("#imagePreview")).toBeVisible();

  own.page.once("dialog", (dialog) => dialog.accept());
  await own.page.locator("#deleteImageBtn").click();
  await expect(own.page.locator("#deleteImageBtn")).toBeHidden();
  await own.context.close();
});
