// The user's own sessions, consents and picture.
import { cancelDialog, confirmDialog, rowWithCell } from "../../../lib/admin-console";
import { signInThroughClient } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { browserSignInClient } from "../../../lib/test-clients";

const picture = { name: "me.png", mimeType: "image/png", buffer: solidPng(300, 300, [90, 160, 60]) };

test("the user sees their sessions, the current one marked, and ends another", async ({ browser, users }) => {
  const user = await users.create();
  const other = await signInToConsole(browser, user);
  const own = await signInToConsole(browser, user, "/account/sessions");
  const rows = own.page.locator("table tbody tr");
  await expect(rows).toHaveCount(2);
  // The session of the device in use comes first.
  await expect(rows.first()).toContainText("This device");
  await expect(rows.filter({ hasText: "This device" })).toHaveCount(1);

  const otherRow = rows.filter({ hasNotText: "This device" });
  await otherRow.getByRole("button", { name: /^End session/ }).click();
  await confirmDialog(own.page, "including ones that keep working in the background, will need you to sign in again");
  // The button gives way to a tag, and the page says so.
  await expect(otherRow.getByText("Ended", { exact: true })).toBeVisible();
  await expect(own.page.locator("#sessions-status")).toHaveText("Session ended.");
  await own.page.reload();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("This device");

  // The other device is signed out of the auth server: its next sign-in asks for the password.
  await other.context.clearCookies({ domain: new URL(env.adminUrl).hostname });
  await other.page.goto(`${env.adminUrl}/account/profile`);
  await expect(other.page.locator("#password")).toBeVisible();
  await other.context.close();
  await own.context.close();
});

// The dialog says ending the current session signs out at once, so the page posts the sign-out
// rather than navigating to the console's GET /auth/logout, which would ask a second time (#411).
test("ending the current session signs the user out at once, with no second confirmation", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/sessions");
  const current = own.page.locator("table tbody tr").filter({ hasText: "This device" });
  await current.getByRole("button", { name: /^End session/ }).click();
  await confirmDialog(own.page, "It's the device you're using, so you'll be signed out.");

  // Through the auth server's end-session endpoint and back to the console's home page.
  await own.page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await own.page.goto(`${env.adminUrl}/account/profile`);
  await expect(own.page.locator("#password")).toBeVisible();
  await own.context.close();
});

test("cancelling the end of the current session leaves the user signed in", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/sessions");
  const current = own.page.locator("table tbody tr").filter({ hasText: "This device" });
  const end = current.getByRole("button", { name: /^End session/ });
  await end.click();
  await cancelDialog(own.page, "you'll be signed out");
  await expect(end).toBeEnabled();
  await expect(own.page.locator("#sessions-status")).toBeEmpty();
  await own.page.reload();
  await expect(own.page).toHaveURL(`${env.adminUrl}/account/sessions`);
  await expect(current).toHaveCount(1);
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
  // The client is named as the consent screen named it: with no display name shown, by its identifier.
  const row = rowWithCell(own.page, client.identifier);
  // Each scope in plain words, with the scope itself beneath.
  await expect(row).toContainText("Your email address, and whether it's verified");
  await expect(row.locator(".code-hint").filter({ hasText: /^email$/ })).toBeVisible();
  await expect(row.locator(".code-hint").filter({ hasText: /^openid$/ })).toBeVisible();

  const revoke = row.getByRole("button", { name: `Revoke ${client.identifier}`, exact: true });
  const question = `Revoke the consent you gave ${client.identifier}? It will have to ask you again before it can use your account.`;
  // Cancel leaves the consent as it was.
  await revoke.click();
  await cancelDialog(own.page, question);
  await expect(revoke).toBeEnabled();
  await expect(own.page.locator("#row-actions-status")).toBeEmpty();

  await revoke.click();
  await confirmDialog(own.page, question);
  // The button gives way to a tag, and the page says so.
  await expect(row.getByText("Revoked", { exact: true })).toBeVisible();
  await expect(own.page.locator("#row-actions-status")).toHaveText("Consent revoked.");
  await own.page.reload();
  await expect(own.page.getByText("You haven't given consent to any application.")).toBeVisible();
  await own.context.close();
});

test("the user uploads and deletes their picture", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/picture");
  const image = own.page.locator("#imagePreview img");
  const deleteButton = own.page.locator("#deleteImageBtn");
  const status = own.page.locator("#imageUploadStatus");
  const crop = own.page.locator("#cropDialog");
  await expect(deleteButton).toBeHidden();
  await expect(image).toHaveCount(0);

  await own.page.locator("#imageUploadInput").setInputFiles(picture);
  await expect(crop).toBeVisible();
  // Save picture is enabled once the cropper has drawn the image.
  await own.page.locator("#confirmCropBtn").click();
  await expect(status).toHaveText("Picture saved.");
  await expect(crop).toBeHidden();
  await expect(deleteButton).toBeVisible();
  await own.page.reload();
  await expect(image).toBeVisible();

  // Deleting asks first, and Cancel keeps the picture.
  await deleteButton.click();
  await cancelDialog(own.page, "Applications will stop showing it.");
  await expect(image).toBeVisible();
  await expect(status).toBeEmpty();

  await deleteButton.click();
  await confirmDialog(own.page, "Applications will stop showing it.");
  await expect(status).toHaveText("Picture deleted.");
  await expect(deleteButton).toBeHidden();
  await expect(image).toHaveCount(0);
  await own.context.close();
});

test("cancelling the crop saves nothing", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/picture");
  const crop = own.page.locator("#cropDialog");
  await own.page.locator("#imageUploadInput").setInputFiles(picture);
  await expect(crop).toBeVisible();
  await crop.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(crop).toBeHidden();
  await expect(own.page.locator("#uploadImageBtn")).toBeEnabled();
  await expect(own.page.locator("#imageUploadStatus")).toBeEmpty();
  await own.page.reload();
  await expect(own.page.locator("#imagePreview img")).toHaveCount(0);
  await expect(own.page.locator("#deleteImageBtn")).toBeHidden();
  await own.context.close();
});

test("a file that is no image, or over 3 MB, is refused, and no crop opens", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/picture");
  const input = own.page.locator("#imageUploadInput");
  const status = own.page.locator("#imageUploadStatus");
  // By its type,
  await input.setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("not a picture") });
  await expect(status).toHaveText("Choose a JPEG, PNG, GIF or WebP image.");
  // by its size,
  await input.setInputFiles({ name: "large.png", mimeType: "image/png", buffer: Buffer.alloc(3 * 1024 * 1024 + 1) });
  await expect(status).toHaveText("This file is larger than 3 MB. Choose a smaller one.");
  // and by its content, when its type says it is one.
  await input.setInputFiles({ name: "fake.png", mimeType: "image/png", buffer: Buffer.from("not a picture") });
  await expect(status).toHaveText("That file couldn't be read as an image. Choose another one.");
  await expect(own.page.locator("#cropDialog")).toBeHidden();
  await expect(own.page.locator("#uploadImageBtn")).toBeEnabled();
  await own.context.close();
});
