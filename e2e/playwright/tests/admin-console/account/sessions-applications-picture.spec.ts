// The user's own sessions, applications and picture.
import type { APIRequestContext, Browser } from "@playwright/test";
import { cancelDialog, confirmDialog, rowWithCell } from "../../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../../lib/browser-sign-in";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { basicAuth, expectTokenError, expectTokenResponse, postToken, type RawAnswer } from "../../../lib/rfc6749";
import { browserSignInClient } from "../../../lib/test-clients";

const picture = { name: "me.png", mimeType: "image/png", buffer: solidPng(300, 300, [90, 160, 60]) };

interface SignInClient {
  client: { identifier: string };
  secret: string;
}

// A refresh with the client's own credentials.
function refresh(request: APIRequestContext, { client, secret }: SignInClient, refreshToken: string): Promise<RawAnswer> {
  return postToken(request, { grant_type: "refresh_token", refresh_token: refreshToken }, {
    headers: { Authorization: basicAuth(client.identifier, secret) },
  });
}

// The refresh token of a sign-in to the client, through the authorization code flow in a browser of
// its own, which is closed again: the client holds its grant on another device.
async function refreshTokenOf(browser: Browser, request: APIRequestContext, { client, secret }: SignInClient,
  user: { email: string; password: string }, scope: string): Promise<string> {
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope });
  await signIn.context.close();
  const answer = await postToken(request, { grant_type: "authorization_code", code: signIn.code, code_verifier: signIn.codeVerifier, redirect_uri: testRedirectUri }, {
    headers: { Authorization: basicAuth(client.identifier, secret) },
  });
  expectTokenResponse(answer);
  expect(answer.body.refresh_token, "a refresh token was issued").toBeTruthy();
  return answer.body.refresh_token as string;
}

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

// The Applications page lists every client the user is connected to (#135 decisions 4, 5 and 7):
// one they gave consent to, one that never asked, and the console itself, which is tagged rather
// than offered a Disconnect. A disconnect ends the client's refresh token at once, and leaves the
// others as they were.
test("the user sees each application connected to their account, and disconnects them", async ({ page, browser, clients, request, users }) => {
  const user = await users.create();
  const consented = await browserSignInClient(page, clients, { consentRequired: true });
  const unasked = await browserSignInClient(page, clients);
  const consentedToken = await refreshTokenOf(browser, request, consented, user, "openid email");
  const unaskedToken = await refreshTokenOf(browser, request, unasked, user, "openid profile");

  const own = await signInToConsole(browser, user, "/account/applications");
  const status = own.page.locator("#row-actions-status");
  // Each client is named as the consent screen names it: with no display name shown, by its identifier.
  const consentedRow = rowWithCell(own.page, consented.client.identifier);
  // What the user allowed and what the client holds now, each under its own label, each scope in
  // plain words with the scope itself beneath.
  await expect(consentedRow).toContainText("You allowed");
  await expect(consentedRow).toContainText("It holds now");
  await expect(consentedRow).toContainText("Your email address, and whether it's verified");
  await expect(consentedRow.locator(".code-hint").filter({ hasText: /^email$/ })).toHaveCount(2);
  await expect(consentedRow).not.toContainText("Not asked");

  // A client with Consent required off was never asked, and still holds what it was given.
  const unaskedRow = rowWithCell(own.page, unasked.client.identifier);
  await expect(unaskedRow).toContainText("Not asked");
  await expect(unaskedRow).not.toContainText("You allowed");
  await expect(unaskedRow).toContainText("It holds now");
  await expect(unaskedRow.locator(".code-hint").filter({ hasText: /^profile$/ })).toBeVisible();

  // The console itself is tagged, and offers nothing to press.
  const current = own.page.locator("table tbody tr").filter({ hasText: "This application" });
  await expect(current).toHaveCount(1);
  await expect(current.getByRole("button")).toHaveCount(0);

  const disconnect = unaskedRow.getByRole("button", { name: `Disconnect ${unasked.client.identifier}`, exact: true });
  const question = `Disconnect ${unasked.client.identifier}? The access it was given will be revoked on every device and any approval you gave it removed, though some of that access can last until it expires. We'll try to tell it to sign you out. It can still ask you to sign in again.`;
  // Cancel leaves the client as it was.
  await disconnect.click();
  await cancelDialog(own.page, question);
  await expect(disconnect).toBeEnabled();
  await expect(status).toBeEmpty();
  // Still working, and rotated: the token it hands back is the one the client holds now.
  const unaskedRefreshed = await refresh(request, unasked, unaskedToken);
  expectTokenResponse(unaskedRefreshed);

  await disconnect.click();
  await confirmDialog(own.page, question);
  // The button gives way to a tag, and the page says so.
  await expect(unaskedRow.getByText("Disconnected", { exact: true })).toBeVisible();
  await expect(status).toHaveText("Application disconnected.");
  // Its refresh token is refused, and the other client's still works.
  expectTokenError(await refresh(request, unasked, unaskedRefreshed.body.refresh_token as string), "invalid_grant");
  const consentedRefreshed = await refresh(request, consented, consentedToken);
  expectTokenResponse(consentedRefreshed);

  await own.page.reload();
  await expect(rowWithCell(own.page, unasked.client.identifier)).toHaveCount(0);
  // The client with a consent goes the same way, its consent with it.
  await rowWithCell(own.page, consented.client.identifier)
    .getByRole("button", { name: `Disconnect ${consented.client.identifier}`, exact: true })
    .click();
  await confirmDialog(own.page, `Disconnect ${consented.client.identifier}?`);
  await expect(status).toHaveText("Application disconnected.");
  expectTokenError(await refresh(request, consented, consentedRefreshed.body.refresh_token as string), "invalid_grant");
  await own.page.reload();
  await expect(rowWithCell(own.page, consented.client.identifier)).toHaveCount(0);
  // The console is still listed, and the user is still signed in to it.
  await expect(own.page.locator("table tbody tr")).toHaveCount(1);
  await expect(own.page.locator("table tbody tr")).toContainText("This application");
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
