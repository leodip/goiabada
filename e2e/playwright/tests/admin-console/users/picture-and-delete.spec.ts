import { addGroupMember, cancelDialog, confirmDialog, detail, groupUrl, rowWithCell, userUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { passwordToken, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

const picture = { name: "me.png", mimeType: "image/png", buffer: solidPng(600, 600, [30, 120, 200]) };
const deleteQuestion = "Clients will stop receiving it in the picture claim.";

test("a picture is uploaded, reaches the picture claim, and is deleted", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "picture"));
  await expect(page.locator("#deleteImageBtn")).toBeHidden();

  await page.locator("#imageUploadInput").setInputFiles(picture);
  await expect(page.locator("#cropDialog")).toBeVisible();
  // Enabled once the image is drawn, which the click waits for.
  await page.locator("#confirmCropBtn").click();
  await expect(page.locator("#imageUploadStatus")).toContainText("Picture saved.");
  await expect(page.locator("#imagePreview img")).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeVisible();

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(typeof id.picture).toBe("string");
  const response = await request.get(id.picture as string);
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toMatch(/^image\//);

  // Deleting asks first.
  await page.goto(userUrl(user.id, "picture"));
  await page.locator("#deleteImageBtn").click();
  await confirmDialog(page, deleteQuestion);
  await expect(page.locator("#imageUploadStatus")).toContainText("Picture deleted.");
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
  const after = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(after.id.picture).toBeUndefined();
});

test("Cancel in the crop dialog saves nothing, and Cancel on the deletion keeps the picture", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "picture"));
  await page.locator("#imageUploadInput").setInputFiles(picture);
  await expect(page.locator("#cropDialog")).toBeVisible();
  await page.locator("#cancelCropBtn").click();
  await expect(page.locator("#cropDialog")).toBeHidden();
  await page.reload();
  await expect(page.locator("#imagePreview img")).toHaveCount(0);
  await expect(page.locator("#deleteImageBtn")).toBeHidden();

  await page.locator("#imageUploadInput").setInputFiles(picture);
  await page.locator("#confirmCropBtn").click();
  await expect(page.locator("#imageUploadStatus")).toContainText("Picture saved.");
  await page.locator("#deleteImageBtn").click();
  await cancelDialog(page, deleteQuestion);
  await page.reload();
  await expect(page.locator("#imagePreview img")).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeVisible();
});

test("a file that is not an image is refused", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "picture"));
  await page.locator("#imageUploadInput").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("hello") });
  // Said in the status region, with no crop to make.
  await expect(page.locator("#imageUploadStatus .notice-danger")).toContainText("Choose a JPEG, PNG, GIF or WebP image.");
  await expect(page.locator("#cropDialog")).toBeHidden();
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
});

test("deleting a user shows what goes with them, and they can no longer sign in", async ({
  page,
  request,
  clients,
  groups,
  users,
}) => {
  const user = await users.create();
  const group = await groups.create();
  await addGroupMember(page, group.id, user.email);
  const { client, secret } = await passwordGrantClient(page, clients);

  // The list's Delete link for the user.
  await page.goto(`${env.adminUrl}/admin/users?query=${user.email.split("@")[0]}`);
  await rowWithCell(page, user.email).getByRole("link", { name: `Delete ${user.email}`, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/delete`));
  await expect(detail(page, "Email")).toHaveText(user.email);
  await expect(detail(page, "Groups")).toContainText(group.identifier);
  // The email is compared without regard to case.
  await page.getByLabel("To confirm, type the user's email").fill(user.email.toUpperCase());
  await page.getByRole("button", { name: "Delete user" }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`));
  user.markDeleted();

  await page.goto(`${env.adminUrl}/admin/users?query=${user.email.split("@")[0]}`);
  await expect(page.getByText("No users found.")).toBeVisible();
  const response = await page.goto(userUrl(user.id, "details"));
  expect(response?.status()).toBe(404);
  await page.goto(groupUrl(group.id, "members"));
  await expect(page.getByText("No one is in this group yet.")).toBeVisible();
  const answer = await passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect(answer.body.error).toBe("invalid_grant");
});

for (const { name, typed, message } of [
  { name: "no email", typed: "", message: "Type the user's email to confirm." },
  { name: "another email", typed: "someone-else@example.com", message: "That isn't this user's email. Type it as shown above." },
]) {
  test(`a delete with ${name} typed is refused, and the user stays`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "delete"));
    await page.locator("#email").fill(typed);
    await page.locator("#btnDelete").click();
    await expect(page.locator("#delete-error")).toContainText(message);
    await expect(page.locator("#email")).toHaveAttribute("aria-invalid", "true");
    const response = await page.goto(userUrl(user.id, "details"));
    expect(response?.status()).toBe(200);
  });
}
