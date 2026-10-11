import { addGroupMember, groupUrl, rowWithCell, userUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { passwordToken, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

test("a picture is uploaded, reaches the picture claim, and is deleted", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "picture"));
  await expect(page.locator("#deleteImageBtn")).toBeHidden();

  await page.locator("#imageUploadInput").setInputFiles({
    name: "me.png",
    mimeType: "image/png",
    buffer: solidPng(600, 600, [30, 120, 200]),
  });
  await expect(page.locator("#cropModal")).toBeVisible();
  await page.locator("#confirmCropBtn").click();
  await expect(page.locator("#imagePreview")).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeVisible();

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(typeof id.picture).toBe("string");
  const picture = await request.get(id.picture as string);
  expect(picture.status()).toBe(200);
  expect(picture.headers()["content-type"]).toMatch(/^image\//);

  await page.goto(userUrl(user.id, "picture"));
  page.once("dialog", (dialog) => dialog.accept());
  await page.locator("#deleteImageBtn").click();
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
  const after = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(after.id.picture).toBeUndefined();
});

test("a file that is not an image is refused", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "picture"));
  await page.locator("#imageUploadInput").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("hello") });
  await expect(page.locator("#imageUploadError")).toBeVisible();
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

  await page.goto(userUrl(user.id, "delete"));
  await expect(rowWithCell(page, "Email").getByRole("cell").nth(1)).toHaveText(user.email);
  await expect(page.getByRole("main")).toContainText(group.identifier);
  await page.getByRole("button", { name: "Delete user" }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.adminUrl}/admin/users/?(\\?|$)`));
  user.markDeleted();

  await page.goto(`${env.adminUrl}/admin/users?query=${user.email.split("@")[0]}`);
  await expect(page.getByText("Could not find any user.")).toBeVisible();
  const response = await page.goto(userUrl(user.id, "details"));
  expect(response?.status()).toBe(404);
  await page.goto(groupUrl(group.id, "members"));
  await expect(page.getByText("No users assigned to group.")).toBeVisible();
  const answer = await passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect(answer.body.error).toBe("invalid_grant");
});
