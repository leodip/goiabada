import { cancelDialog, clientUrl, confirmDialog } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";

const logoFile = { name: "logo.png", mimeType: "image/png", buffer: solidPng(128, 128, [200, 40, 90]) };

test("a logo is uploaded, shown, and deleted, and a cancelled crop or delete changes nothing", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "logo"));
  const logo = page.locator("#imagePreview img");
  const crop = page.locator("#cropDialog");
  await expect(logo).toHaveCount(0);
  await expect(page.locator("#deleteImageBtn")).toBeHidden();

  // A crop cancelled sends nothing.
  await page.locator("#imageUploadInput").setInputFiles(logoFile);
  await expect(crop).toBeVisible();
  await page.locator("#cancelCropBtn").click();
  await expect(crop).toBeHidden();
  await expect(logo).toHaveCount(0);

  await page.locator("#imageUploadInput").setInputFiles(logoFile);
  await expect(crop).toBeVisible();
  // Enabled once the image is drawn, which the click waits for.
  await page.getByRole("button", { name: "Save logo" }).click();
  await expect(crop).toBeHidden();
  await expect(page.locator("#imageUploadStatus")).toContainText("Logo saved.");
  await expect(logo).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeVisible();

  // Still there after a reload, served by the auth server.
  await page.reload();
  await expect(logo).toBeVisible();
  const src = await logo.getAttribute("src");
  expect(src).toBeTruthy();
  const image = await page.request.get(new URL(src!, page.url()).toString());
  expect(image.status()).toBe(200);
  expect(image.headers()["content-type"]).toMatch(/^image\//);

  // The delete asks first; Cancel keeps the logo.
  await page.getByRole("button", { name: "Delete logo" }).click();
  await cancelDialog(page, "The sign-in and consent pages will stop showing it.");
  await expect(logo).toBeVisible();

  await page.getByRole("button", { name: "Delete logo" }).click();
  await confirmDialog(page, "The sign-in and consent pages will stop showing it.");
  await expect(page.locator("#imageUploadStatus")).toContainText("Logo deleted.");
  await expect(logo).toHaveCount(0);
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
  await page.reload();
  await expect(logo).toHaveCount(0);
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
});

for (const { kind, file, message } of [
  {
    kind: "a file of a type that is no image",
    file: { name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("not an image") },
    message: "Choose a JPEG, PNG, GIF or WebP image.",
  },
  {
    kind: "a file named as an image that does not decode as one",
    file: { name: "broken.png", mimeType: "image/png", buffer: Buffer.from("not an image") },
    message: "That file couldn't be read as an image. Choose another one.",
  },
  {
    kind: "a file larger than 3 MB",
    file: { name: "large.png", mimeType: "image/png", buffer: Buffer.alloc(3 * 1024 * 1024 + 1) },
    message: "This file is larger than 3 MB. Choose a smaller one.",
  },
]) {
  test(`${kind} is refused, and no crop opens`, async ({ page, clients }) => {
    const client = await clients.create();
    await page.goto(clientUrl(client.id, "logo"));
    await page.locator("#imageUploadInput").setInputFiles(file);
    await expect(page.locator("#imageUploadStatus")).toContainText(message);
    await expect(page.locator("#cropDialog")).toBeHidden();
    await expect(page.locator("#deleteImageBtn")).toBeHidden();
  });
}
