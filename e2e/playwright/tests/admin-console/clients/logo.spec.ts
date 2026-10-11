import { clientUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";

test("a logo is uploaded, shown, and deleted", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "logo"));
  await expect(page.locator("#deleteImageBtn")).toBeHidden();

  await page.locator("#imageUploadInput").setInputFiles({
    name: "logo.png",
    mimeType: "image/png",
    buffer: solidPng(128, 128, [200, 40, 90]),
  });
  await expect(page.locator("#cropModal")).toBeVisible();
  await page.locator("#confirmCropBtn").click();
  await expect(page.locator("#imagePreview")).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeVisible();

  // Still there after a reload, served by the auth server.
  await page.reload();
  const preview = page.locator("#imagePreview");
  await expect(preview).toBeVisible();
  const src = await preview.getAttribute("src");
  expect(src).toBeTruthy();
  const image = await page.request.get(new URL(src!, page.url()).toString());
  expect(image.status()).toBe(200);
  expect(image.headers()["content-type"]).toMatch(/^image\//);

  // The delete asks through the browser's own confirm(), which Playwright dismisses unless told.
  page.once("dialog", (dialog) => dialog.accept());
  await page.locator("#deleteImageBtn").click();
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
  await page.reload();
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
});

test("a file that is not an image is refused", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "logo"));
  await page.locator("#imageUploadInput").setInputFiles({
    name: "notes.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("not an image"),
  });
  await expect(page.locator("#imageUploadError")).toBeVisible();
  await expect(page.locator("#deleteImageBtn")).toBeHidden();
});
