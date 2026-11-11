// A brand's kit set in the brand editor (#813), then seen where it is drawn: a client's sign-in page,
// in a light and in a dark device. Each file is picked at its field and uploaded at once, through the
// console, and Save attaches it: the logo above the card's app name, the dark logo in dark mode, the
// name hidden beside a logo while the switch hides it, the favicon as the tab's icon, the background
// image behind the card at its fit, and the uploaded font. A file the admin API refuses is said at its
// field, and the slot keeps what it held. The font is checked by the family the page asks for, not by
// how its letters look: the file the spec uploads is a WOFF2 signature, which no browser draws.
//
// The brand is the test's own, given to a client of the test's own, so no other page changes, and
// this is an ordinary parallel spec.
import type { Browser, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandFaviconIcons,
  brandIdFromList,
  brandUrl,
  brandingUrl,
  deleteBrand,
  fillBrandForm,
  firstFontOf,
  goiabadaIcons,
  listBrands,
  newBrandUrl,
  pageIcons,
  pickInEditor,
  pngFile,
  slotHolds,
  uploadKit,
  uploadSays,
  woff2File,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// What a sign-in page draws of its brand's kit, as the browser computes it: the logo it shows, its
// alt, whether the app name is drawn as text, the card's font family, the page's background and how it
// is laid out, and the corners of the card and of its primary button.
async function signInKit(page: Page) {
  return page.evaluate(() => {
    const image = document.querySelector<HTMLImageElement>(".auth-logo img");
    const background = getComputedStyle(document.querySelector(".auth-page")!);
    return {
      logo: image ? image.currentSrc : null,
      alt: image ? image.getAttribute("alt") : null,
      nameDrawn: document.querySelectorAll(".auth-card .auth-brand").length > 0,
      font: getComputedStyle(document.querySelector(".auth-title")!).fontFamily,
      backgroundImage: background.backgroundImage,
      backgroundRepeat: background.backgroundRepeat,
      card: getComputedStyle(document.querySelector(".auth-card")!).borderTopLeftRadius,
      button: getComputedStyle(document.querySelector(".button-primary")!).borderTopLeftRadius,
    };
  });
}

// The client's sign-in, opened in a browser of its own, at its password step.
async function openPasswordStep(browser: Browser, client: TestClient) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
  return signIn;
}

test("each field of the kit set in the editor is drawn on a sign-in page, light and dark, and a file removed and saved is gone", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");

  // The app name, as the client's sign-in draws it in the default brand, which has no logo.
  const before = await openPasswordStep(browser, client);
  const appName = (await before.page.locator(".auth-card .auth-brand").innerText()).trim();
  expect(appName, "the default brand draws the app name").not.toBe("");
  await before.context.close();

  // A new brand: the choices, then each file uploaded at its field, which says so and holds it.
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "auto", theme: "plum", corners: "pill", font: "uploaded", backgroundFit: "tile", hideAppName: true });
  const urls = await uploadKit(page);
  for (const slot of ["logo", "darkLogo", "favicon", "background", "regularFont", "boldFont"] as const) {
    expect(urls[slot], `the ${slot}'s URL`).toMatch(new RegExp(`^${env.authUrl}/brand-assets/\\d+\\?v=`));
    await expect(page.locator(`#${slot}Remove`), `Remove for the ${slot}`).toBeVisible();
  }
  await expect(page.locator(".brand-asset-thumb img").first(), "the logo's thumbnail").toHaveAttribute("src", urls.logo!);
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(brandingUrl);
  const id = await brandIdFromList(page, name);

  try {
    // The brand's page holds what Create attached.
    await page.goto(brandUrl(id, "edit"));
    for (const slot of ["logo", "darkLogo", "favicon", "background", "regularFont", "boldFont"] as const) {
      expect((await slotHolds(page, slot)).url, `the stored ${slot}`).toBe(urls[slot]);
    }

    await setClientBrand(page, client.id, { name });
    const signIn = await openPasswordStep(browser, client);
    const own = signIn.page;
    for (const colorScheme of ["light", "dark"] as const) {
      await own.emulateMedia({ colorScheme, reducedMotion: "reduce" });
      const want = colorScheme === "dark" ? urls.darkLogo : urls.logo;
      await expect.poll(async () => (await signInKit(own)).logo, `the logo a ${colorScheme} device draws`).toBe(want);
      const kit = await signInKit(own);
      // The switch hides the name: the logo stands in for it, its alt the app name.
      expect(kit.alt, colorScheme).toBe(appName);
      expect(kit.nameDrawn, `${colorScheme}: the name is not drawn as text`).toBe(false);
      expect(firstFontOf(kit.font), `${colorScheme}: the uploaded font`).toBe("brand-font");
      expect(kit.backgroundImage, `${colorScheme}: the background`).toBe(`url("${urls.background}")`);
      expect(kit.backgroundRepeat, `${colorScheme}: tiled`).toBe("repeat");
      expect(kit.card, `${colorScheme}: the pill card`).toBe("24px");
      expect(kit.button, `${colorScheme}: the pill button`).toBe("9999px");
      expect(await pageIcons(own), `${colorScheme}: the brand's favicon`).toEqual(brandFaviconIcons(urls.favicon!));
    }

    // The favicon removed and the brand saved: the sign-in links Goiabada's icons again, and keeps the
    // rest of the kit.
    await page.goto(brandUrl(id, "edit"));
    await page.locator("#faviconRemove").click();
    await expect(page.locator("#faviconStatus")).toHaveText(uploadSays.removed);
    await expect(page.locator("#faviconUpload"), "the focus goes to the field's Upload").toBeFocused();
    expect(await slotHolds(page, "favicon")).toEqual({ id: "", url: "" });
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    await expect(page.locator("#faviconRemove")).toBeHidden();

    await own.reload();
    expect(await pageIcons(own)).toEqual(goiabadaIcons(new URL(env.authUrl).origin));
    await own.emulateMedia({ colorScheme: "light" });
    await expect.poll(async () => (await signInKit(own)).logo).toBe(urls.logo);
    await signIn.context.close();
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
});

// Each refusal names what was wrong and the limit it broke, at the field, and the slot keeps what it
// held (#813 decision 3). A file over the kind's byte limit is refused before it is sent.
test("a file the kit's rules refuse is said at its field, and the slot keeps what it held", async ({ page }) => {
  await page.goto(newBrandUrl);

  const sent: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST") sent.push(new URL(request.url()).pathname);
  });
  const tooLarge = { name: "huge.png", mimeType: "image/png", buffer: Buffer.alloc(1024 * 1024 + 1) };
  expect(await pickInEditor(page, "logo", tooLarge)).toBe("The image can be at most 1048576 bytes.");
  expect(sent, "a file over the limit is not sent").toEqual([]);

  expect(await pickInEditor(page, "favicon", pngFile("wide.png", 64, 32, [10, 20, 30]))).toBe(
    "The image must be square. This one is 64x32 pixels.",
  );
  expect(await pickInEditor(page, "background", woff2File("not-an-image.woff2"))).toBe(
    "The image type is not supported. Allowed types are PNG, JPEG and WebP.",
  );
  expect(await pickInEditor(page, "regularFont", pngFile("not-a-font.png", 20, 20, [0, 0, 0]))).toBe(
    "The font type is not supported. The only allowed type is WOFF2.",
  );
  for (const slot of ["logo", "favicon", "background", "regularFont"] as const) {
    expect(await slotHolds(page, slot), `the ${slot} is still empty`).toEqual({ id: "", url: "" });
    await expect(page.locator(`#${slot}Remove`)).toBeHidden();
  }

  // A refusal leaves an uploaded file where it was.
  await uploadKit(page, ["logo"]);
  const held = await slotHolds(page, "logo");
  expect(await pickInEditor(page, "logo", pngFile("tiny.png", 5, 5, [0, 0, 0]))).toBe("The image must be at least 10x10 pixels.");
  expect(await slotHolds(page, "logo"), "the uploaded logo is kept").toEqual(held);
});

// A dark logo without a logo is refused when the brand is saved, at the logo's field, whose Upload
// takes the focus, and the form keeps the dark logo uploaded.
test("a dark logo without a logo is refused at the logo's field, and the form keeps its files", async ({ page }) => {
  const name = uniqueIdentifier("brand");
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name });
  const urls = await uploadKit(page, ["darkLogo", "favicon"]);
  await page.locator("#btnCreate").click();

  await expect(page).toHaveURL(newBrandUrl);
  await expect(page.locator("#brand-error")).toHaveText("Upload a logo to use a dark logo.");
  await expect(page.locator("#logoUpload")).toBeFocused();
  await expect(page.locator("#logoLabel").locator("xpath=..")).toHaveAttribute("aria-describedby", /^brand-error /);
  expect((await slotHolds(page, "darkLogo")).url).toBe(urls.darkLogo);
  expect((await slotHolds(page, "favicon")).url).toBe(urls.favicon);
  await expect(page.locator("#faviconRemove")).toBeVisible();

  await page.goto(brandingUrl);
  await expect(page.locator("#brandsTable").getByText(name, { exact: true })).toHaveCount(0);
});
