// The rest of a brand's kit as a client's sign-in page draws it (#813), beside kit.spec.ts's tiled
// background, pill corners and uploaded font: a background that covers the window and one that is
// contained, square corners, a system font family, a Dark or a Light brand drawing its one logo
// whatever the device asks, and the switch that hides the app name doing nothing while there is no
// logo. A saved change gives the brand's stylesheet a new address, so a browser holding the old one
// in its cache draws the change at once. The brand's files and stylesheets are served with their own
// type, nosniff, and a year's cache at the address a page links, five minutes at any other; a font
// is shared with the admin console's origin alone.
//
// The brands are the test's own, given to clients of the test's own, so no other page changes, and
// this is an ordinary parallel spec.
import type { Browser, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandIdFromList,
  brandUrl,
  deleteBrand,
  fillBrandForm,
  firstFontOf,
  kitFiles,
  listBrands,
  newBrandUrl,
  pngFile,
  uploadInEditor,
  type Appearance,
  type BackgroundFit,
  type BrandSlot,
  type Corners,
  type FontFamily,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// The client's sign-in, opened in a browser of its own, at its password step.
async function openPasswordStep(browser: Browser, client: TestClient) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
  return signIn;
}

interface KitBrand {
  appearance?: Appearance;
  corners?: Corners;
  font?: FontFamily;
  backgroundFit?: BackgroundFit;
  hideAppName?: boolean;
  files?: BrandSlot[];
}

// Creates a brand in the editor with these choices and these kit files uploaded, gives it to client,
// and answers its id and the URL each file is served at. The caller deletes it.
async function kitBrand(page: Page, client: TestClient, kit: KitBrand) {
  const name = uniqueIdentifier("brand");
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, theme: "plum", appearance: kit.appearance ?? "auto", ...kit });
  const urls: Partial<Record<BrandSlot, string>> = {};
  for (const slot of kit.files ?? []) urls[slot] = await uploadInEditor(page, slot, kitFiles[slot]);
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/settings\/branding$/);
  const id = await brandIdFromList(page, name);
  await setClientBrand(page, client.id, { name });
  return { id, name, urls };
}

async function deleteIfThere(page: Page, id: number) {
  if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
}

// How a sign-in page draws the kit, as the browser computes it.
function drawnKit(page: Page) {
  return page.evaluate(() => {
    const background = getComputedStyle(document.querySelector(".auth-page")!);
    return {
      backgroundImage: background.backgroundImage,
      backgroundSize: background.backgroundSize,
      backgroundRepeat: background.backgroundRepeat,
      backgroundAttachment: background.backgroundAttachment,
      backgroundPosition: background.backgroundPosition,
      card: getComputedStyle(document.querySelector(".auth-card")!).borderTopLeftRadius,
      control: getComputedStyle(document.querySelector(".control")!).borderTopLeftRadius,
      button: getComputedStyle(document.querySelector(".button-primary")!).borderTopLeftRadius,
      font: getComputedStyle(document.querySelector(".auth-title")!).fontFamily,
    };
  });
}

test("a covering background, square corners and a serif family are drawn on a client's sign-in page, and a contained background once saved", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const brand = await kitBrand(page, client, { corners: "square", font: "serif", backgroundFit: "cover", files: ["background"] });
  try {
    const signIn = await openPasswordStep(browser, client);
    try {
      const kit = await drawnKit(signIn.page);
      expect(kit.backgroundImage).toBe(`url("${brand.urls.background}")`);
      // Cover: the image fills the window, centred, and stays as the page scrolls.
      expect(kit.backgroundSize).toBe("cover");
      expect(kit.backgroundRepeat).toBe("no-repeat");
      expect(kit.backgroundAttachment).toBe("fixed");
      expect(kit.backgroundPosition).toBe("50% 50%");
      expect([kit.card, kit.control, kit.button], "square corners").toEqual(["0px", "0px", "0px"]);
      expect(firstFontOf(kit.font), "the serif family's first font").toBe("Charter");

      // Contained, saved in the editor: the whole image, centred, the theme's color around it.
      await page.goto(brandUrl(brand.id, "edit"));
      await fillBrandForm(page, { backgroundFit: "contain" });
      await page.locator("#btnSave").click();
      await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
      await signIn.page.reload();
      const contained = await drawnKit(signIn.page);
      expect(contained.backgroundSize).toBe("contain");
      expect(contained.backgroundRepeat).toBe("no-repeat");
      expect(contained.backgroundPosition).toBe("50% 50%");
      expect(contained.backgroundImage).toBe(`url("${brand.urls.background}")`);
    } finally {
      await signIn.context.close();
    }
  } finally {
    await deleteIfThere(page, brand.id);
  }
});

// A brand on Light or Dark draws one mode, so it draws that mode's logo whatever the device asks: a
// Dark brand its dark logo on a light device, a Light brand its light logo on a dark one.
test("a Dark brand draws its dark logo and a Light brand its light logo, whatever the device asks", async ({ page, browser, clients }) => {
  for (const [appearance, slot] of [["dark", "darkLogo"], ["light", "logo"]] as const) {
    await test.step(appearance, async () => {
      const { client } = await browserSignInClient(page, clients);
      const brand = await kitBrand(page, client, { appearance, files: ["logo", "darkLogo"] });
      try {
        const signIn = await openPasswordStep(browser, client);
        try {
          const logo = signIn.page.locator(".auth-logo img");
          for (const colorScheme of ["light", "dark"] as const) {
            await signIn.page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
            await expect.poll(() => logo.evaluate((img: HTMLImageElement) => img.currentSrc), `${appearance} on a ${colorScheme} device`).toBe(
              brand.urls[slot],
            );
          }
        } finally {
          await signIn.context.close();
        }
      } finally {
        await deleteIfThere(page, brand.id);
      }
    });
  }
});

test("the switch hiding the app name hides nothing while the brand has no logo", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const brand = await kitBrand(page, client, { hideAppName: true });
  try {
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator("#hideAppName"), "the switch is stored on").toBeChecked();
    const signIn = await openPasswordStep(browser, client);
    try {
      await expect(signIn.page.locator(".auth-logo img")).toHaveCount(0);
      await expect(signIn.page.locator(".auth-card .auth-brand"), "the app name stands alone").toBeVisible();
      expect((await signIn.page.locator(".auth-card .auth-brand").innerText()).trim()).not.toBe("");
    } finally {
      await signIn.context.close();
    }
  } finally {
    await deleteIfThere(page, brand.id);
  }
});

// The address of the one brand stylesheet a page links, as it links it, its fingerprint included.
function brandStylesheetHref(page: Page): Promise<string> {
  return page.evaluate(() => {
    const links = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')).filter((link) =>
      /^\/brand\/\d+\/[a-z-]+\.css$/.test(new URL(link.href).pathname),
    );
    if (links.length !== 1) throw new Error(`the page links ${links.length} brand stylesheets`);
    return links[0].href;
  });
}

test("a saved change and a replaced logo give the page new addresses, so a browser that cached the old ones draws the change at once", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const brand = await kitBrand(page, client, { corners: "rounded", files: ["logo"] });
  try {
    const signIn = await openPasswordStep(browser, client);
    try {
      const before = await brandStylesheetHref(signIn.page);
      expect(new URL(before).searchParams.get("v"), "the stylesheet's address names its content").toMatch(/^[0-9a-f]{12}$/);
      await expect.poll(() => signIn.page.locator(".auth-logo img").evaluate((img: HTMLImageElement) => img.currentSrc)).toBe(brand.urls.logo);

      // Square corners and another logo, saved in the editor.
      await page.goto(brandUrl(brand.id, "edit"));
      await fillBrandForm(page, { corners: "square" });
      const replaced = await uploadInEditor(page, "logo", pngFile("logo-2.png", 200, 60, [200, 40, 40]));
      expect(replaced).not.toBe(brand.urls.logo);
      await page.locator("#btnSave").click();
      await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();

      // The same browser, whose cache holds the old stylesheet for a year, reloads the page.
      await signIn.page.reload();
      const after = await brandStylesheetHref(signIn.page);
      expect(after, "a new address for the changed stylesheet").not.toBe(before);
      expect((await drawnKit(signIn.page)).card, "the change is drawn").toBe("0px");
      await expect.poll(() => signIn.page.locator(".auth-logo img").evaluate((img: HTMLImageElement) => img.currentSrc)).toBe(replaced);
    } finally {
      await signIn.context.close();
    }
  } finally {
    await deleteIfThere(page, brand.id);
  }
});

test("the brand's files and stylesheets are served with their type, nosniff, and a year's cache at the address a page links", async ({
  page,
  browser,
  clients,
  request,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const brand = await kitBrand(page, client, { font: "uploaded", files: ["logo", "background", "regularFont"] });
  try {
    const signIn = await openPasswordStep(browser, client);
    const stylesheet = await brandStylesheetHref(signIn.page);
    await signIn.context.close();

    const year = "public, max-age=31536000, immutable";
    const fiveMinutes = "public, max-age=300";
    for (const [what, url, type] of [
      ["the logo", brand.urls.logo!, "image/png"],
      ["the background", brand.urls.background!, "image/png"],
      ["the font", brand.urls.regularFont!, "font/woff2"],
      ["the stylesheet", stylesheet, "text/css; charset=utf-8"],
    ] as const) {
      await test.step(what, async () => {
        // At the address a page links, its fingerprint the content's: a year, never checked again.
        const linked = await request.get(url, { failOnStatusCode: false });
        expect(linked.status(), url).toBe(200);
        expect(linked.headers()["content-type"]).toBe(type);
        expect(linked.headers()["x-content-type-options"]).toBe("nosniff");
        expect(linked.headers()["cache-control"]).toBe(year);
        expect((await linked.body()).length).toBeGreaterThan(0);
        // A font may be drawn by the admin console's pages, on another origin, and by no other site;
        // nothing else is shared.
        expect(linked.headers()["access-control-allow-origin"], "who else may use it").toBe(
          what === "the font" ? new URL(env.adminUrl).origin : undefined,
        );

        // HEAD answers the same headers and no body.
        const head = await request.head(url, { failOnStatusCode: false });
        expect(head.status()).toBe(200);
        expect(head.headers()["content-type"]).toBe(type);

        // A fingerprint that is not the content's, or none: the same content, cached five minutes.
        for (const other of [`${url.split("?")[0]}?v=000000000000`, url.split("?")[0]]) {
          const stale = await request.get(other, { failOnStatusCode: false });
          expect(stale.status(), other).toBe(200);
          expect(stale.headers()["cache-control"], other).toBe(fiveMinutes);
        }
      });
    }

    // An address naming no file or no brand answers not found.
    for (const missing of [`${env.authUrl}/brand-assets/999999999`, `${env.authUrl}/brand/999999999/stylesheet.css`]) {
      expect((await request.get(missing, { failOnStatusCode: false })).status(), missing).toBe(404);
    }
  } finally {
    await deleteIfThere(page, brand.id);
  }
});
