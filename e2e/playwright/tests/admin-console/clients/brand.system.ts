// The console drawn in its brand's kit (#813): the admin console's own client given a brand with a
// logo, a dark logo and a favicon. Its admin pages take the brand's colors and logo and keep Goiabada's
// icons; its end-user pages, Account, home and an error page, take the full stylesheet and the brand's
// favicon. The logo sits before the app name in the header's link to home and above it on a card, the
// light one or the dark one as the device asks, and stands in for the name while the brand's switch
// hides it. The console's own client's brand is what every console page is drawn in, so this runs
// alone, and puts the client back on the default brand.
import type { Locator, Page } from "@playwright/test";
import { clientIdFromList, setClientBrand } from "../../../lib/admin-console";
import {
  brandFaviconIcons,
  brandKitToken,
  brandingUrl,
  goiabadaIcons,
  pageBrandStylesheets,
  pageIcons,
  saveBrand,
  setBrandKit,
  uploadBrandAsset,
  withBrand,
} from "../../../lib/brands";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";

// A logo draws the light image under a device asking for light and the dark one under a device
// asking for dark, as the browser picks the source of its picture.
async function expectLogoFollowsDevice(page: Page, image: Locator, light: string, dark: string, where: string) {
  for (const [colorScheme, url] of [["light", light], ["dark", dark]] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.currentSrc), `${where}, ${colorScheme}`).toBe(url);
  }
  await page.emulateMedia({ colorScheme: null, reducedMotion: null });
}

// The header's link to home on a menu page, the sidebar's on a wide screen.
const homeLink = (page: Page) => page.locator("a.sidebar-brand");

test("the console's own client given a brand with a logo and a favicon draws them on its pages, the admin pages keeping Goiabada's icons, and is put back", async ({
  page,
  request,
  clients,
}) => {
  const token = await brandKitToken(page, request, clients);
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const consoleIcons = goiabadaIcons(new URL(env.adminUrl).origin);

  await withBrand(page, { appearance: "auto", theme: "plum" }, async (brand) => {
    const logo = await uploadBrandAsset(request, token, "logo", solidPng(200, 50, [200, 40, 40]));
    const darkLogo = await uploadBrandAsset(request, token, "logo", solidPng(200, 50, [250, 200, 60]));
    const favicon = await uploadBrandAsset(request, token, "favicon", solidPng(64, 64, [40, 160, 40]));
    await setBrandKit(request, token, brand.id, { logo, darkLogo, favicon });
    try {
      // Saving the console's own client's brand draws every console page in it at once.
      await setClientBrand(page, consoleClient, brand);

      // An admin page: the colors-only stylesheet, Goiabada's icons, and the logo before the name,
      // its alt empty while the name is shown as text.
      await page.goto(brandingUrl);
      expect(await pageBrandStylesheets(page)).toEqual([{ brandId: brand.id, kind: "colors" }]);
      expect(await pageIcons(page)).toEqual(consoleIcons);
      const appName = (await homeLink(page).locator(".app-brand-name").innerText()).trim();
      expect(appName, "the name is shown beside the logo").not.toBe("");
      await expect(homeLink(page).locator("img")).toHaveAttribute("alt", "");
      await expect(homeLink(page)).toHaveAccessibleName(appName);
      await expectLogoFollowsDevice(page, homeLink(page).locator("img"), logo.url, darkLogo.url, "an admin page");

      // An Account page: the full stylesheet, the brand's favicon, and the logo in its header.
      await page.goto(`${env.adminUrl}/account/profile`);
      expect(await pageBrandStylesheets(page)).toEqual([{ brandId: brand.id, kind: "full" }]);
      expect(await pageIcons(page)).toEqual(brandFaviconIcons(favicon.url));
      await expectLogoFollowsDevice(page, homeLink(page).locator("img"), logo.url, darkLogo.url, "an Account page");

      // Cards: home, and an error answered for an admin URL, an end-user page too. The logo sits above
      // the app name.
      for (const [name, url, status] of [
        ["home", `${env.adminUrl}/`, 200],
        ["an error page at an admin URL", `${env.adminUrl}/admin/clients/999999999/settings`, 404],
      ] as const) {
        const answer = await page.goto(url);
        expect(answer?.status(), name).toBe(status);
        expect(await pageBrandStylesheets(page), name).toEqual([{ brandId: brand.id, kind: "full" }]);
        expect(await pageIcons(page), name).toEqual(brandFaviconIcons(favicon.url));
        const cardLogo = page.locator(".auth-card .auth-logo img");
        await expect(cardLogo, name).toHaveAttribute("alt", "");
        await expect(page.locator(".auth-card .auth-brand"), name).toHaveText(appName);
        await expectLogoFollowsDevice(page, cardLogo, logo.url, darkLogo.url, name);
      }

      // The switch hides the name: the logo stands in for it, its alt the app name, which is then the
      // header link's name. Set through the Admin API, then saved as it stands in the editor, whose save
      // draws every console page again at once.
      await setBrandKit(request, token, brand.id, { logo, darkLogo, favicon, hideAppName: true });
      await saveBrand(page, brand.id, {});
      for (const path of ["/admin/settings/branding", "/account/profile"]) {
        await page.goto(`${env.adminUrl}${path}`);
        await expect(homeLink(page).locator(".app-brand-name"), path).toHaveCount(0);
        await expect(homeLink(page).locator("img"), path).toHaveAttribute("alt", appName);
        await expect(homeLink(page), path).toHaveAccessibleName(appName);
      }
      await page.goto(`${env.adminUrl}/`);
      await expect(page.locator(".auth-card .auth-brand")).toHaveCount(0);
      await expect(page.locator(".auth-card .auth-logo img")).toHaveAttribute("alt", appName);
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }

    // Put back: the console is drawn in the default again, with no logo.
    await page.goto(brandingUrl);
    expect((await pageBrandStylesheets(page))[0]?.brandId).not.toBe(brand.id);
    await expect(homeLink(page).locator("img")).toHaveCount(0);
  });
});
