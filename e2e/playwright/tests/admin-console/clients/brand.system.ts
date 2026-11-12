// The console drawn in its brand's kit (#813): the admin console's own client given a brand with a
// logo, a dark logo and a favicon. Its admin pages take the brand's colors and logo and keep Goiabada's
// icons; its end-user pages, Account, home and an error page, take the full stylesheet and the brand's
// favicon. The logo sits before the app name in the header's link to home and above it on a card, the
// light one or the dark one as the device asks, and stands in for the name while the brand's switch
// hides it. The console's end-user pages also draw the brand's footer links and support contact
// (#814): under the card on home and an error page, after the content on an Account page, each
// label in the page's language. Its admin pages draw none. The console's own client's brand is what
// every console page is drawn in, so this runs alone, and puts the client back on the default brand.
import type { Browser, Locator, Page } from "@playwright/test";
import { clientIdFromList, setClientBrand } from "../../../lib/admin-console";
import {
  brandFaviconIcons,
  brandKitToken,
  brandingUrl,
  goiabadaIcons,
  pageBrandStylesheets,
  pageIcons,
  saveBrand,
  setBrandFooter,
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

// A page's footer landmark, the brand's footer.
const footerOf = (page: Page) => page.getByRole("contentinfo");

// The console's home in a browser of its own that asks for German, signed out.
async function openGermanHome(browser: Browser) {
  const context = await browser.newContext({ locale: "de-DE", storageState: { cookies: [], origins: [] } });
  const home = await context.newPage();
  await home.goto(`${env.adminUrl}/`);
  return { context, home };
}

test("the console's own client given a brand with footer links and a support contact draws them under its cards and after an Account page's content, none on its admin pages, and is put back", async ({
  page,
  request,
  clients,
  browser,
}) => {
  const token = await brandKitToken(page, request, clients);
  const consoleClient = await clientIdFromList(page, "admin-console-client");

  await withBrand(page, { appearance: "auto", theme: "plum" }, async (brand) => {
    await setBrandFooter(request, token, brand.id, {
      footerLinks: [
        { url: "https://example.com/privacy", label: "Privacy", labels: { de: "Datenschutz" } },
        { url: "https://status.example.com/", label: "Status" },
      ],
      supportEmail: "help@example.com",
      supportUrl: "https://example.com/support",
      supportPhone: "+14155550123",
    });
    try {
      // Saving the console's own client's brand draws every console page in it at once.
      await setClientBrand(page, consoleClient, brand);

      // Cards: home, and an error answered for an admin URL. The footer is its own landmark, outside
      // main, under the card: the links, each opening a new tab and saying so, then "Need help?".
      for (const [name, url, status] of [
        ["home", `${env.adminUrl}/`, 200],
        ["an error page at an admin URL", `${env.adminUrl}/admin/clients/999999999/settings`, 404],
      ] as const) {
        const answer = await page.goto(url);
        expect(answer?.status(), name).toBe(status);
        const footer = footerOf(page);
        await expect(footer, name).toBeVisible();
        await expect(page.locator("main footer"), name).toHaveCount(0);
        await expect(footer.getByRole("listitem"), name).toHaveCount(2);
        const privacy = footer.getByRole("link", { name: "Privacy (opens in a new tab)", exact: true });
        await expect(privacy, name).toHaveAttribute("href", "https://example.com/privacy");
        await expect(privacy, name).toHaveAttribute("target", "_blank");
        await expect(privacy, name).toHaveAttribute("rel", "noopener noreferrer");
        await expect(footer.getByRole("link", { name: "Status (opens in a new tab)", exact: true }), name).toHaveAttribute(
          "href",
          "https://status.example.com/",
        );
        await expect(footer.getByText("Need help?", { exact: true }), name).toBeVisible();
        await expect(footer.getByRole("link", { name: "help@example.com", exact: true }), name).toHaveAttribute("href", "mailto:help@example.com");
        await expect(footer.getByRole("link", { name: "+14155550123", exact: true }), name).toHaveAttribute("href", "tel:+14155550123");
        await expect(footer.getByRole("link", { name: "Support page (opens in a new tab)", exact: true }), name).toHaveAttribute(
          "href",
          "https://example.com/support",
        );
        const card = await page.locator(".auth-card").boundingBox();
        const drawn = await footer.boundingBox();
        expect(drawn!.y, `${name}: the footer is under the card`).toBeGreaterThanOrEqual(card!.y + card!.height);
      }

      // An Account page: the footer after the content, outside main.
      await page.goto(`${env.adminUrl}/account/profile`);
      await expect(page.getByRole("navigation", { name: "Account", exact: true })).toBeVisible();
      const accountFooter = footerOf(page);
      await expect(accountFooter).toBeVisible();
      await expect(page.locator("main footer")).toHaveCount(0);
      await expect(accountFooter.getByRole("link", { name: "Privacy (opens in a new tab)", exact: true })).toBeVisible();
      await expect(accountFooter.getByRole("link", { name: "help@example.com", exact: true })).toBeVisible();
      const content = await page.locator("main").boundingBox();
      const accountDrawn = await accountFooter.boundingBox();
      expect(accountDrawn!.y, "the footer follows the content").toBeGreaterThanOrEqual(content!.y + content!.height);

      // Admin pages draw no footer.
      for (const path of ["/admin/clients", "/admin/settings/branding"]) {
        await page.goto(`${env.adminUrl}${path}`);
        await expect(page.getByRole("navigation", { name: "Admin", exact: true }), path).toBeVisible();
        await expect(page.locator("footer"), path).toHaveCount(0);
      }

      // A page in German takes the link's German label, and the fallback label for a link with none.
      const german = await openGermanHome(browser);
      const germanFooter = footerOf(german.home);
      await expect(germanFooter.getByRole("link", { name: "Datenschutz (öffnet sich in einem neuen Tab)", exact: true })).toHaveAttribute(
        "href",
        "https://example.com/privacy",
      );
      await expect(germanFooter.getByRole("link", { name: "Status (öffnet sich in einem neuen Tab)", exact: true })).toBeVisible();
      await expect(germanFooter.getByText("Brauchen Sie Hilfe?", { exact: true })).toBeVisible();
      await german.context.close();
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }

    // Put back: the console is drawn in the default again, which has no footer.
    await page.goto(`${env.adminUrl}/`);
    expect((await pageBrandStylesheets(page))[0]?.brandId).not.toBe(brand.id);
    await expect(page.locator("footer")).toHaveCount(0);
  });
});
