// goiabada_safe_mode on an authorization request (#816 decision 3), beside authorize-parameters.spec.ts's
// sign-in drawn safe: the pages the sign-in links to, in the browser holding it, are drawn safe too,
// and so is the page refusing a request once its client is known. Safe mode sets aside only what an
// administrator authors freely, the custom CSS, the custom palette and the uploaded font: the logo,
// the favicon, the background image and the footer stay. The parameter asks for safe mode with true
// alone, any other value asking for nothing, and is refused when sent twice, as every parameter of
// the request is.
//
// The brand and the client are the test's own, so no other page changes, and this is an ordinary
// parallel spec.
import type { Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandUrl,
  customCssField,
  drawnFooter,
  fillBrandFooter,
  fillBrandForm,
  kitFiles,
  pageIcons,
  pageToken,
  uploadInEditor,
  warmBasicPalette,
  withCustomBrand,
} from "../../../lib/brands";
import { openSignIn, testRedirectUri } from "../../../lib/browser-sign-in";
import { expect, test } from "../../../lib/fixtures";
import { authorizeEndpoint, codeRequest, expectAuthorizeError } from "../../../lib/rfc6749";
import { browserSignInClient } from "../../../lib/test-clients";

const outlined = "rgb(18, 52, 86)";
const blueberryCanvas = "#f4f5f7";

// What a page draws of the brand, safe or not: the brand stylesheet it links, by the last part of its
// path, its custom CSS's outline on the card, its canvas, its logo, its icons, its background and its
// footer's links.
async function drawnBrand(page: Page) {
  const look = await page.evaluate(() => ({
    stylesheets: Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]'))
      .map((link) => new URL(link.href).pathname.match(/^\/brand\/\d+\/([a-z-]+)\.css$/)?.[1])
      .filter((kind) => kind !== undefined),
    outline: getComputedStyle(document.querySelector(".auth-card")!).outlineColor,
    logo: document.querySelector<HTMLImageElement>(".auth-logo img")?.currentSrc ?? null,
    background: getComputedStyle(document.querySelector(".auth-page")!).backgroundImage,
  }));
  return {
    ...look,
    canvas: await pageToken(page, "canvas"),
    icons: (await pageIcons(page)).length,
    footer: (await drawnFooter(page))?.links.map((link) => link.href) ?? [],
  };
}

test("safe mode reaches the pages a sign-in links to and its refusal page, and keeps the brand's logo, favicon, background and footer", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandForm(page, { backgroundFit: "tile" });
    const logo = await uploadInEditor(page, "logo", kitFiles.logo);
    const favicon = await uploadInEditor(page, "favicon", kitFiles.favicon);
    const background = await uploadInEditor(page, "background", kitFiles.background);
    await fillBrandFooter(page, { footerLinks: [{ label: "Help", url: "https://example.com/help" }] });
    await customCssField(page).fill(`.auth-card {\n  outline: 6px solid ${outlined};\n}\n`);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    await setClientBrand(page, client.id, brand);

    // What safe mode keeps, and what it sets aside.
    const safe = {
      stylesheets: ["safe-stylesheet"],
      outline: expect.not.stringMatching(/^rgb\(18, 52, 86\)$/),
      canvas: blueberryCanvas,
      logo,
      icons: 2,
      background: `url("${background}")`,
      footer: ["https://example.com/help"],
    };
    expect(favicon).toBeTruthy();

    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid", params: { goiabada_safe_mode: "true" } });
    try {
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      expect(await drawnBrand(signIn.page), "the sign-in").toEqual(safe);

      // The forgot password page its link leads to, in the same browser, and the page saying the
      // link was sent.
      await signIn.page.getByRole("link", { name: "Forgot your password?" }).click();
      await expect(signIn.page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
      expect(await drawnBrand(signIn.page), "forgot password").toEqual(safe);

      // The same client's sign-in without the parameter, in the same browser, is drawn as saved.
      const usual = await signIn.context.newPage();
      const { params } = codeRequest(client.identifier);
      await usual.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
      await expect(usual).toHaveURL(/\/auth\/pwd/);
      expect(await drawnBrand(usual), "a sign-in without it").toEqual({ ...safe, stylesheets: ["stylesheet"], outline: outlined, canvas: warmBasicPalette.light.canvas });
    } finally {
      await signIn.context.close();
    }

    // A request refused once its client is known, its redirect URI not registered, drawn safe.
    const refused = await openSignIn(browser, {
      clientId: client.identifier,
      scope: "openid",
      params: { goiabada_safe_mode: "true", redirect_uri: "https://unregistered.example/callback" },
    });
    try {
      await expect(refused.page.getByRole("heading", { level: 1, name: "Unable to authorize", exact: true })).toBeVisible();
      expect(await drawnBrand(refused.page), "the refusal page").toEqual(safe);
    } finally {
      await refused.context.close();
    }
  });
});

test("goiabada_safe_mode asks for safe mode with true alone, and is refused when sent twice", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await setClientBrand(page, client.id, brand);

    // Any other value is no parameter at all.
    for (const value of ["1", "false", "TRUE", ""]) {
      await test.step(`goiabada_safe_mode=${value}`, async () => {
        const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid", params: { goiabada_safe_mode: value } });
        try {
          await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
          expect(await pageToken(signIn.page, "canvas"), "the palette, not safe mode's colors").toBe(warmBasicPalette.light.canvas);
          await expect(signIn.page.locator('link[rel="stylesheet"][href*="/safe-stylesheet.css"]')).toHaveCount(0);
        } finally {
          await signIn.context.close();
        }
      });
    }

    // Twice: an invalid request, answered at the redirect URI (RFC 6749 section 3.1).
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      const tab = await context.newPage();
      const { params } = codeRequest(client.identifier);
      const pairs = [...Object.entries(params), ["goiabada_safe_mode", "true"], ["goiabada_safe_mode", "true"]];
      await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(pairs)}`);
      await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));
      expectAuthorizeError(new URL(tab.url()), "invalid_request", params.state);
    } finally {
      await context.close();
    }
  });
});
