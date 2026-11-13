// Safe mode on the admin console (#816 decision 2). The console's own client is given a brand that
// holds all three things safe mode sets aside: custom CSS, a custom palette and an uploaded font. A
// browser opening a console URL with goiabada_safe_mode=true signs in on safe pages, and its console
// session stays in safe mode: the admin pages link the brand's safe colors-only stylesheet, are drawn in
// Blueberry in place of the palette and say safe mode is on, and the Account pages draw neither the CSS
// nor the font. Signing out ends it. The console's home page opened with the parameter starts its
// sign-ins in safe mode too. Runs alone, since the console's own client's brand is what every
// console page is drawn in, and puts it back.
import type { Page } from "@playwright/test";
import { expect, test } from "../../../lib/fixtures";
import {
  clientIdFromList,
  safeModeNotice,
  safeModeSessionNotice,
  setClientBrand,
  signOutOfConsole,
} from "../../../lib/admin-console";
import {
  brandUrl,
  brandingPath,
  customCssField,
  expectDrawnInPalette,
  fillBrandForm,
  firstFontOf,
  kitFiles,
  pageToken,
  uploadInEditor,
  warmBasicPalette,
  withCustomBrand,
} from "../../../lib/brands";
import { submitPassword } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";

const underlined = "rgb(18, 52, 86)";
const customCss = `.page-title, .auth-title {\n  text-decoration: underline wavy ${underlined};\n}\n`;
const blueberryCanvas = "#f4f5f7";

// The brand stylesheet a page links, by the last part of its path: stylesheet, colors, safe-stylesheet
// or safe-colors.
function linkedBrandStylesheets(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]'))
      .map((link) => new URL(link.href, document.baseURI).pathname.match(/^\/brand\/\d+\/([a-z-]+)\.css$/)?.[1])
      .filter((kind): kind is string => kind !== undefined),
  );
}

async function titleDecoration(page: Page, selector: string): Promise<string> {
  return page.locator(selector).first().evaluate((title) => getComputedStyle(title).textDecorationLine);
}

async function bodyFont(page: Page): Promise<string> {
  return firstFontOf(await page.evaluate(() => getComputedStyle(document.body).fontFamily));
}

test("a console URL with goiabada_safe_mode=true signs in on safe pages, keeps the console session in safe mode, and signing out ends it", async ({
  page,
  browser,
}) => {
  const consoleClient = await clientIdFromList(page, "admin-console-client");

  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    // The uploaded font and the custom CSS beside the palette.
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandForm(page, { font: "uploaded" });
    await uploadInEditor(page, "regularFont", kitFiles.regularFont);
    await customCssField(page).fill(customCss);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const admin = await context.newPage();
    // Whether admin holds a session of the administrator's. A failure signs it out too, so a failed
    // run leaves no session counting against the administrator's cap: closing the browser does not
    // end it.
    let signedIn = false;
    try {
      await setClientBrand(page, consoleClient, brand);

      // Out of safe mode, the console's sign-in draws all three.
      await admin.goto(`${env.adminUrl}${brandingPath}`);
      await expect(admin.locator('input[name="password"]')).toBeVisible();
      expect(await linkedBrandStylesheets(admin)).toEqual(["stylesheet"]);
      expect(await titleDecoration(admin, ".auth-title")).toBe("underline");
      await context.clearCookies();

      // The console URL with the parameter sends a sign-in in safe mode.
      await admin.goto(`${env.adminUrl}${brandingPath}?goiabada_safe_mode=true`);
      await expect(admin.locator('input[name="password"]')).toBeVisible();
      expect(new URL(admin.url()).origin, "the sign-in page is the auth server's").toBe(new URL(env.authUrl).origin);
      expect(await linkedBrandStylesheets(admin)).toEqual(["safe-stylesheet"]);
      expect(await titleDecoration(admin, ".auth-title"), "no custom CSS").toBe("none");
      expect(await pageToken(admin, "canvas"), "Blueberry's canvas").toBe(blueberryCanvas);
      expect(await bodyFont(admin), "not the uploaded font").not.toBe("brand-font");

      await submitPassword(admin, env.adminEmail, env.adminPassword);
      signedIn = true;
      await expect(admin).toHaveURL(`${env.adminUrl}${brandingPath}?goiabada_safe_mode=true`);

      // Every console page is in safe mode now, with no parameter: the admin pages say so and are
      // drawn in Blueberry, and the Account pages draw neither the CSS nor the font.
      for (const path of [brandingPath, "/admin/clients"]) {
        await admin.goto(`${env.adminUrl}${path}`);
        expect(await linkedBrandStylesheets(admin), path).toEqual(["safe-colors"]);
        await expect(safeModeNotice(admin)).toHaveText(safeModeSessionNotice);
        expect(await pageToken(admin, "canvas"), `${path}: Blueberry's canvas`).toBe(blueberryCanvas);
      }
      await admin.goto(`${env.adminUrl}/account/profile`);
      expect(await linkedBrandStylesheets(admin)).toEqual(["safe-stylesheet"]);
      await expect(safeModeNotice(admin), "the notice is on admin pages alone").toHaveCount(0);
      expect(await titleDecoration(admin, ".page-title"), "no custom CSS").toBe("none");
      expect(await bodyFont(admin), "not the uploaded font").not.toBe("brand-font");

      // Nothing stored changed: the editor still holds the CSS.
      await admin.goto(brandUrl(brand.id, "edit"));
      await expect(customCssField(admin)).toHaveValue(customCss);

      // Signing out ends it: the next sign-in is drawn in the brand as saved.
      await signOutOfConsole(admin);
      signedIn = false;
      await admin.goto(`${env.adminUrl}${brandingPath}`);
      await expect(admin.locator('input[name="password"]')).toBeVisible();
      expect(await linkedBrandStylesheets(admin)).toEqual(["stylesheet"]);
      await submitPassword(admin, env.adminEmail, env.adminPassword);
      signedIn = true;
      await expect(admin).toHaveURL(`${env.adminUrl}${brandingPath}`);
      expect(await linkedBrandStylesheets(admin)).toEqual(["colors"]);
      await expect(safeModeNotice(admin)).toHaveCount(0);
      await expectDrawnInPalette(admin, "light", warmBasicPalette.light);
      await admin.goto(`${env.adminUrl}/account/profile`);
      expect(await linkedBrandStylesheets(admin)).toEqual(["stylesheet"]);
      expect(await titleDecoration(admin, ".page-title")).toBe("underline");
      expect(await bodyFont(admin)).toBe("brand-font");
      await signOutOfConsole(admin);
      signedIn = false;

      // The console's home page opened with the parameter, signed out, starts a sign-in in safe mode
      // from its Administration link too, and the session it signs in to stays in safe mode.
      await admin.goto(`${env.adminUrl}/?goiabada_safe_mode=true`);
      expect(await linkedBrandStylesheets(admin)).toEqual(["safe-stylesheet"]);
      await admin.getByRole("link", { name: /^Administration/ }).click();
      await expect(admin.locator('input[name="password"]')).toBeVisible();
      expect(await linkedBrandStylesheets(admin), "the sign-in the home page starts is safe").toEqual(["safe-stylesheet"]);
      expect(await titleDecoration(admin, ".auth-title"), "no custom CSS").toBe("none");
      await submitPassword(admin, env.adminEmail, env.adminPassword);
      signedIn = true;
      await expect(admin).toHaveURL(`${env.adminUrl}/admin/clients?goiabada_safe_mode=true`);
      await admin.goto(`${env.adminUrl}/admin/clients`);
      expect(await linkedBrandStylesheets(admin)).toEqual(["safe-colors"]);
      await expect(safeModeNotice(admin)).toHaveText(safeModeSessionNotice);
      await signOutOfConsole(admin);
      signedIn = false;
    } finally {
      if (signedIn) {
        // The test's own failure is the one to report, so a sign-out that fails as well is let go.
        await signOutOfConsole(admin).catch(() => undefined);
      }
      await context.close();
      await setClientBrand(page, consoleClient, "default");
    }
  });
});
