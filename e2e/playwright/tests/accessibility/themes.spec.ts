// axe-core over a sign-in page drawn in each of the eight built-in themes (#810 decision 3), light and
// dark: the console says the built-in themes meet WCAG 2.2 level AA (#815 decision 3), and this holds
// each to it in a browser, beside the unit tier's contrast test of their palettes. Each page is
// checked as it is first drawn and once a wrong password is refused, which draws the danger notice
// and the invalid field. The page is drawn in the theme the stylesheet names: its canvas and its
// brand color are the theme's own.
//
// Each theme is a brand of the test's own, on Automatic, given to a client of its own, so no other
// page changes, and this is an ordinary parallel spec.
import type { Page } from "@playwright/test";
import { setClientBrand } from "../../lib/admin-console";
import { checkStates, titled } from "../../lib/axe";
import { pageToken, withBrand } from "../../lib/brands";
import { openSignIn, submitPassword } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";

// Each theme's canvas and brand color in light and in dark, as the palettes approved for #810 hold
// them (brandthemes/presets.go).
const themes: Record<string, { light: [string, string]; dark: [string, string] }> = {
  blueberry: { light: ["#f4f5f7", "#2456c4"], dark: ["#0f1217", "#8ab4ff"] },
  blackberry: { light: ["#f5f5f6", "#3b414c"], dark: ["#111214", "#c8ccd6"] },
  avocado: { light: ["#f3f6f4", "#1f6b43"], dark: ["#0e1411", "#7fd3a0"] },
  plum: { light: ["#f6f4f7", "#7a3aa8"], dark: ["#120f15", "#cda4f0"] },
  tangerine: { light: ["#f8f5f2", "#a84d08"], dark: ["#15110e", "#ffb25c"] },
  guava: { light: ["#f8f4f6", "#b0206a"], dark: ["#151012", "#ff9ccb"] },
  coconut: { light: ["#f7f4ec", "#6f4a2a"], dark: ["#14110d", "#dcc0a0"] },
  "high-contrast": { light: ["#ffffff", "#0037a6"], dark: ["#000000", "#9ec5ff"] },
};

// The page's canvas and brand color under each scheme a device asks for.
async function drawnTheme(page: Page) {
  const read = async (colorScheme: "light" | "dark") => {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    return [await pageToken(page, "canvas"), await pageToken(page, "brand")];
  };
  const drawn = { light: await read("light"), dark: await read("dark") };
  await page.emulateMedia({ colorScheme: null, reducedMotion: null });
  return drawn;
}

for (const [theme, colors] of Object.entries(themes)) {
  test(`a sign-in page in ${theme} meets WCAG 2.2 AA in light and dark, refusing a password too`, async ({ page, browser, clients }) => {
    const { client } = await browserSignInClient(page, clients);
    await withBrand(page, { appearance: "auto", theme }, async (brand) => {
      await setClientBrand(page, client.id, brand);
      const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
      const own = signIn.page;
      try {
        await expect(own).toHaveURL(/\/auth\/pwd/);
        expect(await drawnTheme(own), `the page is drawn in ${theme}`).toEqual(colors);
        await checkStates(own, [
          titled(own, `sign-in in ${theme}`, "Sign in", async () => {}),
          {
            name: `sign-in in ${theme}, a wrong password refused`,
            reach: async () => {
              await submitPassword(own, "nobody@example.com", "not-the-password");
              await expect(own.locator('input[name="password"][aria-invalid="true"], .notice-danger').first()).toBeVisible();
            },
          },
        ]);
      } finally {
        await signIn.context.close();
      }
    });
  });
}
