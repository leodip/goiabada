// A brand's uploaded font and its two logos, as each browser engine draws them (#813): the files
// are uploaded in the brand editor, and the brand given to a client of the test's own, whose sign-in
// page then draws them. The font is a real WOFF2 made on the spot (lib/woff2.ts), whose glyphs are
// boxes of a known width, so the page shows the browser fetched the file and drew with it: each face
// of the brand's family has loaded, and text set in it measures the font's own width, the bold file's
// for bold. How an engine reads a font and picks the source of a picture is its own code, so this
// spec runs in Chromium, Firefox and WebKit (playwright.config.ts).
//
// The brand is the test's own, given to a client of the test's own, so no other page changes, and
// this is an ordinary parallel spec. The console's Account pages, which load the font from the auth
// server's origin, are font.system.ts's.
import type { Browser, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import { type BrandSlot, brandIdFromList, deleteBrand, fillBrandForm, kitFiles, listBrands, newBrandUrl, uploadInEditor } from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";
import { drawnProbeFont, probeBold, probeFontFile, probeRegular, probeTextWidth } from "../../../lib/woff2";

// A width within two pixels of the one the font's advance gives: an engine drawing bold from a
// regular file alone thickens each glyph a little, as Firefox does.
function expectWidth(measured: number, want: number, what: string) {
  expect(Math.abs(measured - want), `${what}: ${measured}px, want ${want}px`).toBeLessThanOrEqual(2);
}

// The client's sign-in, opened in a browser of its own, at its password step.
async function openPasswordStep(browser: Browser, client: TestClient) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
  return signIn;
}

// Creates a brand in the editor with these files uploaded at their fields and the font uploaded,
// gives it to client, and answers its id.
async function brandWith(page: Page, client: TestClient, name: string, files: BrandSlot[]) {
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "auto", theme: "plum", font: "uploaded" });
  const urls: Record<string, string> = {};
  for (const slot of files) {
    const file =
      slot === "regularFont" ? probeFontFile("probe-regular.woff2", probeRegular) : slot === "boldFont" ? probeFontFile("probe-bold.woff2", probeBold) : kitFiles[slot];
    urls[slot] = await uploadInEditor(page, slot, file);
  }
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/settings\/branding$/);
  const id = await brandIdFromList(page, name);
  await setClientBrand(page, client.id, { name });
  return { id, urls };
}

test("a regular and a bold font uploaded in the editor are fetched and drawn on a client's sign-in page, and the logo follows the device", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");
  const { id, urls } = await brandWith(page, client, name, ["regularFont", "boldFont", "logo", "darkLogo"]);
  try {
    const signIn = await openPasswordStep(browser, client);
    try {
      // Both faces loaded: the regular one draws up to 500 and the bold one above.
      const font = await drawnProbeFont(signIn.page, ".auth-card");
      expect(font.faces, "each face of the brand's font loaded").toEqual(["1 500 loaded", "501 1000 loaded"]);
      expectWidth(font.regular, probeTextWidth(probeRegular), "regular text, in the regular file");
      expectWidth(font.bold, probeTextWidth(probeBold), "bold text, in the bold file");

      // The logo is a picture whose source the device's scheme picks.
      const logo = signIn.page.locator(".auth-logo img");
      for (const [colorScheme, want] of [["light", urls.logo], ["dark", urls.darkLogo], ["light", urls.logo]] as const) {
        await signIn.page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
        await expect.poll(() => logo.evaluate((img: HTMLImageElement) => img.currentSrc), `a ${colorScheme} device`).toBe(want);
        await expect.poll(() => logo.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth), "the logo is drawn").toBe(240);
      }
    } finally {
      await signIn.context.close();
    }
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
});

test("a regular font file alone is fetched and draws every weight", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");
  const { id } = await brandWith(page, client, name, ["regularFont"]);
  try {
    const signIn = await openPasswordStep(browser, client);
    try {
      // One face, with no weight of its own, so bold text is drawn from it too.
      const font = await drawnProbeFont(signIn.page, ".auth-card");
      expect(font.faces).toEqual(["normal loaded"]);
      expectWidth(font.regular, probeTextWidth(probeRegular), "regular text");
      expectWidth(font.bold, probeTextWidth(probeRegular), "bold text, drawn from the regular file");
    } finally {
      await signIn.context.close();
    }
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
});
