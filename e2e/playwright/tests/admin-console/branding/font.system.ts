// The admin console drawn in a brand's uploaded font (#813): the console's own client given a brand
// whose font is a real WOFF2, a regular and a bold file made on the spot (lib/woff2.ts). The console's
// end-user pages, an Account page and home, link the brand's full stylesheet from the auth server, so
// the browser fetches the font from the auth server's origin: each face loads, which takes the auth
// server's answer naming the console's origin, and text set in it measures the font's own width. Its
// admin pages link the colors-only stylesheet and load no font. The console's own client's brand is
// what every console page is drawn in, so this runs alone, and puts the client back on the default
// brand.
import { clientIdFromList, setClientBrand } from "../../../lib/admin-console";
import { brandIdFromList, brandingUrl, deleteBrand, fillBrandForm, listBrands, newBrandUrl, uploadInEditor } from "../../../lib/brands";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";
import { drawnProbeFont, probeBold, probeFontFile, probeRegular, probeTextWidth } from "../../../lib/woff2";

function expectWidth(measured: number, want: number, what: string) {
  expect(Math.abs(measured - want), `${what}: ${measured}px, want ${want}px`).toBeLessThanOrEqual(2);
}

test("the admin console's own client given a brand with an uploaded font draws it on the console's end-user pages, fetched from the auth server, and not on its admin pages", async ({
  page,
}) => {
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const name = uniqueIdentifier("brand");
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "auto", theme: "avocado", font: "uploaded" });
  const regular = await uploadInEditor(page, "regularFont", probeFontFile("probe-regular.woff2", probeRegular));
  const bold = await uploadInEditor(page, "boldFont", probeFontFile("probe-bold.woff2", probeBold));
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(brandingUrl);
  const id = await brandIdFromList(page, name);

  try {
    // The files are the auth server's, so a console page fetches them from another origin.
    for (const url of [regular, bold]) expect(new URL(url).origin, "the font is the auth server's").toBe(new URL(env.authUrl).origin);
    await setClientBrand(page, consoleClient, { name });

    for (const [where, path, inside] of [
      ["an Account page", "/account/profile", "main"],
      ["home", "/", ".auth-card"],
    ] as const) {
      await page.goto(`${env.adminUrl}${path}`);
      const font = await drawnProbeFont(page, inside);
      expect(font.faces, `${where}: each face of the brand's font loaded`).toEqual(["1 500 loaded", "501 1000 loaded"]);
      expectWidth(font.regular, probeTextWidth(probeRegular), `${where}: regular text`);
      expectWidth(font.bold, probeTextWidth(probeBold), `${where}: bold text`);
    }

    // An admin page links the colors-only stylesheet, which declares no font.
    await page.goto(brandingUrl);
    expect((await drawnProbeFont(page, "main")).faces, "an admin page loads no font").toEqual([]);
  } finally {
    await setClientBrand(page, consoleClient, "default");
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
});
