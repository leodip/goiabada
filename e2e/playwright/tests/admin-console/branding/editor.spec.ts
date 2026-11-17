// The brand editor's rules beside brands.system.ts's, on brands of the test's own (#810, #812, #813,
// #815): a corner shape, a font family or a background fit the auth server does not know, as a page
// older than its list could send, is refused at its choice; the delete page refuses an empty name; two
// clients using a brand are counted in the plural; a custom palette saved over with a built-in theme
// is gone, so Custom starts again from that theme's colors; and a custom palette on Dark draws its
// dark colors whatever the device asks.
//
// The brands and the clients are the test's own, so no other page changes, and this is an ordinary
// parallel spec.
import { expectRefusal, setClientBrand } from "../../../lib/admin-console";
import {
  brandingUrl,
  brandRow,
  brandUrl,
  defaultBrand,
  expectDrawnInPalette,
  fillBrandForm,
  paletteField,
  readBrand,
  warmBasicPalette,
  withBrand,
  withCustomBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { expect, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";

test("a corner shape, a font family or a background fit the auth server does not know is refused at its choice, and nothing is stored", async ({
  page,
}) => {
  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    for (const { what, choice, field, message } of [
      { what: "corners", choice: 'input[name="corners"]:checked', field: "corners-square", message: "Choose square, rounded or pill corners." },
      { what: "font", choice: "#font option:checked", field: "font", message: "Choose one of the system font families, or the uploaded font." },
      {
        what: "background fit",
        choice: 'input[name="backgroundFit"]:checked',
        field: "backgroundFit-cover",
        message: "Choose cover, contain or tile for the background image.",
      },
    ]) {
      await test.step(what, async () => {
        await page.goto(brandUrl(brand.id, "edit"));
        await page.locator(choice).evaluate((element) => ((element as HTMLInputElement | HTMLOptionElement).value = "sepia"));
        await page.locator("#btnSave").click();
        await expectRefusal(page, "brand-error", field, message);
      });
    }
    expect(await readBrand(page, brand.id), "nothing refused was stored").toEqual({ name: brand.name, appearance: "dark", theme: "plum" });
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator("#corners-rounded")).toBeChecked();
    await expect(page.locator("#font")).toHaveValue("system-ui");
    await expect(page.locator("#backgroundFit-cover")).toBeChecked();
  });
});

test("the delete page refuses an empty name, and counts two clients using the brand in the plural", async ({ page, clients }) => {
  const first = await clients.create();
  const second = await clients.create();
  const seeded = await defaultBrand(page);
  await withBrand(page, { appearance: "light", theme: "avocado" }, async (brand) => {
    await setClientBrand(page, first.id, brand);
    await setClientBrand(page, second.id, brand);

    await page.goto(brandingUrl);
    await expect(brandRow(page, brand.name).locator('td[data-label="Clients"]')).toHaveText("2");
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator(".page-lead")).toHaveText("Choose it on a client's Settings tab to draw that client's pages in it. 2 clients use this brand.");

    await page.goto(brandUrl(brand.id, "delete"));
    await expect(page.locator(".page-lead")).toHaveText(
      `The brand will be deleted. 2 clients use it. They will move to the default brand, ${seeded.name}.`,
    );
    await page.locator("#btnDelete").click();
    await expectRefusal(page, "delete-error", "name", "Type the brand's name to confirm.");
    await expect(page).toHaveURL(brandUrl(brand.id, "delete"));
  });
});

test("a custom palette saved over with a built-in theme is gone, and Custom starts again from that theme's colors", async ({ page }) => {
  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandForm(page, { theme: "plum" });
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();

    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator("#theme-plum")).toBeChecked();
    await page.locator("#theme-custom").check();
    await expect(page.locator("#paletteMode-basic")).toBeChecked();
    // Plum's light canvas and brand color, not the palette saved before.
    await expect(paletteField(page, "light", "canvas")).toHaveValue("#f6f4f7");
    await expect(paletteField(page, "light", "brand")).toHaveValue("#7a3aa8");
  });
});

test("a custom palette on Dark draws its dark colors whatever the device asks", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  await withCustomBrand(page, "dark", warmBasicPalette, async (brand) => {
    await setClientBrand(page, client.id, brand);
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      await expect(signIn.page.locator("html")).toHaveAttribute("data-theme", "dark");
      await expectDrawnInPalette(signIn.page, "light", warmBasicPalette.dark);
      await expectDrawnInPalette(signIn.page, "dark", warmBasicPalette.dark);
    } finally {
      await signIn.context.close();
    }
  });
});
