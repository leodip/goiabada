// Settings - Branding: brands created, edited and deleted, each refusal on the field it is about, the
// default marked and not deletable, and another brand made the default, which draws the console and
// the sign-in pages in its theme and appearance at once. The admin console's own client given a brand
// (#812) draws the console and its sign-in in it, while another client's sign-in keeps the default,
// and the Branding list counts the clients each brand draws; given a brand in a custom palette (#815),
// it draws its admin pages, its Account pages and its sign-in in the palette's colors. Runs alone,
// since the default brand and
// the console's own client's brand are what every page is drawn in, and puts back what it found.
import type { Browser, Page } from "@playwright/test";
import { expect, test } from "../../../lib/fixtures";
import { clientBrandChoice, clientIdFromList, expectRefusal, setClientBrand } from "../../../lib/admin-console";
import {
  brandClientCounts,
  brandUrl,
  brandingUrl,
  createBrand,
  defaultBrand,
  deleteBrand,
  expectDrawnInPalette,
  expectDrawnInPlumDark,
  expectDrawnInSeededDefault,
  fillBrandForm,
  listBrands,
  makeBrandDefault,
  pageBackgrounds as backgrounds,
  pageBrandStylesheets,
  plumCanvas,
  readBrand,
  saveBrand,
  submitNewBrand,
  warmBasicPalette,
  withBrand,
  withCustomBrand,
  withDefaultBrandRestored,
  type Appearance,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// A page drawn in Plum with this appearance: Light and Dark name themselves on the root element and
// keep their colors whatever the device asks, and Automatic names none and follows the device, as the
// color-scheme meta's "light dark" says.
async function expectDrawnInPlum(page: Page, appearance: Appearance) {
  const html = page.locator("html");
  if (appearance === "auto") await expect(html).not.toHaveAttribute("data-theme");
  else await expect(html).toHaveAttribute("data-theme", appearance);
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute("content", appearance === "auto" ? "light dark" : appearance);

  const { onLight, onDark } = await backgrounds(page);
  if (appearance === "auto") {
    expect(onLight, "Automatic draws Plum's light canvas on a light device").toBe(plumCanvas.light);
    expect(onDark, "and its dark canvas on a dark device").toBe(plumCanvas.dark);
  } else {
    expect(onLight, `${appearance} on a light device`).toBe(plumCanvas[appearance]);
    expect(onDark, `${appearance} on a dark device`).toBe(plumCanvas[appearance]);
  }
}

// The sign-in page, as a browser that holds no session sees it.
async function expectSignInDrawnInPlum(browser: Browser, appearance: Appearance) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  try {
    const signIn = await context.newPage();
    await signIn.goto(`${env.adminUrl}/account/profile`);
    await expect(signIn.locator('input[name="password"]')).toBeVisible();
    expect(new URL(signIn.url()).origin, "the sign-in page is the auth server's").toBe(new URL(env.authUrl).origin);
    await expectDrawnInPlum(signIn, appearance);
  } finally {
    await context.close();
  }
}

test("a brand is created, edited and deleted, and each refusal is shown on its field", async ({ page }) => {
  const name = uniqueIdentifier("brand");
  let id: number | undefined;
  try {
    // Refused on the new form, each at its field, the form keeping what was sent.
    for (const { typed, message } of [
      { typed: "", message: "Name is required." },
      { typed: "x".repeat(61), message: "The name cannot exceed a maximum length of 60 characters." },
      { typed: "<b>Brand</b>", message: "The name cannot contain the characters < or >." },
    ]) {
      await submitNewBrand(page, { name: typed, appearance: "dark", theme: "plum" });
      await expectRefusal(page, "brand-error", "name", message);
      await expect(page.locator("#appearance-dark")).toBeChecked();
      await expect(page.locator("#theme-plum")).toBeChecked();
    }

    id = await createBrand(page, { name, appearance: "dark", theme: "plum" });
    const row = page.locator("#brandsTable tbody tr", { has: page.getByRole("link", { name, exact: true }) });
    await expect(row).toContainText("Dark");
    await expect(row).toContainText("Plum");
    await expect(row.locator(".tag")).toHaveCount(0);

    // Another brand's name is refused, on create and on rename.
    const seeded = await defaultBrand(page);
    await submitNewBrand(page, { name, appearance: "auto", theme: "blueberry" });
    await expectRefusal(page, "brand-error", "name", "Another brand already uses this name.");
    await page.goto(brandUrl(id, "edit"));
    await fillBrandForm(page, { name: seeded.name });
    await page.locator("#btnSave").click();
    await expectRefusal(page, "brand-error", "name", "Another brand already uses this name.");

    // An appearance or a theme the auth server does not know, as a page older than its list could
    // send, is refused at its choice, the first card focused.
    for (const { group, message } of [
      { group: "appearance", message: "Choose automatic, light or dark." },
      { group: "theme", message: "Choose one of the built-in themes." },
    ]) {
      await page.goto(brandUrl(id, "edit"));
      await page.locator(`input[name="${group}"]:checked`).evaluate((radio) => ((radio as HTMLInputElement).value = "sepia"));
      await page.locator("#btnSave").click();
      const first = group === "appearance" ? "appearance-auto" : "theme-blueberry";
      await expectRefusal(page, "brand-error", first, message);
    }
    expect(await readBrand(page, id), "nothing refused was stored").toEqual({ name, appearance: "dark", theme: "plum" });

    // Edited: the three fields saved, and the page drawn again with them.
    await saveBrand(page, id, { name: `${name}-2`, appearance: "light", theme: "avocado" });
    expect(await readBrand(page, id)).toEqual({ name: `${name}-2`, appearance: "light", theme: "avocado" });

    // Deleted by typing its name; anything else is refused at the field. No client uses it, and the
    // page says so.
    await page.goto(brandUrl(id, "delete"));
    await expect(page.locator(".page-lead")).toHaveText("The brand will be deleted. No client uses it, so no page will change.");
    await page.locator("#name").fill(name);
    await page.locator("#btnDelete").click();
    await expectRefusal(page, "delete-error", "name", "That isn't this brand's name. Type it as shown above.");
    await deleteBrand(page, id);
    id = undefined;
    expect((await listBrands(page)).map((brand) => brand.name)).not.toContain(`${name}-2`);
  } finally {
    if (id !== undefined) await deleteBrand(page, id);
  }
});

test("the default brand is marked, and is not deletable", async ({ page }) => {
  const brands = await listBrands(page);
  const defaults = brands.filter((brand) => brand.isDefault);
  expect(defaults).toHaveLength(1);
  const row = page.locator("#brandsTable tbody tr", { has: page.getByRole("link", { name: defaults[0].name, exact: true }) });
  await expect(row.locator(".tag")).toHaveText("Default");
  await expect(row.getByRole("link", { name: /^Delete/ })).toHaveCount(0);

  // Its delete page says why and offers nothing to delete it with.
  await page.goto(brandUrl(defaults[0].id, "delete"));
  await expect(page.locator(".notice-caution")).toContainText("The default brand cannot be deleted. Make another brand the default first.");
  await expect(page.locator("#btnDelete")).toHaveCount(0);
  await expect(page.locator("#name")).toHaveCount(0);
});

test("another brand made the default draws the console and the sign-in pages in its theme and appearance, and automatic follows the device", async ({
  page,
  browser,
}) => {
  const name = uniqueIdentifier("brand");
  let id: number | undefined;
  try {
    await withDefaultBrandRestored(page, async () => {
      const previous = await defaultBrand(page);
      id = await createBrand(page, { name, appearance: "dark", theme: "plum" });

      // Stored but drawn nowhere while no client uses it and it is not the default.
      await page.goto(brandUrl(id, "edit"));
      expect((await backgrounds(page)).onDark).not.toBe(plumCanvas.dark);

      // Cancel asks nothing more, and changes nothing.
      await page.locator("#btnMakeDefault").click();
      await page.locator("dialog[open]").getByRole("button", { name: "Cancel", exact: true }).click();
      expect((await defaultBrand(page)).id).toBe(previous.id);

      await makeBrandDefault(page, id);
      await expect(page.locator("#btnMakeDefault")).toHaveCount(0);
      const brands = await listBrands(page);
      expect(brands.filter((brand) => brand.isDefault).map((brand) => brand.id)).toEqual([id]);
      // The brand that was the default can now be deleted, and the new default cannot.
      await expect(page.locator(`a[href="${new URL(brandUrl(previous.id, "delete")).pathname}"]`)).toHaveCount(1);
      await expect(page.locator(`a[href="${new URL(brandUrl(id, "delete")).pathname}"]`)).toHaveCount(0);

      for (const appearance of ["dark", "light", "auto"] as const) {
        if (appearance !== "dark") await saveBrand(page, id, { appearance });
        await page.goto(brandingUrl);
        await expectDrawnInPlum(page, appearance);
        await expectSignInDrawnInPlum(browser, appearance);
      }
    });
    expect((await defaultBrand(page)).name, "the default brand found is the default again").not.toBe(name);
  } finally {
    if (id !== undefined) await deleteBrand(page, id);
  }
});

test("the list says how the brands are used, and the default brand's page says what it draws", async ({ page }) => {
  await page.goto(brandingUrl);
  await expect(page.locator(".page-lead")).toHaveText(
    "A client's pages are drawn in the brand chosen on its Settings tab, or in the default brand when none is chosen. This admin console is drawn in the brand of its own client.",
  );
  await expect(page.locator("#brandsTable thead th").nth(3)).toHaveText("Clients");

  const seeded = await defaultBrand(page);
  await page.goto(brandUrl(seeded.id, "edit"));
  await expect(page.locator(".page-lead")).toContainText(
    "This is the default brand. The pages of every client with no brand of its own are drawn in it, and so are pages that belong to no client.",
  );
  // Make default's question on another brand says what will change.
  await withBrand(page, { appearance: "light", theme: "avocado" }, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await page.locator("#btnMakeDefault").click();
    const dialog = page.locator("dialog[open]");
    await expect(dialog).toContainText(
      "The pages of every client with no brand of its own, and pages that belong to no client, will be drawn in this brand at once.",
    );
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect((await defaultBrand(page)).id).toBe(seeded.id);
  });
});

test("the admin console's own client given a brand draws the console and its sign-in in it, another client's sign-in keeps the default, and it is put back", async ({
  page,
  browser,
  clients,
}) => {
  const { client: other } = await browserSignInClient(page, clients);
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const seeded = await defaultBrand(page);
  const onDefault = `Default brand (${seeded.name})`;
  expect(await clientBrandChoice(page, consoleClient), "the console's client starts on the default brand").toBe(onDefault);
  const before = await brandClientCounts(page);

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    try {
      await setClientBrand(page, consoleClient, brand);

      // The console takes it at once, its own pages and its sign-in.
      await page.goto(brandingUrl);
      await expectDrawnInPlumDark(page, brand.id);
      const signIn = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const consoleSignIn = await signIn.newPage();
      await consoleSignIn.goto(`${env.adminUrl}/account/profile`);
      await expect(consoleSignIn.locator('input[name="password"]')).toBeVisible();
      expect(new URL(consoleSignIn.url()).origin, "the sign-in page is the auth server's").toBe(new URL(env.authUrl).origin);
      await expectDrawnInPlumDark(consoleSignIn, brand.id);
      await signIn.close();

      // Another client's sign-in keeps the default.
      const elsewhere = await openSignIn(browser, { clientId: other.identifier, scope: "openid" });
      await expect(elsewhere.page).toHaveURL(/\/auth\/pwd/);
      await expectDrawnInSeededDefault(elsewhere.page, seeded.id);
      await elsewhere.context.close();

      // The list counts the console's client under its brand, and no longer under the default.
      const counts = await brandClientCounts(page);
      expect(counts[brand.name]).toBe(1);
      expect(counts[seeded.name]).toBe(before[seeded.name] - 1);
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }

    // Put back: the console is drawn in the default again, and the brand draws no client.
    expect(await clientBrandChoice(page, consoleClient)).toBe(onDefault);
    await page.goto(brandingUrl);
    await expectDrawnInSeededDefault(page, seeded.id);
    const counts = await brandClientCounts(page);
    expect(counts[brand.name]).toBe(0);
    expect(counts[seeded.name]).toBe(before[seeded.name]);
  });
});

test("the admin console's own client given a brand in a custom palette draws the console's admin and Account pages and its sign-in in the palette's colors, and it is put back", async ({
  page,
  browser,
}) => {
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const seeded = await defaultBrand(page);

  // Automatic, so each scheme a device asks for draws its mode of the palette.
  await withCustomBrand(page, "auto", warmBasicPalette, async (brand) => {
    try {
      await setClientBrand(page, consoleClient, brand);

      // An admin page links the brand's colors-only stylesheet, an Account page its full one, and
      // both are drawn in the palette.
      await page.goto(brandingUrl);
      expect(await pageBrandStylesheets(page)).toEqual([{ brandId: brand.id, kind: "colors" }]);
      await expectDrawnInPalette(page, "light", warmBasicPalette.light);
      await expectDrawnInPalette(page, "dark", warmBasicPalette.dark);
      await page.goto(`${env.adminUrl}/account/profile`);
      expect(await pageBrandStylesheets(page)).toEqual([{ brandId: brand.id, kind: "full" }]);
      await expectDrawnInPalette(page, "light", warmBasicPalette.light);
      await expectDrawnInPalette(page, "dark", warmBasicPalette.dark);

      // The console's sign-in, the auth server's page, too.
      const signIn = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const consoleSignIn = await signIn.newPage();
      await consoleSignIn.goto(`${env.adminUrl}/account/profile`);
      await expect(consoleSignIn.locator('input[name="password"]')).toBeVisible();
      await expectDrawnInPalette(consoleSignIn, "light", warmBasicPalette.light);
      await expectDrawnInPalette(consoleSignIn, "dark", warmBasicPalette.dark);
      await signIn.close();
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }

    // Put back: the console is drawn in the default again.
    await page.goto(brandingUrl);
    await expectDrawnInSeededDefault(page, seeded.id);
  });
});
