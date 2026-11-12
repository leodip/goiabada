// A brand's custom palette set in the brand editor's Colors section (#815 decisions 7 and 8): a basic
// and an advanced palette saved, then seen on the sign-in page of a client given the brand, under a
// device asking for light and for dark; each value that is not a color marked at its field and the
// save refused there, the field focused and keeping what was typed; and a column the appearance hides,
// shown again while it holds a value that is not a color.
//
// The brands are the test's own, given to clients of the test's own, so no other page changes, and
// this is an ordinary parallel spec. The console drawn in a custom palette is brands.system.ts's.
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandIdFromList,
  brandRow,
  brandUrl,
  deleteBrand,
  expectDrawnInPalette,
  fillBrandForm,
  newBrandUrl,
  paletteColumnHead,
  paletteField,
  paletteNote,
  plumCanvas,
  warmBasicPalette,
  withCustomBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { expect, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// The message a field holding a value that is not a color shows under it.
const notAColor = "Enter # and six hexadecimal digits, such as #2456c4.";

test("a basic palette saved in the editor draws a client's sign-in page in its four colors, light and dark", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  await withCustomBrand(page, "auto", warmBasicPalette, async (brand) => {
    // The brand's page holds the palette as entered, in Basic.
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator("#theme-custom")).toBeChecked();
    await expect(page.locator("#paletteMode-basic")).toBeChecked();
    await expect(page.locator("#brand-palette")).toBeVisible();
    for (const mode of ["light", "dark"] as const) {
      for (const [token, value] of Object.entries(warmBasicPalette[mode])) await expect(paletteField(page, mode, token)).toHaveValue(value);
    }
    // The 19 other rows are Advanced's.
    await expect(page.locator("[data-palette-row]:visible")).toHaveCount(4);

    await setClientBrand(page, client.id, brand);
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      await expectDrawnInPalette(signIn.page, "light", warmBasicPalette.light);
      await expectDrawnInPalette(signIn.page, "dark", warmBasicPalette.dark);
    } finally {
      await signIn.context.close();
    }
  });
});

test("an advanced palette copied from a built-in theme and changed draws a client's sign-in page in every color set, light and dark", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "auto" });
  await page.locator("#theme-custom").check();
  await page.locator("#paletteMode-advanced").check();
  await expect(page.locator("[data-palette-row]:visible")).toHaveCount(23);

  // Copy colors from asks nothing and fills both modes; then four colors are changed by hand.
  await page.locator("#paletteCopyFrom").selectOption("plum");
  await page.locator("#paletteCopy").click();
  await expect(page.locator("#paletteCopyStatus")).toHaveText("Colors copied. Save the brand to use them.");
  await expect(paletteField(page, "light", "canvas")).toHaveValue("#f6f4f7");
  const changed = { light: { "brand-soft": "#ffe8cc", "note-ink": "#123456" }, dark: { focus: "#ffcc00", "caution-soft": "#2a1e00" } };
  for (const mode of ["light", "dark"] as const) {
    for (const [token, value] of Object.entries(changed[mode])) await paletteField(page, mode, token).fill(value);
  }
  // The well beside a field follows what is typed.
  await expect(page.locator("#palette-dark-focus-well")).toHaveValue("#ffcc00");
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/settings\/branding$/);

  await expect(brandRow(page, name)).toContainText("Custom");
  const id = await brandIdFromList(page, name);
  try {
    await page.goto(brandUrl(id, "edit"));
    await expect(page.locator("#paletteMode-advanced")).toBeChecked();
    await expect(paletteField(page, "light", "note-ink")).toHaveValue("#123456");

    await setClientBrand(page, client.id, { name });
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      // The changed colors, and the ones kept from Plum, whose canvas is the page's background.
      await expectDrawnInPalette(signIn.page, "light", changed.light);
      await expectDrawnInPalette(signIn.page, "dark", changed.dark);
      await signIn.page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
      expect(await signIn.page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(plumCanvas.light);
      await signIn.page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
      expect(await signIn.page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(plumCanvas.dark);
    } finally {
      await signIn.context.close();
    }
  } finally {
    await deleteBrand(page, id);
  }
});

// Each value that is not # and six hexadecimal digits: three digits, a name, no #, and eight digits,
// in Basic and in Advanced, in each column.
for (const refusal of [
  { mode: "basic", column: "light", token: "canvas", value: "#abc" },
  { mode: "basic", column: "dark", token: "brand", value: "navy" },
  { mode: "advanced", column: "light", token: "on-danger", value: "123456" },
  { mode: "advanced", column: "dark", token: "note-soft", value: "#12345678" },
] as const) {
  test(`a ${refusal.mode} palette's ${refusal.column} ${refusal.token} of ${refusal.value} is marked at its field, and the save refused there`, async ({ page }) => {
    await page.goto(newBrandUrl);
    await fillBrandForm(page, { name: uniqueIdentifier("brand"), appearance: "auto" });
    await page.locator("#theme-custom").check();
    await page.locator(`#paletteMode-${refusal.mode}`).check();
    const field = paletteField(page, refusal.column, refusal.token);
    await field.fill(refusal.value);

    // Marked as it is typed, before any save.
    const message = page.locator(`#palette-${refusal.column}-${refusal.token}-error`);
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(message).toHaveText(notAColor);

    // The save is refused at the field, which takes the focus and keeps what was typed.
    await page.locator("#btnCreate").click();
    await expect(page.locator("#brand-error")).toContainText(`${refusal.column} ${refusal.token} color must be # and six hexadecimal digits`);
    await expect(page).toHaveURL(newBrandUrl);
    await expect(field).toBeFocused();
    await expect(field).toHaveValue(refusal.value);
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(field).toHaveAttribute("aria-describedby", `brand-error palette-${refusal.column}-${refusal.token}-error`);
    await expect(message).toBeVisible();

    // A color typed in its place clears the mark.
    await field.fill("#2456C4");
    await expect(field).not.toHaveAttribute("aria-invalid", "true");
    await expect(message).toBeHidden();
    await expect(page.locator(`#palette-${refusal.column}-${refusal.token}-well`)).toHaveValue("#2456c4");
  });
}

test("a column the appearance hides comes back while it holds a value that is not a color", async ({ page }) => {
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name: uniqueIdentifier("brand"), appearance: "auto" });
  await page.locator("#theme-custom").check();

  // Automatic shows both columns; Light hides the Dark one and says its colors are kept.
  await expect(paletteColumnHead(page, "light")).toBeVisible();
  await expect(paletteColumnHead(page, "dark")).toBeVisible();
  await fillBrandForm(page, { appearance: "light" });
  await expect(paletteColumnHead(page, "dark")).toBeHidden();
  await expect(paletteField(page, "dark", "brand")).toBeHidden();
  await expect(paletteNote(page, "unused", "dark")).toHaveText("The dark colors are kept, and are not used while the appearance is Light.");

  // Under Automatic something that is not a color is typed in a Dark field, and the appearance is
  // changed to Light: the column stays, saying its colors must be colors.
  await fillBrandForm(page, { appearance: "auto" });
  await paletteField(page, "dark", "brand").fill("#12");
  await fillBrandForm(page, { appearance: "light" });
  await expect(paletteColumnHead(page, "dark")).toBeVisible();
  await expect(paletteField(page, "dark", "brand")).toBeVisible();
  await expect(paletteNote(page, "unused", "dark")).toBeHidden();
  const mustBeValid = "The dark colors are not drawn while the appearance is Light, but each must be a color for the brand to be saved.";
  await expect(paletteNote(page, "invalid", "dark")).toHaveText(mustBeValid);

  // Saved like that, the refusal is at the field, in the column drawn again for it.
  await page.locator("#btnCreate").click();
  await expect(page.locator("#brand-error")).toContainText("dark brand color");
  await expect(page.locator("#appearance-light")).toBeChecked();
  await expect(paletteColumnHead(page, "dark")).toBeVisible();
  await expect(paletteNote(page, "invalid", "dark")).toHaveText(mustBeValid);
  await expect(paletteField(page, "dark", "brand")).toBeFocused();
  await expect(paletteField(page, "dark", "brand")).toHaveValue("#12");

  // Once it is a color the column stays until the next change of appearance, and hides then.
  await paletteField(page, "dark", "brand").fill("#8ab4ff");
  await expect(paletteColumnHead(page, "dark")).toBeVisible();
  await fillBrandForm(page, { appearance: "auto" });
  await fillBrandForm(page, { appearance: "light" });
  await expect(paletteColumnHead(page, "dark")).toBeHidden();
  await expect(paletteNote(page, "unused", "dark")).toBeVisible();
  // The hidden column keeps its colors, which are sent unchanged.
  await expect(paletteField(page, "dark", "brand")).toHaveValue("#8ab4ff");
});
