// A brand's custom palette set in the brand editor's Colors section (#815 decisions 7 and 8): a basic
// and an advanced palette saved, then seen on the sign-in page of a client given the brand, under a
// device asking for light and for dark; each value that is not a color marked at its field and the
// save refused there, the field focused and keeping what was typed; and a column the appearance hides,
// shown again while it holds a value that is not a color. A failing palette saved on an existing
// brand lists its failing pairs on the page the save returns to, which the saved notice links to, and
// one created is marked on the brand list it lands on (decision 9). While the colors are edited, the
// list is the console's live check of them, and changes as a color is typed; Advanced then holds the
// colors a basic palette works out; and when the check cannot be reached, the list says the colors
// could not be checked (decision 6). A save refused for another field keeps the list of the colors the
// form holds.
//
// The brands are the test's own, given to clients of the test's own, so no other page changes, and
// this is an ordinary parallel spec. The console drawn in a custom palette is brands.system.ts's.
import { expectRefusal, setClientBrand } from "../../../lib/admin-console";
import {
  brandIdFromList,
  brandingUrl,
  brandRow,
  brandUrl,
  brandWarningsMarker,
  deleteBrand,
  expectDrawnInPalette,
  failingBasicPalette,
  fillBrandForm,
  newBrandUrl,
  paletteColumnHead,
  paletteField,
  paletteNote,
  paletteWarningItems,
  paletteWarnings,
  paletteWarningsCount,
  plumCanvas,
  previewSample,
  sampleToken,
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

// The count line of more than one failing pair, and the brand list's marker of them; how many there
// are depends on the colors the save works out, so the number is any.
const manyPairsBelow = /^\d+ pairs are below their minimum\. Text and boundaries drawn in them do not meet WCAG 2\.2 level AA contrast\.$/;
const manyPairsMarker = /^\d+ pairs below contrast minimum$/;

// Text at #777777 on white is 4.47:1 when cut, below 4.5:1, on the background and on the card.
const textOnBackground = "Light: Text on Background, 4.47:1. Minimum 4.5:1.";
const textOnCard = "Light: Text on Card, 4.47:1. Minimum 4.5:1.";

test("a failing palette saved on an existing brand lists its failing pairs after the save, linked from the saved notice", async ({ page }) => {
  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await paletteField(page, "light", "ink").fill(failingBasicPalette.light.ink);
    await page.locator("#btnSave").click();
    await expect(page).toHaveURL(brandUrl(brand.id, "edit"));

    // The saved notice says pairs fail, and links to the list.
    const notice = page.locator(".notice-positive");
    await expect(notice).toContainText(/^Brand saved\. \d+ pairs of its colors are below their contrast minimum\. See the pairs$/);
    await notice.getByRole("link", { name: "See the pairs" }).click();
    await expect(page).toHaveURL(`${brandUrl(brand.id, "edit")}#palette-warnings`);

    // The list, at the foot of the Colors section, in the shared list's order: text on the background
    // first, then on the card, each beside a swatch of the pair. Under Light no dark pair is listed.
    await expect(paletteWarnings(page)).toBeVisible();
    await expect(paletteWarningsCount(page)).toHaveText(manyPairsBelow);
    await expect(paletteWarningsCount(page)).toHaveAttribute("role", "status");
    const items = paletteWarningItems(page);
    await expect(items.nth(0)).toHaveText(textOnBackground);
    await expect(items.nth(1)).toHaveText(textOnCard);
    await expect(items.filter({ hasText: /^Dark:/ })).toHaveCount(0);
    const fills = await items.nth(0).locator("svg rect").evaluateAll((rects) => rects.map((rect) => rect.getAttribute("fill")));
    expect(fills, "the background, then the text on it").toEqual(["#ffffff", "#777777"]);

    // The brand list marks the brand, and draws its swatch in the colors it is drawn in.
    await page.goto(brandingUrl);
    await expect(brandWarningsMarker(page, brand.name)).toHaveText(manyPairsMarker);
    await expect(brandRow(page, brand.name).locator('.brand-list-swatch svg').first().locator('[data-fill="ink"]')).toHaveAttribute("fill", "#777777");
  });
});

test("a brand created with a failing palette lands on the brand list, marked there, and its editor lists the pairs", async ({ page }) => {
  await withCustomBrand(page, "light", failingBasicPalette, async (brand) => {
    // withCustomBrand creates the brand and lands on the list, as any creation does, with no notice.
    await expect(page).toHaveURL(brandingUrl);
    await expect(page.locator(".notice-positive")).toHaveCount(0);
    await expect(brandWarningsMarker(page, brand.name)).toHaveText(manyPairsMarker);
    await expect(brandRow(page, brand.name).locator(".tag-note"), "it is not the default").toHaveCount(0);

    await page.goto(brandUrl(brand.id, "edit"));
    await expect(paletteWarningsCount(page)).toHaveText(manyPairsBelow);
    await expect(paletteWarningItems(page).nth(0)).toHaveText(textOnBackground);
  });
});

// The probe's "mid-gray brand color" palette (#815), with its six failing pairs and its worked-out
// colors as the probe's JavaScript computed them, before any Go existed: a mid-gray brand color fails
// as text on the page's light backgrounds, and white text fails on it.
const midGray = { canvas: "#f4f4f4", surface: "#ffffff", ink: "#222222", brand: "#777777" };
const midGrayPairs = [
  "Light: Brand color on Background, 4.07:1. Minimum 4.5:1.",
  "Light: Brand color on Card, 4.47:1. Minimum 4.5:1.",
  "Light: Text on brand color on Brand color, 4.47:1. Minimum 4.5:1.",
  "Light: Brand color on Subtle background, 3.82:1. Minimum 4.5:1.",
  "Light: Brand color on Soft note background, 3.81:1. Minimum 4.5:1.",
  "Light: Brand color on Soft caution background, 4.01:1. Minimum 4.5:1.",
];
const midGrayWorkedOut = { subtle: "#eeedeb", "line-strong": "#7d796c", "ink-muted": "#605e5a", "brand-strong": "#606060", danger: "#b42318" };
// Blueberry's own four light colors, which the probe rebuilt with no failing pair.
const blueberryFour = { canvas: "#f4f5f7", surface: "#ffffff", ink: "#1a1f29", brand: "#2456c4" };
const uncheckedLine = "The colors could not be checked. They are checked when the brand is saved.";

test("the list of failing pairs changes as a color is typed, and Advanced holds the colors worked out", async ({ page }) => {
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name: uniqueIdentifier("brand"), appearance: "light" });
  await page.locator("#theme-custom").check();
  await expect(page.locator("#paletteMode-basic")).toBeChecked();

  // The four colors typed: under Light, only light pairs are listed, in the shared list's order.
  for (const [token, value] of Object.entries(midGray)) await paletteField(page, "light", token).fill(value);
  await expect(paletteWarnings(page)).toBeVisible();
  await expect(paletteWarningsCount(page)).toHaveText(
    "6 pairs are below their minimum. Text and boundaries drawn in them do not meet WCAG 2.2 level AA contrast.",
  );
  await expect(paletteWarningItems(page)).toHaveText(midGrayPairs);

  // Advanced shows the colors the basic palette worked out, ready to adjust.
  await page.locator("#paletteMode-advanced").check();
  for (const [token, value] of Object.entries(midGrayWorkedOut)) await expect(paletteField(page, "light", token), token).toHaveValue(value);

  // Back in Basic, a color typed changes the list: Blueberry's four pass every pair.
  await page.locator("#paletteMode-basic").check();
  for (const [token, value] of Object.entries(blueberryFour)) await paletteField(page, "light", token).fill(value);
  await expect(paletteWarningsCount(page)).toHaveText("Every pair meets its minimum.");
  await expect(paletteWarningItems(page)).toHaveCount(0);

  // A value that is not a color is not checked: the list hides until it is one again.
  await paletteField(page, "light", "brand").fill("#2456c");
  await expect(paletteWarnings(page)).toBeHidden();
  await paletteField(page, "light", "brand").fill("#777777");
  // #777777 on #f4f5f7 is 4.10:1 (WCAG 2.2's relative luminance), written as the page writes a number.
  await expect(paletteWarningItems(page).filter({ hasText: "Light: Brand color on Background," })).toHaveText(
    "Light: Brand color on Background, 4.1:1. Minimum 4.5:1.",
  );
});

test("a save refused for its name lists the failing pairs of the colors the form keeps", async ({ page }) => {
  await withCustomBrand(page, "light", { mode: "basic", light: midGray, dark: warmBasicPalette.dark }, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(paletteWarningItems(page)).toHaveText(midGrayPairs);

    await page.locator("#name").fill("");
    await page.locator("#btnSave").click();
    await expectRefusal(page, "brand-error", "name", "Name is required.");
    await expect(paletteWarnings(page)).toBeVisible();
    await expect(paletteWarningsCount(page)).toHaveText(
      "6 pairs are below their minimum. Text and boundaries drawn in them do not meet WCAG 2.2 level AA contrast.",
    );
    await expect(paletteWarningItems(page)).toHaveText(midGrayPairs);
    // Checking the form as it stands works nothing out again: the colors stored stay in the fields.
    for (const [token, value] of Object.entries(midGrayWorkedOut)) await expect(paletteField(page, "light", token), token).toHaveValue(value);
  });
});

test("when the colors cannot be checked the page says so, and the sample keeps the colors typed", async ({ page }) => {
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name: uniqueIdentifier("brand"), appearance: "light" });
  await page.locator("#theme-custom").check();
  await expect(paletteWarningsCount(page)).toHaveText("Every pair meets its minimum.");

  await page.route("**/admin/settings/branding/palette-check*", (route) => route.abort("failed"));
  await paletteField(page, "light", "brand").fill("#7a3e00");
  await expect(paletteWarningsCount(page)).toHaveText(uncheckedLine);
  await expect(paletteWarningItems(page)).toHaveCount(0);
  expect(await sampleToken(previewSample(page, "light"), "brand")).toBe("#7a3e00");

  // Reached again, the next edit is checked.
  await page.unroute("**/admin/settings/branding/palette-check*");
  await paletteField(page, "light", "brand").fill("#2456c4");
  await expect(paletteWarningsCount(page)).toHaveText("Every pair meets its minimum.");
});
