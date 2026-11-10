// The brand editor's preview (#811): beside the form, a sample of a sign-in page drawn in the theme and
// appearance the form holds, before anything is saved. The appearance decides what it shows: Light and
// Dark their one sample with no switch, Automatic the sample the Light/Dark switch names, starting on
// Light. The Appearance cards' swatches follow the chosen theme too. The sample is an illustration: it
// cannot be focused, assistive technology skips it, and the page says in text what it shows.
//
// Everything here is on the New brand page and nothing is saved, so this is an ordinary parallel spec.
// A browser restores the form after Back without firing a change, each engine in its own way, so this
// file runs in Chromium, Firefox and WebKit (playwright.config.ts, #811 decision 5).
import type { Page } from "@playwright/test";
import {
  appearanceSwatchFills,
  brandPreview,
  brandingUrl,
  fillBrandForm,
  newBrandUrl,
  previewSample,
  previewSwitch,
  sampleColors,
  switchPreviewTo,
  type Appearance,
  type PreviewMode,
  type SampleColors,
} from "../../../lib/brands";
import { expect, test } from "../../../lib/fixtures";

// The colors a sample in each theme and mode is drawn in, from the palettes approved for #810, as a
// browser reports a computed color: the canvas, the card's surface, the primary button and its text,
// the invalid field's border, and the danger notice's background and text.
const lightStatus = { danger: "rgb(180, 35, 24)", dangerSoft: "rgb(253, 236, 235)", dangerInk: "rgb(143, 28, 19)" };
const darkStatus = { danger: "rgb(255, 143, 133)", dangerSoft: "rgb(58, 23, 20)", dangerInk: "rgb(255, 180, 171)" };
const approved: Record<string, Record<PreviewMode, SampleColors>> = {
  blueberry: {
    light: { canvas: "rgb(244, 245, 247)", surface: "rgb(255, 255, 255)", brand: "rgb(36, 86, 196)", onBrand: "rgb(255, 255, 255)", ...lightStatus, colorScheme: "light" },
    dark: { canvas: "rgb(15, 18, 23)", surface: "rgb(23, 27, 34)", brand: "rgb(138, 180, 255)", onBrand: "rgb(11, 26, 51)", ...darkStatus, colorScheme: "dark" },
  },
  plum: {
    light: { canvas: "rgb(246, 244, 247)", surface: "rgb(255, 255, 255)", brand: "rgb(122, 58, 168)", onBrand: "rgb(255, 255, 255)", ...lightStatus, colorScheme: "light" },
    dark: { canvas: "rgb(18, 15, 21)", surface: "rgb(26, 22, 31)", brand: "rgb(205, 164, 240)", onBrand: "rgb(42, 15, 64)", ...darkStatus, colorScheme: "dark" },
  },
  guava: {
    light: { canvas: "rgb(248, 244, 246)", surface: "rgb(255, 255, 255)", brand: "rgb(176, 32, 106)", onBrand: "rgb(255, 255, 255)", ...lightStatus, colorScheme: "light" },
    dark: { canvas: "rgb(21, 16, 18)", surface: "rgb(29, 23, 26)", brand: "rgb(255, 156, 203)", onBrand: "rgb(61, 10, 36)", ...darkStatus, colorScheme: "dark" },
  },
  "high-contrast": {
    light: {
      canvas: "rgb(255, 255, 255)",
      surface: "rgb(255, 255, 255)",
      brand: "rgb(0, 55, 166)",
      onBrand: "rgb(255, 255, 255)",
      danger: "rgb(163, 0, 0)",
      dangerSoft: "rgb(255, 229, 229)",
      dangerInk: "rgb(122, 0, 0)",
      colorScheme: "light",
    },
    dark: {
      canvas: "rgb(0, 0, 0)",
      surface: "rgb(0, 0, 0)",
      brand: "rgb(158, 197, 255)",
      onBrand: "rgb(0, 0, 0)",
      danger: "rgb(255, 157, 148)",
      dangerSoft: "rgb(61, 15, 11)",
      dangerInk: "rgb(255, 192, 186)",
      colorScheme: "dark",
    },
  },
};

// The canvas and brand of the same palettes, as the swatches' shapes carry them.
const approvedFills: Record<string, Record<PreviewMode, { canvas: string; brand: string }>> = {
  blueberry: { light: { canvas: "#f4f5f7", brand: "#2456c4" }, dark: { canvas: "#0f1217", brand: "#8ab4ff" } },
  plum: { light: { canvas: "#f6f4f7", brand: "#7a3aa8" }, dark: { canvas: "#120f15", brand: "#cda4f0" } },
  "high-contrast": { light: { canvas: "#ffffff", brand: "#0037a6" }, dark: { canvas: "#000000", brand: "#9ec5ff" } },
};

// The console is drawn in its own default brand, the seeded one, automatic on Blueberry, whatever the
// sample shows: its page background and its Create button in the device's scheme.
const consoleColors = {
  light: { background: "rgb(244, 245, 247)", create: "rgb(36, 86, 196)" },
  dark: { background: "rgb(15, 18, 23)", create: "rgb(138, 180, 255)" },
};

const notes = {
  auto: "Visitors see it light or dark, following their device.",
  light: "This brand is always light.",
  dark: "This brand is always dark.",
};

// Opens the New brand page on a device asking for this scheme, with reduced motion, so no color
// transition is caught half way.
async function openNewBrand(page: Page, colorScheme: PreviewMode) {
  await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
  await page.goto(newBrandUrl);
  await expect(page.locator("#appearance-auto")).toBeChecked();
  await expect(page.locator("#theme-blueberry")).toBeChecked();
}

// The preview shows the one sample of this mode, drawn in the theme's approved colors.
async function expectSampleShown(page: Page, theme: string, mode: PreviewMode) {
  const other: PreviewMode = mode === "light" ? "dark" : "light";
  await expect(previewSample(page, mode)).toBeVisible();
  await expect(previewSample(page, other)).toBeHidden();
  expect(await sampleColors(previewSample(page, mode)), `the ${mode} sample in ${theme}`).toEqual(approved[theme][mode]);
}

// What the preview shows for an appearance: the switch under Automatic alone, and the one sentence
// saying which modes visitors get.
async function expectPreviewFor(page: Page, appearance: Appearance) {
  if (appearance === "auto") await expect(previewSwitch(page)).toBeVisible();
  else await expect(previewSwitch(page)).toBeHidden();
  for (const [shown, text] of Object.entries(notes)) {
    const note = brandPreview(page).getByText(text, { exact: true });
    if (shown === appearance) await expect(note).toBeVisible();
    else await expect(note).toBeHidden();
  }
}

async function expectConsoleColors(page: Page, colorScheme: PreviewMode) {
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), "the console's page background").toBe(consoleColors[colorScheme].background);
  await expect(page.locator("#btnCreate")).toHaveCSS("background-color", consoleColors[colorScheme].create);
}

for (const colorScheme of ["light", "dark"] as const) {
  test(`on a ${colorScheme} device, the sample takes the chosen theme's colors, light and under the switch dark, and the console around it keeps its own`, async ({ page }) => {
    await openNewBrand(page, colorScheme);
    // Automatic starts on Light, whatever the device asks.
    await expectPreviewFor(page, "auto");
    await expect(previewSwitch(page).getByRole("radio", { name: "Light", exact: true })).toBeChecked();
    await expectSampleShown(page, "blueberry", "light");

    for (const theme of ["plum", "high-contrast"]) {
      await fillBrandForm(page, { theme });
      await switchPreviewTo(page, "light");
      await expectSampleShown(page, theme, "light");
      await switchPreviewTo(page, "dark");
      await expectSampleShown(page, theme, "dark");
      await expectConsoleColors(page, colorScheme);
    }
  });
}

test("the appearance decides the preview: Light and Dark their one sample and no switch, Automatic the switch, operable by keyboard", async ({ page }) => {
  await openNewBrand(page, "light");
  await fillBrandForm(page, { theme: "plum" });

  await fillBrandForm(page, { appearance: "dark" });
  await expectPreviewFor(page, "dark");
  await expectSampleShown(page, "plum", "dark");

  await fillBrandForm(page, { appearance: "light" });
  await expectPreviewFor(page, "light");
  await expectSampleShown(page, "plum", "light");

  // Back on Automatic the switch is there again, and its arrow keys move it, as any radio group's do.
  await fillBrandForm(page, { appearance: "auto" });
  await expectPreviewFor(page, "auto");
  await expectSampleShown(page, "plum", "light");
  const light = previewSwitch(page).getByRole("radio", { name: "Light", exact: true });
  const dark = previewSwitch(page).getByRole("radio", { name: "Dark", exact: true });
  await light.focus();
  await page.keyboard.press("ArrowDown");
  await expect(dark).toBeFocused();
  await expect(dark).toBeChecked();
  await expectSampleShown(page, "plum", "dark");
  await page.keyboard.press("ArrowUp");
  await expect(light).toBeChecked();
  await expectSampleShown(page, "plum", "light");
});

test("the Appearance cards' swatches take the chosen theme, and each theme card keeps its own", async ({ page }) => {
  await openNewBrand(page, "light");
  const drawnIn = (theme: string) => ({
    auto: [approvedFills[theme].light, approvedFills[theme].dark],
    light: [approvedFills[theme].light],
    dark: [approvedFills[theme].dark],
  });
  expect(await appearanceSwatchFills(page), "drawn in Blueberry, the form's theme").toEqual(drawnIn("blueberry"));
  for (const theme of ["plum", "high-contrast", "blueberry"]) {
    await fillBrandForm(page, { theme });
    expect(await appearanceSwatchFills(page), `drawn in ${theme}`).toEqual(drawnIn(theme));
  }

  await fillBrandForm(page, { theme: "plum" });
  const blueberryCard = page.locator("label.option-card", { has: page.locator("#theme-blueberry") });
  const fills = await blueberryCard.locator('[data-fill="canvas"]').evaluateAll((shapes) => shapes.map((shape) => shape.getAttribute("fill")));
  expect(fills, "Blueberry's card shows Blueberry, light and dark").toEqual(["#f4f5f7", "#0f1217"]);
});

test("after leaving the page and coming Back, the sample matches the form as the browser restored it", async ({ page }) => {
  await openNewBrand(page, "light");
  await fillBrandForm(page, { theme: "guava" });
  await switchPreviewTo(page, "dark");
  await expectSampleShown(page, "guava", "dark");

  await page.locator(".page-eyebrow").getByRole("link", { name: "Branding", exact: true }).click();
  await expect(page).toHaveURL(brandingUrl);
  await page.goBack();
  await expect(page).toHaveURL(newBrandUrl);

  // Each engine restores the form its own way, or not at all: whatever it holds, the sample is drawn
  // from it.
  const restored = await page.evaluate(() => ({
    appearance: document.querySelector<HTMLInputElement>('input[name="appearance"]:checked')?.value ?? "auto",
    theme: document.querySelector<HTMLInputElement>('input[name="theme"]:checked')?.value ?? "",
    mode: document.querySelector<HTMLInputElement>('input[name="brandPreviewMode"]:checked')?.value ?? "light",
  }));
  test.info().annotations.push({ type: "restored form", description: JSON.stringify(restored) });
  expect(Object.keys(approved), "the restored theme is one this test knows the colors of").toContain(restored.theme);
  const mode = (restored.appearance === "auto" ? restored.mode : restored.appearance) as PreviewMode;
  await expectPreviewFor(page, restored.appearance as Appearance);
  await expectSampleShown(page, restored.theme, mode);
});

test("picking a theme, an appearance or a mode sends no request", async ({ page }) => {
  await openNewBrand(page, "light");
  await page.waitForLoadState("load");
  const sent: string[] = [];
  page.on("request", (request) => {
    if (!new URL(request.url()).pathname.startsWith("/static/favicon/")) sent.push(`${request.method()} ${request.url()}`);
  });

  await fillBrandForm(page, { theme: "plum" });
  await switchPreviewTo(page, "dark");
  await fillBrandForm(page, { appearance: "light", theme: "high-contrast" });
  await fillBrandForm(page, { appearance: "dark" });
  await expectSampleShown(page, "high-contrast", "dark");
  expect(sent, "the requests sent while the form changed").toEqual([]);
});

test("the sample cannot be reached by Tab, is hidden from assistive technology, and the page says in text what it shows", async ({ page }) => {
  await openNewBrand(page, "light");
  const preview = brandPreview(page);
  await expect(preview.getByRole("heading", { level: 2, name: "Preview", exact: true })).toBeVisible();
  await expect(preview.getByText("A sample of a sign-in page in this brand, as the form stands now. The brand changes only when you save.", { exact: true })).toBeVisible();
  await expect(preview.getByText(notes.auto, { exact: true })).toBeVisible();

  for (const mode of ["light", "dark"] as const) {
    await expect(previewSample(page, mode)).toHaveAttribute("inert", "");
    await expect(previewSample(page, mode)).toHaveAttribute("aria-hidden", "true");
  }
  // On screen, as a refused sign-in reads, and absent from what assistive technology is given.
  const sample = previewSample(page, "light");
  for (const text of ["Enter your email and password to continue.", "Password is required.", "alex@example.com", "Forgot your password?"]) {
    await expect(sample.getByText(text, { exact: true })).toBeVisible();
  }
  const tree = await preview.ariaSnapshot();
  expect(tree, "the preview as assistive technology reads it").toContain("Preview in");
  for (const text of ["Password is required.", "alex@example.com", "Forgot your password?"]) {
    expect(tree, "the preview as assistive technology reads it").not.toContain(text);
  }

  // The samples follow the switch, so Tab from the switch would land in one if anything in it took
  // the focus; and nothing in either takes it when asked to.
  const switchLight = page.locator("#brand-preview-mode-light");
  await switchLight.focus();
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => document.activeElement?.closest(".brand-sample") ?? null), "the focus after the switch").toBeNull();
  for (const mode of ["light", "dark"] as const) {
    await switchPreviewTo(page, mode);
    expect(
      await previewSample(page, mode).evaluate((sample) => {
        for (const element of Array.from(sample.querySelectorAll<HTMLElement>("*"))) {
          element.focus();
          if (document.activeElement === element) return element.outerHTML;
        }
        return null;
      }),
      `an element of the ${mode} sample that takes the focus`,
    ).toBeNull();
  }
});
