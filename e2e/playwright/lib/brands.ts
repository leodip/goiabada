// The admin console's Branding pages (Settings - Branding): the brands, one of them the default. A
// client's pages are drawn in the brand chosen on its Settings tab, or in the default when it has none,
// and the console in the brand of its own client (#812). Changing the default, the default brand, or
// the console's own client's brand changes what the whole instance looks like, so the tests doing it
// are *.system.ts files, and put back what they found (withDefaultBrandRestored). A brand that is not
// the default, given to a client of a test's own, changes only that client's pages (withBrand).
import { expect, type Locator, type Page } from "@playwright/test";
import { confirmDialog } from "./admin-console";
import { env } from "./environment";
import { uniqueIdentifier } from "./unique";

export const brandingPath = "/admin/settings/branding";
export const brandingUrl = `${env.adminUrl}${brandingPath}`;
export const newBrandUrl = `${brandingUrl}/new`;

export type Appearance = "auto" | "light" | "dark";

export interface BrandValues {
  name: string;
  appearance: Appearance;
  theme: string;
}

export interface ListedBrand {
  id: number;
  name: string;
  isDefault: boolean;
}

export function brandUrl(id: number, page: "edit" | "delete"): string {
  return `${brandingUrl}/${id}/${page}`;
}

// The id in a brand's link, /admin/settings/branding/7/edit.
function brandIdFrom(href: string | null): number {
  const match = href?.match(/\/admin\/settings\/branding\/(\d+)\/edit$/);
  if (!match) throw new Error(`not a brand's link: ${href}`);
  return Number(match[1]);
}

// Every brand on the list, in its order, the default marked by its tag.
export async function listBrands(page: Page): Promise<ListedBrand[]> {
  await page.goto(brandingUrl);
  const rows = page.locator("#brandsTable tbody tr");
  const brands: ListedBrand[] = [];
  for (const row of await rows.all()) {
    const link = row.locator("td:first-child a");
    brands.push({
      id: brandIdFrom(await link.getAttribute("href")),
      name: (await link.innerText()).trim(),
      isDefault: (await row.locator(".tag").count()) > 0,
    });
  }
  return brands;
}

export async function defaultBrand(page: Page): Promise<ListedBrand> {
  const found = (await listBrands(page)).filter((brand) => brand.isDefault);
  expect(found, "exactly one brand is marked the default").toHaveLength(1);
  return found[0];
}

export async function brandIdFromList(page: Page, name: string): Promise<number> {
  const brand = (await listBrands(page)).find((listed) => listed.name === name);
  if (!brand) throw new Error(`no brand named ${name} on the list`);
  return brand.id;
}

// Fills the brand form on the page as it stands, the new one or a brand's own.
export async function fillBrandForm(page: Page, values: Partial<BrandValues>) {
  if (values.name !== undefined) await page.locator("#name").fill(values.name);
  if (values.appearance) await page.locator(`#appearance-${values.appearance}`).check();
  if (values.theme) await page.locator(`#theme-${values.theme}`).check();
}

// The brand editor's preview (#811): a sample of a sign-in page in each mode, drawn in the theme the
// form holds, one shown at a time; the Light/Dark switch named "Preview in", shown under Automatic;
// and the sentences saying what it shows.
export type PreviewMode = "light" | "dark";

export function brandPreview(page: Page): Locator {
  return page.locator("section.brand-preview");
}

export function previewSample(page: Page, mode: PreviewMode): Locator {
  return page.locator(`[data-brand-sample="${mode}"]`);
}

export function previewSwitch(page: Page): Locator {
  return brandPreview(page).getByRole("group", { name: "Preview in", exact: true });
}

// Puts the switch on a mode, as a click on its choice does.
export async function switchPreviewTo(page: Page, mode: PreviewMode) {
  await page.locator(`#brand-preview-mode-${mode}`).check();
}

// Waits for the preview to be drawn: the script has styled the samples and shown one of them.
export async function expectPreviewDrawn(page: Page) {
  await expect(page.locator("[data-brand-sample]:visible")).toHaveCount(1);
}

// The colors a sample is drawn in, as the browser computes them: its canvas, the card's surface, the
// primary button's brand and the text on it, the invalid Password field's danger border, the danger
// notice's soft background and its ink, and the color-scheme the sample asks for.
export interface SampleColors {
  canvas: string;
  surface: string;
  brand: string;
  onBrand: string;
  danger: string;
  dangerSoft: string;
  dangerInk: string;
  colorScheme: string;
}

export function sampleColors(sample: Locator): Promise<SampleColors> {
  return sample.evaluate((sample) => {
    const style = (selector: string) => getComputedStyle(sample.querySelector(selector)!);
    const button = style(".button-primary");
    const notice = style(".notice-danger");
    return {
      canvas: getComputedStyle(sample).backgroundColor,
      surface: style(".auth-card").backgroundColor,
      brand: button.backgroundColor,
      onBrand: button.color,
      danger: style('.control[aria-invalid="true"]').borderTopColor,
      dangerSoft: notice.backgroundColor,
      dangerInk: notice.color,
      colorScheme: getComputedStyle(sample).colorScheme,
    };
  });
}

// What each Appearance card's swatch is drawn in, one entry per mode it shows, in order: the canvas
// and the brand, as the attributes the shapes carry.
export function appearanceSwatchFills(page: Page): Promise<Record<string, { canvas: string; brand: string }[]>> {
  return page.evaluate(() => {
    const fills: Record<string, { canvas: string; brand: string }[]> = {};
    for (const card of Array.from(document.querySelectorAll<HTMLInputElement>('input[name="appearance"]'))) {
      const swatch = card.closest("label")!.querySelector("[data-appearance-swatch]")!;
      fills[card.value] = Array.from(swatch.querySelectorAll("svg"), (svg) => ({
        canvas: svg.querySelector('[data-fill="canvas"]')!.getAttribute("fill")!,
        brand: svg.querySelector('[data-fill="brand"]')!.getAttribute("fill")!,
      }));
    }
    return fills;
  });
}

// Fills and submits the new brand form, leaving the page wherever the console answers.
export async function submitNewBrand(page: Page, values: BrandValues) {
  await page.goto(newBrandUrl);
  await fillBrandForm(page, values);
  await page.locator("#btnCreate").click();
}

// Creates a brand and answers its id.
export async function createBrand(page: Page, values: BrandValues): Promise<number> {
  await submitNewBrand(page, values);
  await expect(page).toHaveURL(brandingUrl);
  return brandIdFromList(page, values.name);
}

// What a brand's page holds: its name and the appearance and theme checked.
export async function readBrand(page: Page, id: number): Promise<BrandValues> {
  await page.goto(brandUrl(id, "edit"));
  return {
    name: await page.locator("#name").inputValue(),
    appearance: (await page.locator('input[name="appearance"]:checked').getAttribute("value")) as Appearance,
    theme: (await page.locator('input[name="theme"]:checked').getAttribute("value")) ?? "",
  };
}

// Saves a brand's page with these values and waits for "Brand saved.".
export async function saveBrand(page: Page, id: number, values: Partial<BrandValues>) {
  await page.goto(brandUrl(id, "edit"));
  await fillBrandForm(page, values);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
}

// Makes a brand the default from its page, answering the question it asks first.
export async function makeBrandDefault(page: Page, id: number) {
  await page.goto(brandUrl(id, "edit"));
  await page.locator("#btnMakeDefault").click();
  await confirmDialog(page, "will be drawn in this brand at once");
  await expect(page).toHaveURL(brandUrl(id, "edit"));
  await expect(page.getByText("This is now the default brand.", { exact: false })).toBeVisible();
}

// Deletes a brand from its delete page, typing its name.
export async function deleteBrand(page: Page, id: number) {
  await page.goto(brandUrl(id, "delete"));
  const name = await page.locator("dl.detail-list dd").first().innerText();
  await page.locator("#name").fill(name.trim());
  await page.locator("#btnDelete").click();
  await expect(page).toHaveURL(brandingUrl);
}

// Runs body, then puts back the default brand it found, the default again and with its values,
// whatever happened.
export async function withDefaultBrandRestored(page: Page, body: () => Promise<void>) {
  const found = await defaultBrand(page);
  const values = await readBrand(page, found.id);
  try {
    await body();
  } finally {
    if ((await defaultBrand(page)).id !== found.id) await makeBrandDefault(page, found.id);
    const now = await readBrand(page, found.id);
    if (now.name !== values.name || now.appearance !== values.appearance || now.theme !== values.theme) {
      await saveBrand(page, found.id, values);
    }
  }
}

// The brand every run starts from: the one the instance was seeded with, named Default, is the
// default, automatic on Blueberry. Answers what it had to change.
export async function restoreBaselineBrand(page: Page): Promise<string[]> {
  const seeded = (await listBrands(page)).find((brand) => brand.name === "Default");
  if (!seeded) throw new Error("no brand named Default, the one the instance was seeded with");
  const drifted: string[] = [];
  if (!seeded.isDefault) {
    await makeBrandDefault(page, seeded.id);
    drifted.push(`${brandingPath}: the default brand`);
  }
  const now = await readBrand(page, seeded.id);
  if (now.appearance !== "auto" || now.theme !== "blueberry") {
    await saveBrand(page, seeded.id, { appearance: "auto", theme: "blueberry" });
    drifted.push(`${brandingPath}: the default brand's appearance and theme`);
  }
  return drifted;
}

// Creates a brand under a fresh name, with this appearance and theme, runs body with it, and deletes it
// afterwards, pass or fail, unless body deleted it. Deleting it moves the clients that use it to the
// default brand, so the brand can be left given to a client of the test's own.
export async function withBrand(
  page: Page,
  values: Omit<BrandValues, "name">,
  body: (brand: { id: number; name: string }) => Promise<void>,
) {
  const name = uniqueIdentifier("brand");
  const id = await createBrand(page, { name, ...values });
  try {
    await body({ id, name });
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
}

// The Branding list's row for a brand, by its name.
export function brandRow(page: Page, name: string): Locator {
  return page.locator("#brandsTable tbody tr", { has: page.getByRole("link", { name, exact: true }) });
}

// How many clients the Branding list says each brand draws, by the brand's name: the Clients column.
export async function brandClientCounts(page: Page): Promise<Record<string, number>> {
  await page.goto(brandingUrl);
  const counts: Record<string, number> = {};
  for (const row of await page.locator("#brandsTable tbody tr").all()) {
    const name = (await row.locator("td:first-child a").innerText()).trim();
    counts[name] = Number((await row.locator('td[data-label="Clients"]').innerText()).trim());
  }
  return counts;
}

// Plum's page background in light and in dark, the canvas token of the palettes approved for #810, as
// a browser reports a computed color.
export const plumCanvas = { light: "rgb(246, 244, 247)", dark: "rgb(18, 15, 21)" } as const;

// The page's background under a device asking for light and for dark.
export async function pageBackgrounds(page: Page): Promise<{ onLight: string; onDark: string }> {
  const background = async (colorScheme: "light" | "dark") => {
    // Reduced motion, so no transition is caught half way between the two.
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  };
  const onLight = await background("light");
  const onDark = await background("dark");
  await page.emulateMedia({ colorScheme: null, reducedMotion: null });
  return { onLight, onDark };
}

// The brand a page of the auth server or the console names in its head: the id in the brand
// stylesheet it links (/brand/7/stylesheet.css), or null when it links none.
export function pageStylesheetBrand(page: Page): Promise<number | null> {
  return page.evaluate(() => {
    for (const link of Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]'))) {
      const match = new URL(link.href, document.baseURI).pathname.match(/^\/brand\/(\d+)\/stylesheet\.css$/);
      if (match) return Number(match[1]);
    }
    return null;
  });
}

// A page drawn in Plum on Dark, the brand the client tests give a client: it links that brand's
// stylesheet, names Dark on its root element and in its color-scheme meta, and keeps Plum's dark
// canvas whatever the device asks.
export async function expectDrawnInPlumDark(page: Page, brandId: number) {
  expect(await pageStylesheetBrand(page), "the page links the client's brand").toBe(brandId);
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute("content", "dark");
  const { onLight, onDark } = await pageBackgrounds(page);
  expect(onLight, "Plum's dark canvas on a light device").toBe(plumCanvas.dark);
  expect(onDark, "and on a dark device").toBe(plumCanvas.dark);
}

// A page drawn in the default brand as the baseline keeps it, the seeded Default, automatic on
// Blueberry: it links the default brand's stylesheet, names no theme, follows the device, and is not
// drawn in Plum.
export async function expectDrawnInSeededDefault(page: Page, defaultBrandId: number) {
  expect(await pageStylesheetBrand(page), "the page links the default brand").toBe(defaultBrandId);
  await expect(page.locator("html")).not.toHaveAttribute("data-theme");
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute("content", "light dark");
  const { onLight, onDark } = await pageBackgrounds(page);
  expect(onLight, "a light device draws the default's light canvas").not.toBe(onDark);
  expect([onLight, onDark], "neither is Plum's").not.toContain(plumCanvas.dark);
  expect([onLight, onDark], "neither is Plum's").not.toContain(plumCanvas.light);
}
