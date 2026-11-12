// The admin console's Branding pages (Settings - Branding): the brands, one of them the default. A
// client's pages are drawn in the brand chosen on its Settings tab, or in the default when it has none,
// and the console in the brand of its own client (#812). Changing the default, the default brand, or
// the console's own client's brand changes what the whole instance looks like, so the tests doing it
// are *.system.ts files, and put back what they found (withDefaultBrandRestored). A brand that is not
// the default, given to a client of a test's own, changes only that client's pages (withBrand).
import { type APIRequestContext, expect, type Locator, type Page } from "@playwright/test";
import { confirmDialog, grantClientPermission, readClientSecret } from "./admin-console";
import { env } from "./environment";
import { solidPng } from "./images";
import type { TestClient } from "./fixtures";
import { clientCredentialsToken } from "./oauth";
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

// The kit's choices in the brand form (#813): the corners, the font family, the background fit and
// the switch hiding the app name beside a logo.
export type Corners = "square" | "rounded" | "pill";
export type FontFamily = "system-ui" | "humanist" | "geometric" | "serif" | "neo-grotesque" | "rounded" | "uploaded";
export type BackgroundFit = "cover" | "contain" | "tile";

export interface BrandKitChoices {
  corners: Corners;
  font: FontFamily;
  backgroundFit: BackgroundFit;
  hideAppName: boolean;
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

// Every brand on the list, in its order, the default marked by its tag, which is a note's; a brand
// with failing contrast pairs carries a caution tag too (#815 decision 9).
export async function listBrands(page: Page): Promise<ListedBrand[]> {
  await page.goto(brandingUrl);
  const rows = page.locator("#brandsTable tbody tr");
  const brands: ListedBrand[] = [];
  for (const row of await rows.all()) {
    const link = row.locator("td:first-child a");
    brands.push({
      id: brandIdFrom(await link.getAttribute("href")),
      name: (await link.innerText()).trim(),
      isDefault: (await row.locator(".tag-note").count()) > 0,
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
export async function fillBrandForm(page: Page, values: Partial<BrandValues & BrandKitChoices>) {
  if (values.name !== undefined) await page.locator("#name").fill(values.name);
  if (values.appearance) await page.locator(`#appearance-${values.appearance}`).check();
  if (values.theme) await page.locator(`#theme-${values.theme}`).check();
  if (values.corners) await page.locator(`#corners-${values.corners}`).check();
  if (values.font) await page.locator("#font").selectOption(values.font);
  if (values.backgroundFit) await page.locator(`#backgroundFit-${values.backgroundFit}`).check();
  if (values.hideAppName !== undefined) await page.locator("#hideAppName").setChecked(values.hideAppName);
}

// The kit's choices the brand form holds.
export async function readBrandKitChoices(page: Page): Promise<BrandKitChoices> {
  return {
    corners: (await page.locator('input[name="corners"]:checked').getAttribute("value")) as Corners,
    font: (await page.locator("#font").inputValue()) as FontFamily,
    backgroundFit: (await page.locator('input[name="backgroundFit"]:checked').getAttribute("value")) as BackgroundFit,
    hideAppName: await page.locator("#hideAppName").isChecked(),
  };
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

// The preview's two views (#815 decision 10): each sample holds the sign-in card and the Messages card,
// and the Sign-in/Messages switch named "Show", on the preview's heading line, picks which shows.
export type PreviewView = "signin" | "messages";

export function previewView(page: Page, mode: PreviewMode, view: PreviewView): Locator {
  return previewSample(page, mode).locator(`[data-brand-sample-view="${view}"]`);
}

export function previewViewSwitch(page: Page): Locator {
  return brandPreview(page).getByRole("group", { name: "Show", exact: true });
}

// Puts the view switch on a view, as a click on its choice does.
export async function switchPreviewViewTo(page: Page, view: PreviewView) {
  await page.locator(`#brand-preview-view-${view}`).check();
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

// The corners and the font a sample is drawn with, as the browser computes them: the radius of the
// card, of a field and of a button, which a corner shape sets, and of the danger notice, a box that may
// hold several lines; and the first font of the family the sample's title asks for, unquoted. Which
// font a device then finds is its own: the headless browser has almost none of the families' fonts.
export interface SampleShape {
  card: string;
  control: string;
  button: string;
  notice: string;
  firstFont: string;
}

// firstFontOf is the first font of a computed font-family list, without its quotes.
export function firstFontOf(fontFamily: string): string {
  return fontFamily.split(",")[0].trim().replace(/^["']|["']$/g, "");
}

export async function sampleShape(sample: Locator): Promise<SampleShape> {
  const shape = await sample.evaluate((sample) => {
    const radius = (selector: string) => getComputedStyle(sample.querySelector(selector)!).borderTopLeftRadius;
    return {
      card: radius(".auth-card"),
      control: radius(".control"),
      button: radius(".button-primary"),
      notice: radius(".notice-danger"),
      fontFamily: getComputedStyle(sample.querySelector(".auth-title")!).fontFamily,
    };
  });
  return { card: shape.card, control: shape.control, button: shape.button, notice: shape.notice, firstFont: firstFontOf(shape.fontFamily) };
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

// The brand stylesheets a page links, in order: each one's brand, and whether it is the full one
// (/brand/7/stylesheet.css), which the auth server's pages and the console's end-user pages link, or
// the colors-only one (/brand/7/colors.css), which the console's admin pages link (#813 decision 9).
export interface LinkedBrandStylesheet {
  brandId: number;
  kind: "full" | "colors";
}

export function pageBrandStylesheets(page: Page): Promise<LinkedBrandStylesheet[]> {
  return page.evaluate(() => {
    const linked: { brandId: number; kind: "full" | "colors" }[] = [];
    for (const link of Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]'))) {
      const match = new URL(link.href, document.baseURI).pathname.match(/^\/brand\/(\d+)\/(stylesheet|colors)\.css$/);
      if (match) linked.push({ brandId: Number(match[1]), kind: match[2] === "colors" ? "colors" : "full" });
    }
    return linked;
  });
}

// The brand a page of the auth server or the console names in its head: the brand of the one brand
// stylesheet it links, full or colors-only, or null when it links none.
export async function pageStylesheetBrand(page: Page): Promise<number | null> {
  const linked = await pageBrandStylesheets(page);
  expect(linked.length, "a page links one brand stylesheet at most").toBeLessThanOrEqual(1);
  return linked[0]?.brandId ?? null;
}

// The icons a page links, each as "rel href" with the href absolute, in order.
export function pageIcons(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(
      document.querySelectorAll<HTMLLinkElement>('link[rel="icon"], link[rel="apple-touch-icon"], link[rel="manifest"]'),
      (link) => `${link.rel} ${link.href}`,
    ),
  );
}

// Goiabada's own icons and web manifest, as a page of the origin named links them.
export function goiabadaIcons(origin: string): string[] {
  return [
    `icon ${origin}/static/favicon/favicon.ico`,
    `apple-touch-icon ${origin}/static/favicon/apple-touch-icon.png`,
    `icon ${origin}/static/favicon/favicon-32x32.png`,
    `icon ${origin}/static/favicon/favicon-16x16.png`,
    `manifest ${origin}/static/favicon/site.webmanifest`,
  ];
}

// A brand's favicon, as a page links it in place of Goiabada's icons: the one stored image, as its
// icon and its Apple touch icon (#813 decision 4).
export function brandFaviconIcons(faviconUrl: string): string[] {
  return [`icon ${faviconUrl}`, `apple-touch-icon ${faviconUrl}`];
}

// A brand's kit set through the Admin API, as an application does, in two steps: a file is uploaded
// as a brand asset of its kind, then named in the brand's slot (#813 decision 1). The editor's own
// uploads are uploadInEditor's. The caller is a
// client of the test's own holding authserver:manage-settings.
export interface UploadedBrandAsset {
  id: number;
  url: string;
}

export interface BrandKit {
  logo?: UploadedBrandAsset;
  darkLogo?: UploadedBrandAsset;
  favicon?: UploadedBrandAsset;
  hideAppName?: boolean;
}

export async function brandKitToken(
  page: Page,
  request: APIRequestContext,
  clients: { create(options: { authorizationCode: boolean; clientCredentials: boolean }): Promise<TestClient> },
): Promise<string> {
  const caller = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, caller.id, "authserver", "manage-settings");
  const token = await clientCredentialsToken(request, caller.identifier, await readClientSecret(page, caller.id), "authserver:manage-settings");
  expect(token.status, JSON.stringify(token.body)).toBe(200);
  return String(token.body.access_token);
}

// Uploads a PNG as a brand asset of the kind named, and answers its id and URL.
export async function uploadBrandAsset(
  request: APIRequestContext,
  token: string,
  kind: "logo" | "favicon",
  png: Buffer,
): Promise<UploadedBrandAsset> {
  const response = await request.post(`${env.authUrl}/api/v1/admin/brand-assets/${kind}`, {
    headers: { Authorization: `Bearer ${token}` },
    multipart: { file: { name: `${kind}.png`, mimeType: "image/png", buffer: png } },
    failOnStatusCode: false,
  });
  expect(response.status(), await response.text()).toBe(201);
  const { brandAsset } = await response.json();
  return { id: brandAsset.id, url: brandAsset.url };
}

// Writes a brand's logo, dark logo, favicon and switch as kit has them, an absent one empty or off,
// and keeps the rest of the brand as it is stored.
export async function setBrandKit(request: APIRequestContext, token: string, brandId: number, kit: BrandKit) {
  const url = `${env.authUrl}/api/v1/admin/brands/${brandId}`;
  const headers = { Authorization: `Bearer ${token}` };
  const read = await request.get(url, { headers, failOnStatusCode: false });
  expect(read.status(), await read.text()).toBe(200);
  const { brand } = await read.json();
  const slot = (asset?: { id: number } | null) => (asset ? { id: asset.id } : null);
  const written = await request.put(url, {
    headers,
    data: {
      name: brand.name,
      appearance: brand.appearance,
      theme: brand.theme,
      corners: brand.corners,
      font: brand.font,
      backgroundFit: brand.backgroundFit,
      hideAppName: kit.hideAppName ?? false,
      logo: slot(kit.logo),
      darkLogo: slot(kit.darkLogo),
      favicon: slot(kit.favicon),
      background: slot(brand.background),
      regularFont: slot(brand.regularFont),
      boldFont: slot(brand.boldFont),
      // The footer as it was read, so it is kept: a member left out would mean none (#814).
      footerLinks: brand.footerLinks,
      supportEmail: brand.supportEmail,
      supportUrl: brand.supportUrl,
      supportPhone: brand.supportPhone,
    },
    failOnStatusCode: false,
  });
  expect(written.status(), await written.text()).toBe(200);
}

// A brand's footer links and support contact, as the Admin API names them (#814): up to three
// links, each a URL, a fallback label and a label per built-in language, and each contact value
// optional.
export interface BrandFooterLink {
  url: string;
  label: string;
  labels?: Record<string, string>;
}

export interface BrandFooter {
  footerLinks?: BrandFooterLink[];
  supportEmail?: string;
  supportUrl?: string;
  supportPhone?: string;
}

// Writes a brand's footer links and support contact as footer has them, an absent one none, and
// keeps the rest of the brand, its kit included, as it is stored.
export async function setBrandFooter(request: APIRequestContext, token: string, brandId: number, footer: BrandFooter) {
  const url = `${env.authUrl}/api/v1/admin/brands/${brandId}`;
  const headers = { Authorization: `Bearer ${token}` };
  const read = await request.get(url, { headers, failOnStatusCode: false });
  expect(read.status(), await read.text()).toBe(200);
  const { brand } = await read.json();
  const slot = (asset?: { id: number } | null) => (asset ? { id: asset.id } : null);
  const written = await request.put(url, {
    headers,
    data: {
      name: brand.name,
      appearance: brand.appearance,
      theme: brand.theme,
      corners: brand.corners,
      font: brand.font,
      backgroundFit: brand.backgroundFit,
      hideAppName: brand.hideAppName,
      logo: slot(brand.logo),
      darkLogo: slot(brand.darkLogo),
      favicon: slot(brand.favicon),
      background: slot(brand.background),
      regularFont: slot(brand.regularFont),
      boldFont: slot(brand.boldFont),
      footerLinks: footer.footerLinks ?? [],
      supportEmail: footer.supportEmail ?? "",
      supportUrl: footer.supportUrl ?? "",
      supportPhone: footer.supportPhone ?? "",
    },
    failOnStatusCode: false,
  });
  expect(written.status(), await written.text()).toBe(200);
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

// The brand editor's six upload fields (#813 decision 1), by the name the form gives each slot. A file
// picked at one is uploaded at once, through the console, as a brand asset of the slot's kind: the
// field says so in its status region, and its two hidden fields hold the asset's id and URL, which the
// preview draws and Save names in the slot.
export type BrandSlot = "logo" | "darkLogo" | "favicon" | "background" | "regularFont" | "boldFont";

export interface PickedFile {
  name: string;
  mimeType: string;
  buffer: Buffer;
}

// What the uploads in the editor's fields answer, the sentences its status region shows.
export const uploadSays = {
  uploaded: "Uploaded. Save the brand to use it.",
  removed: "Removed. Save the brand to apply it.",
} as const;

// A PNG made on the spot, as a file picked in the editor.
export function pngFile(name: string, width: number, height: number, rgb: [number, number, number]): PickedFile {
  return { name, mimeType: "image/png", buffer: solidPng(width, height, rgb) };
}

// A file the auth server takes as a WOFF2 font, which it tells by the signature its first four bytes
// hold. No browser draws it, and no spec needs one to: they check the family a page asks for, not how
// its letters look.
export function woff2File(name: string): PickedFile {
  return { name, mimeType: "font/woff2", buffer: Buffer.concat([Buffer.from("wOF2", "ascii"), Buffer.alloc(124)]) };
}

// Picks file at slot's field, as Upload and the file picker do, and answers what the field then says,
// once its upload has been answered.
export async function pickInEditor(page: Page, slot: BrandSlot, file: PickedFile): Promise<string> {
  await page.locator(`#${slot}File`).setInputFiles(file);
  const answer = page.locator(`#${slot}Status .notice:not(.notice-note)`);
  await expect(answer).toBeVisible();
  return (await answer.innerText()).trim();
}

// Uploads file at slot's field and waits for the field to say it was uploaded, answering the URL the
// asset is served at.
export async function uploadInEditor(page: Page, slot: BrandSlot, file: PickedFile): Promise<string> {
  expect(await pickInEditor(page, slot, file), `the ${slot} uploaded`).toBe(uploadSays.uploaded);
  return slotHolds(page, slot).then((held) => held.url);
}

// What a slot's hidden fields hold: the asset's id and URL, both empty for an empty slot.
export async function slotHolds(page: Page, slot: BrandSlot): Promise<{ id: string; url: string }> {
  return {
    id: await page.locator(`input[type="hidden"][name="${slot}"]`).inputValue(),
    url: await page.locator(`input[type="hidden"][name="${slot}Url"]`).inputValue(),
  };
}

// The kit a test uploads in the editor: a logo, a dark logo of another color, a square favicon, a
// background and the uploaded font's two files.
export const kitFiles: Record<BrandSlot, PickedFile> = {
  logo: pngFile("logo.png", 240, 80, [36, 86, 196]),
  darkLogo: pngFile("dark-logo.png", 240, 80, [138, 180, 255]),
  favicon: pngFile("favicon.png", 64, 64, [176, 32, 106]),
  background: pngFile("background.png", 320, 200, [240, 200, 120]),
  regularFont: woff2File("brand-regular.woff2"),
  boldFont: woff2File("brand-bold.woff2"),
};

// Uploads each file of kitFiles in the editor's fields, answering the URL each is served at.
export async function uploadKit(page: Page, slots: BrandSlot[] = Object.keys(kitFiles) as BrandSlot[]): Promise<Partial<Record<BrandSlot, string>>> {
  const urls: Partial<Record<BrandSlot, string>> = {};
  for (const slot of slots) urls[slot] = await uploadInEditor(page, slot, kitFiles[slot]);
  return urls;
}

// What a sample of the preview draws of the kit: its logo box's image, if it shows one, whether the
// app name shows, its background image and how it is laid out, as the browser computes them.
export interface SampleKit {
  logo: string | null;
  nameShown: boolean;
  backgroundImage: string;
  backgroundSize: string;
  backgroundRepeat: string;
}

export function sampleKit(sample: Locator): Promise<SampleKit> {
  return sample.evaluate((sample) => {
    const box = sample.querySelector<HTMLElement>(".auth-logo")!;
    const image = box.querySelector("img");
    const style = getComputedStyle(sample);
    return {
      logo: !box.hidden && image ? image.getAttribute("src") : null,
      nameShown: !sample.querySelector<HTMLElement>(".auth-brand")!.hidden,
      backgroundImage: style.backgroundImage,
      backgroundSize: style.backgroundSize,
      backgroundRepeat: style.backgroundRepeat,
    };
  });
}

// The brand editor's footer (#814 decision 11): three rows, Link 1 to Link 3, each a label, a URL and a
// label per built-in language under a disclosure, then the support contact's three fields.
export const footerRows = 3;

// The disclosure holding a row's language labels.
export function footerLanguageLabels(page: Page, row: number): Locator {
  return page.locator(`#footerLinks-${row} details`);
}

// Opens a row's language labels, when they are closed.
export async function openFooterLanguageLabels(page: Page, row: number) {
  const disclosure = footerLanguageLabels(page, row);
  if (!(await disclosure.evaluate((element) => (element as HTMLDetailsElement).open))) {
    await disclosure.locator("summary").click();
  }
  await expect(disclosure).toHaveAttribute("open", "");
}

// Types footer into the editor: each row the link of its index, a row past the links emptied, the
// language labels named typed, and each contact value named. A value left out of a link is typed
// empty, a language label included, so nothing stays from what the row held before. A row's language
// labels are opened when one of them is typed or emptied.
export async function fillBrandFooter(page: Page, footer: BrandFooter) {
  const links = footer.footerLinks ?? [];
  for (let row = 0; row < footerRows; row++) {
    const link = links[row];
    await page.locator(`#footerLinks-${row}-label`).fill(link?.label ?? "");
    await page.locator(`#footerLinks-${row}-url`).fill(link?.url ?? "");
    const labels = link?.labels ?? {};
    const prefix = `footerLinks-${row}-labels-`;
    for (const input of await page.locator(`input[id^="${prefix}"]`).all()) {
      const tag = (await input.getAttribute("id"))!.slice(prefix.length);
      if (labels[tag] !== undefined || (await input.inputValue()) === "") continue;
      await openFooterLanguageLabels(page, row);
      await input.fill("");
    }
    if (Object.keys(labels).length > 0) await openFooterLanguageLabels(page, row);
    for (const [tag, label] of Object.entries(labels)) await page.locator(`#${prefix}${tag}`).fill(label);
  }
  if (footer.supportEmail !== undefined) await page.locator("#supportEmail").fill(footer.supportEmail);
  if (footer.supportUrl !== undefined) await page.locator("#supportUrl").fill(footer.supportUrl);
  if (footer.supportPhone !== undefined) await page.locator("#supportPhone").fill(footer.supportPhone);
}

// What the editor's footer fields hold: the rows that hold anything, in order, each language label
// that is not blank, and the three contact values.
export function readBrandFooterForm(page: Page): Promise<Required<BrandFooter>> {
  return page.evaluate((rows) => {
    const value = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
    const footerLinks: BrandFooterLink[] = [];
    for (let row = 0; row < rows; row++) {
      const labels: Record<string, string> = {};
      for (const input of Array.from(document.querySelectorAll<HTMLInputElement>(`input[id^="footerLinks-${row}-labels-"]`))) {
        if (input.value !== "") labels[input.id.slice(`footerLinks-${row}-labels-`.length)] = input.value;
      }
      const link = { url: value(`footerLinks-${row}-url`), label: value(`footerLinks-${row}-label`), labels };
      if (link.url !== "" || link.label !== "" || Object.keys(labels).length > 0) footerLinks.push(link);
    }
    return { footerLinks, supportEmail: value("supportEmail"), supportUrl: value("supportUrl"), supportPhone: value("supportPhone") };
  }, footerRows);
}

// A link of a page's footer as it is drawn: its text, the new-tab notice its sr-only span adds
// included, where it goes, and how it opens.
export interface DrawnFooterLink {
  text: string;
  href: string;
  target: string | null;
  rel: string | null;
}

// A page's footer as it is drawn: none, or the links of its list, the contact line's text and its
// links, whether it is outside main and straight after it, and whether it is on a panel in the card's
// color rather than on the page's background.
export interface DrawnFooter {
  links: DrawnFooterLink[];
  contact: string;
  contactLinks: DrawnFooterLink[];
  afterMain: boolean;
  panel: boolean;
}

export function drawnFooter(page: Page): Promise<DrawnFooter | null> {
  return page.evaluate(() => {
    const footers = document.querySelectorAll("footer");
    if (footers.length === 0) return null;
    const footer = footers[0];
    const text = (element: Element | null) => (element?.textContent ?? "").replace(/\s+/g, " ").trim();
    const link = (a: HTMLAnchorElement) => ({ text: text(a), href: a.getAttribute("href")!, target: a.getAttribute("target"), rel: a.getAttribute("rel") });
    const contact = footer.querySelector("p");
    const card = document.querySelector(".auth-card");
    const background = getComputedStyle(footer).backgroundColor;
    return {
      links: Array.from(footer.querySelectorAll<HTMLAnchorElement>("ul a"), link),
      contact: text(contact),
      contactLinks: contact ? Array.from(contact.querySelectorAll<HTMLAnchorElement>("a"), link) : [],
      afterMain: footer.closest("main") === null && footer.previousElementSibling?.tagName === "MAIN",
      panel: background !== "rgba(0, 0, 0, 0)" && card !== null && background === getComputedStyle(card).backgroundColor,
    };
  });
}

// What a sample of the brand editor's preview draws of the footer under its card (#814 decision 12):
// whether it shows, the links' text in order, the contact line's parts that show, in order, "Need
// help?" first, whether it is on a panel in the card's color rather than on the sample's background,
// and how many elements in it could be operated, which the inert sample draws none of.
export interface SampleFooter {
  shown: boolean;
  links: string[];
  contact: string[];
  panel: boolean;
  operable: number;
}

export function sampleFooter(sample: Locator): Promise<SampleFooter> {
  return sample.evaluate((sample) => {
    const footer = sample.querySelector<HTMLElement>("[data-brand-sample-footer]")!;
    const shown = (element: Element) => (element as HTMLElement).checkVisibility();
    const text = (element: Element) => (element.textContent ?? "").replace(/\s+/g, " ").trim();
    const contact = footer.querySelector(".brand-footer-contact")!;
    const background = getComputedStyle(footer).backgroundColor;
    return {
      shown: shown(footer),
      links: Array.from(footer.querySelectorAll(".brand-footer-links li")).filter(shown).map(text),
      contact: shown(contact) ? Array.from(contact.children).filter(shown).map(text) : [],
      panel: background !== "rgba(0, 0, 0, 0)" && background === getComputedStyle(sample.querySelector(".auth-card")!).backgroundColor,
      operable: footer.querySelectorAll("a, button, input, [tabindex]").length,
    };
  });
}

// A brand's custom palette in the editor's Colors section (#815 decision 7): Custom picked among the
// theme cards, Basic or Advanced, and a #rrggbb field for each color of each mode, named by its mode
// and its color token. Basic sets four colors a mode and the save works out the rest; Advanced sets
// all 23.
export type PaletteMode = "basic" | "advanced";

export interface PaletteValues {
  mode: PaletteMode;
  light: Record<string, string>;
  dark: Record<string, string>;
}

// The 23 color tokens a palette sets for each mode, in the order ui.css declares them and the Colors
// section's Advanced rows name them.
export const paletteTokens = [
  "canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
  "brand", "brand-strong", "on-brand", "brand-soft",
  "danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
  "positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink",
  "focus",
];

// What a preview sample resolves a color token to, as the preview set it on the sample, in lower case.
export function sampleToken(sample: Locator, token: string): Promise<string> {
  return sample.evaluate((sample, token) => getComputedStyle(sample).getPropertyValue(`--color-${token}`).trim().toLowerCase(), token);
}

// A color's text field in the Colors section, by the mode of its column and its token.
export function paletteField(page: Page, mode: PreviewMode, token: string): Locator {
  return page.locator(`#palette-${mode}-${token}`);
}

// The heading of the Light or the Dark column, shown while the column is.
export function paletteColumnHead(page: Page, mode: PreviewMode): Locator {
  return page.locator(`#palette-head-${mode}`);
}

// The line under the Colors section's choices: a column's colors kept and not used ("unused"), or not
// drawn but required to be colors ("invalid").
export function paletteNote(page: Page, note: "unused" | "invalid", mode: PreviewMode): Locator {
  return page.locator(`[data-palette-note="${note}-${mode}"]`);
}

// Picks Custom and fills the Colors section: the mode, then each color typed in its field.
export async function fillPalette(page: Page, palette: PaletteValues) {
  await page.locator("#theme-custom").check();
  await page.locator(`#paletteMode-${palette.mode}`).check();
  for (const mode of ["light", "dark"] as const) {
    for (const [token, value] of Object.entries(palette[mode])) await paletteField(page, mode, token).fill(value);
  }
}

// What a page's root resolves a color token to, as the brand's stylesheet declares it, in lower case.
export function pageToken(page: Page, token: string): Promise<string> {
  return page.evaluate((token) => getComputedStyle(document.documentElement).getPropertyValue(`--color-${token}`).trim().toLowerCase(), token);
}

// A #rrggbb color as a browser reports a computed color.
export function rgbOf(color: string): string {
  const channel = (at: number) => parseInt(color.slice(at, at + 2), 16);
  return `rgb(${channel(1)}, ${channel(3)}, ${channel(5)})`;
}

// Expects a page drawn in a mode of a palette under each color scheme a device can ask for: each color
// named resolves on the root to its value, and the page's background is the canvas color.
export async function expectDrawnInPalette(page: Page, colorScheme: PreviewMode, colors: Record<string, string>) {
  // Reduced motion, so no transition is caught half way between the two schemes.
  await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
  for (const [token, value] of Object.entries(colors)) {
    expect(await pageToken(page, token), `${colorScheme}: --color-${token}`).toBe(value.toLowerCase());
  }
  if (colors.canvas) {
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), `${colorScheme}: the page's background`).toBe(rgbOf(colors.canvas));
  }
  await page.emulateMedia({ colorScheme: null, reducedMotion: null });
}

// A basic palette in warm colors no built-in theme has, whose own pairs pass.
export const warmBasicPalette: PaletteValues = {
  mode: "basic",
  light: { canvas: "#fbf7f0", surface: "#ffffff", ink: "#1d1a16", brand: "#7a3e00" },
  dark: { canvas: "#14110d", surface: "#1e1a15", ink: "#f2ede6", brand: "#f0a050" },
};

// Creates a brand under a fresh name in the editor, with this appearance and custom palette, runs body
// with it, and deletes it afterwards, pass or fail, unless body deleted it.
export async function withCustomBrand(
  page: Page,
  appearance: Appearance,
  palette: PaletteValues,
  body: (brand: { id: number; name: string }) => Promise<void>,
) {
  const name = uniqueIdentifier("brand");
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance });
  await fillPalette(page, palette);
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(brandingUrl);
  const id = await brandIdFromList(page, name);
  try {
    await body({ id, name });
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
}

// The editor form's saved notice. The preview's Messages samples hold a positive notice each, hidden
// until that view is chosen, so a bare .notice-positive matches them too.
export function savedNotice(page: Page): Locator {
  return page.locator('.brand-editor > form .notice-positive[role="status"]');
}

// The failing pairs of a saved custom palette, at the foot of the Colors section (#815 decision 9):
// the region the saved notice links to, its count line, and an item per pair, each a sentence beside a
// swatch of the pair.
export function paletteWarnings(page: Page): Locator {
  return page.locator("#palette-warnings");
}

export function paletteWarningsCount(page: Page): Locator {
  return page.locator("#paletteWarningsCount");
}

export function paletteWarningItems(page: Page): Locator {
  return paletteWarnings(page).locator("li.palette-warning");
}

// The brand list's marker of a brand with failing contrast pairs, in its row.
export function brandWarningsMarker(page: Page, name: string): Locator {
  return brandRow(page, name).locator(".tag-caution");
}

// A basic palette whose light text fails on its background and its card: #777777 on white is 4.47:1
// when cut, below text's 4.5:1 (WCAG 2.2 SC 1.4.3). Its dark colors are warmBasicPalette's.
export const failingBasicPalette: PaletteValues = {
  mode: "basic",
  light: { canvas: "#ffffff", surface: "#ffffff", ink: "#777777", brand: "#1f4fa8" },
  dark: warmBasicPalette.dark,
};
