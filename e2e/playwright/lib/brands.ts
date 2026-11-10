// The admin console's Branding pages (Settings - Branding): the brands, one of them the default every
// page of the auth server and the console is drawn in. Changing the default, or the default brand,
// changes what the whole instance looks like, so the tests doing it are *.system.ts files, and put back
// the default brand they found (withDefaultBrandRestored).
import { expect, type Page } from "@playwright/test";
import { confirmDialog } from "./admin-console";
import { env } from "./environment";

export const brandingPath = "/admin/settings/branding";
export const brandingUrl = `${env.adminUrl}${brandingPath}`;

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

// Fills and submits the new brand form, leaving the page wherever the console answers.
export async function submitNewBrand(page: Page, values: BrandValues) {
  await page.goto(`${brandingUrl}/new`);
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
