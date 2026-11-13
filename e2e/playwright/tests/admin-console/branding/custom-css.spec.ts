// A brand's custom CSS set in the brand editor (#816), then seen where it is drawn: a client's sign-in
// page, a data: image among it, with no Content-Security-Policy violation (the fixtures' watcher fails
// the test on one). The editor's preview never draws it, and the sentence beside the field says so and
// how to try it (decision 8). An @import and a URL that is not a data: image are refused at the field,
// with the line each is on, and the form keeps what was typed.
//
// The brand is the test's own, given to a client of the test's own, so no other page changes, and
// this is an ordinary parallel spec. The console's own pages, which every console page shares, are
// brands.system.ts's.
import type { Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandUrl,
  brandingUrl,
  customCssField,
  customCssPreviewNote,
  fillBrandForm,
  newBrandUrl,
  previewSample,
  saveCustomCss,
  withBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { expect, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// A transparent GIF of one pixel, as a data: URL, the one kind of URL custom CSS can hold.
const pixel = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

// CSS a page shows unmistakably: an outline no page draws on the card, and, on the sign-in page alone,
// a background image from a data: URL.
const customCss = [
  "/* Acme's card */",
  ".auth-card {",
  "  outline: 6px solid rgb(18, 52, 86);",
  "}",
  `body[data-page="sign-in"] .auth-card {`,
  `  background-image: url("${pixel}");`,
  "}",
  "",
].join("\n");

// The card's outline and background image, as the browser computes them.
function cardLook(page: Page, card = page.locator(".auth-card").first()) {
  return card.evaluate((element) => {
    const style = getComputedStyle(element);
    return { outline: `${style.outlineStyle} ${style.outlineWidth} ${style.outlineColor}`, backgroundImage: style.backgroundImage };
  });
}

test("custom CSS saved in the editor is drawn on the client's sign-in page, and not in the preview, which says so", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  await withBrand(page, { appearance: "light", theme: "plum" }, async (brand) => {
    // The field says the preview does not show custom CSS, and how to try it.
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(customCssField(page)).toHaveValue("");
    await expect(page.locator("#customCssPreviewNote")).toHaveText(customCssPreviewNote);
    await expect(customCssField(page)).toHaveAccessibleName("Custom CSS");
    await expect(customCssField(page)).toHaveAccessibleDescription(/The preview doesn't show custom CSS\./);

    // Saved, the page holds it as typed, and the preview's sample card is drawn as before.
    await saveCustomCss(page, brand.id, customCss);
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(customCssField(page)).toHaveValue(customCss);
    const sample = await cardLook(page, previewSample(page, "light").locator(".auth-card"));
    expect(sample.outline, "the preview does not draw custom CSS").not.toContain("rgb(18, 52, 86)");
    expect(sample.backgroundImage).toBe("none");

    // The client's sign-in page draws it, the data: image included.
    await setClientBrand(page, client.id, brand);
    const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      await expect(signIn.page.locator("body")).toHaveAttribute("data-page", "sign-in");
      expect(await cardLook(signIn.page)).toEqual({ outline: "solid 6px rgb(18, 52, 86)", backgroundImage: `url("${pixel}")` });
    } finally {
      await signIn.context.close();
    }
  });
});

// Each refusal, with the line it names: an @import, and a URL to another site, which a browser would
// fetch, sending the visitor's address with it.
const refusals = [
  {
    name: "an @import",
    css: '.auth-card {\n  color: rgb(18, 52, 86);\n}\n@import "https://cdn.example.com/theme.css";\n',
    says: "Line 4 of the custom CSS has an @import. Custom CSS cannot load another stylesheet.",
  },
  {
    name: "a URL to another site",
    css: '.auth-card {\n  background-image: url("https://cdn.example.com/card.png");\n}\n',
    says: "Line 2 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL.",
  },
];

test("an @import and a URL in custom CSS are refused at the field with their line, and the form keeps what was typed", async ({ page }) => {
  for (const refusal of refusals) {
    await test.step(refusal.name, async () => {
      const name = uniqueIdentifier("brand");
      await page.goto(newBrandUrl);
      await fillBrandForm(page, { name });
      await customCssField(page).fill(refusal.css);
      await page.locator("#btnCreate").click();

      await expect(page).toHaveURL(newBrandUrl);
      await expect(page.locator("#brand-error")).toHaveText(refusal.says);
      const field = customCssField(page);
      await expect(field).toBeFocused();
      await expect(field).toHaveAttribute("aria-invalid", "true");
      await expect(field).toHaveAttribute("aria-describedby", /^brand-error\b/);
      // Only the field is marked: the preview's samples draw an inert invalid field of their own.
      await expect(page.locator('.brand-editor > form [aria-invalid="true"]')).toHaveCount(1);
      await expect(field).toHaveValue(refusal.css);
      await expect(page.locator("#customCssPreviewNote")).toHaveText(customCssPreviewNote);

      await page.goto(brandingUrl);
      await expect(page.locator("#brandsTable").getByText(name, { exact: true }), "nothing was created").toHaveCount(0);
    });
  }
});
