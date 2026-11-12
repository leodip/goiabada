// A brand's footer links and support contact set in the brand editor (#814), then seen where they are
// drawn: a client's sign-in page in English and in German, the error page a request through the client
// is refused with, and the same over a background image, where the footer sits on a panel. Each
// refusal is said at the input it is about, which takes the focus, and the form keeps what was typed.
//
// The brand is the test's own, given to a client of the test's own, so no other page changes, and
// this is an ordinary parallel spec. The console's own pages, which every console page shares, are
// footer.system.ts's.
import type { Browser, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandIdFromList,
  brandUrl,
  brandingUrl,
  type DrawnFooterLink,
  deleteBrand,
  drawnFooter,
  fillBrandFooter,
  fillBrandForm,
  footerLanguageLabels,
  kitFiles,
  listBrands,
  newBrandUrl,
  readBrandFooterForm,
  uploadInEditor,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const rel = "noopener noreferrer";

// A footer link that opens a new tab, as the page draws it, saying so in the page's language.
const newTab = (text: string, href: string, notice: string): DrawnFooterLink => ({ text: `${text} ${notice}`, href, target: "_blank", rel });

// The client's sign-in in a browser of its own, params added to its authorization request.
async function openOwnSignIn(browser: Browser, client: TestClient, params: Record<string, string> = {}) {
  return openSignIn(browser, { clientId: client.identifier, scope: "openid", params });
}

// The page's footer, which must be drawn as its own landmark straight after main.
async function footerOf(page: Page) {
  await expect(page.getByRole("contentinfo")).toBeVisible();
  const footer = await drawnFooter(page);
  expect(footer, "a footer is drawn").not.toBeNull();
  expect(footer!.afterMain, "the footer is outside main, straight after it").toBe(true);
  return footer!;
}

test("each footer field set in the editor is drawn on a sign-in page in two languages and on an error page, on a panel over a background image", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");

  // A new brand: three links, the first with a German and a Portuguese label, and the whole contact,
  // the phone number typed with separators.
  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "light", theme: "plum" });
  await fillBrandFooter(page, {
    footerLinks: [
      { label: "Privacy", url: "https://example.com/privacy", labels: { de: "Datenschutz", "pt-BR": "Privacidade" } },
      { label: "Status", url: "https://status.example.com/" },
      { label: "Acme & Co", url: "https://example.com/" },
    ],
    supportEmail: "help+desk@example.com",
    supportUrl: "https://example.com/support",
    supportPhone: "+1 (415) 555-0123",
  });
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(brandingUrl);
  const id = await brandIdFromList(page, name);

  try {
    // The brand's page holds what was saved, the number without its separators, and its language
    // labels closed away.
    await page.goto(brandUrl(id, "edit"));
    expect(await readBrandFooterForm(page)).toEqual({
      footerLinks: [
        { label: "Privacy", url: "https://example.com/privacy", labels: { de: "Datenschutz", "pt-BR": "Privacidade" } },
        { label: "Status", url: "https://status.example.com/", labels: {} },
        { label: "Acme & Co", url: "https://example.com/", labels: {} },
      ],
      supportEmail: "help+desk@example.com",
      supportUrl: "https://example.com/support",
      supportPhone: "+14155550123",
    });
    for (let row = 0; row < 3; row++) await expect(footerLanguageLabels(page, row)).not.toHaveAttribute("open");
    await setClientBrand(page, client.id, { name });

    // English: the links in order, each label the fallback, then "Need help?" with the address, the
    // number and the support page; on the page's background, with no panel.
    const english = await openOwnSignIn(browser, client);
    await expect(english.page).toHaveURL(/\/auth\/pwd/);
    const notice = "(opens in a new tab)";
    let footer = await footerOf(english.page);
    expect(footer.links).toEqual([
      newTab("Privacy", "https://example.com/privacy", notice),
      newTab("Status", "https://status.example.com/", notice),
      newTab("Acme & Co", "https://example.com/", notice),
    ]);
    expect(footer.contact).toBe(`Need help? help+desk@example.com +14155550123 Support page ${notice}`);
    expect(footer.contactLinks).toEqual([
      { text: "help+desk@example.com", href: "mailto:help+desk@example.com", target: null, rel: null },
      { text: "+14155550123", href: "tel:+14155550123", target: null, rel: null },
      newTab("Support page", "https://example.com/support", notice),
    ]);
    expect(footer.panel, "no background image, no panel").toBe(false);
    const card = (await english.page.locator(".auth-card").boundingBox())!;
    const drawn = (await english.page.getByRole("contentinfo").boundingBox())!;
    expect(drawn.y, "the footer is under the card").toBeGreaterThanOrEqual(card.y + card.height);
    await english.context.close();

    // German: the link with a German label takes it, the others their fallback.
    const german = await openOwnSignIn(browser, client, { ui_locales: "de" });
    await expect(german.page).toHaveURL(/\/auth\/pwd/);
    await expect(german.page.locator("html")).toHaveAttribute("lang", "de");
    const deNotice = "(öffnet sich in einem neuen Tab)";
    footer = await footerOf(german.page);
    expect(footer.links.map((link) => link.text)).toEqual([`Datenschutz ${deNotice}`, `Status ${deNotice}`, `Acme & Co ${deNotice}`]);
    expect(footer.contact).toBe(`Brauchen Sie Hilfe? help+desk@example.com +14155550123 Supportseite ${deNotice}`);
    await german.context.close();

    // The error page a request through the client is refused with, its redirect URI not registered, is
    // drawn in the client's brand, its footer under the short card.
    const refused = await openOwnSignIn(browser, client, { redirect_uri: "https://unregistered.example/callback" });
    await expect(refused.page).toHaveURL(/\/auth\/authorize/);
    await expect(refused.page.getByRole("heading", { level: 1, name: "Unable to authorize", exact: true })).toBeVisible();
    footer = await footerOf(refused.page);
    expect(footer.links.map((link) => link.href)).toEqual(["https://example.com/privacy", "https://status.example.com/", "https://example.com/"]);
    expect(footer.contact).toBe(`Need help? help+desk@example.com +14155550123 Support page ${notice}`);
    expect(footer.panel).toBe(false);
    await refused.context.close();

    // A background image saved: the footer is drawn on a panel in the card's color, on the sign-in
    // and on the error page.
    await page.goto(brandUrl(id, "edit"));
    await uploadInEditor(page, "background", kitFiles.background);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    for (const [what, params] of [
      ["the sign-in page", {}],
      ["the error page", { redirect_uri: "https://unregistered.example/callback" }],
    ] as const) {
      const own = await openOwnSignIn(browser, client, params);
      footer = await footerOf(own.page);
      expect(footer.panel, `${what}: on a panel`).toBe(true);
      expect(footer.links, what).toHaveLength(3);
      await own.context.close();
    }
  } finally {
    if ((await listBrands(page)).some((brand) => brand.id === id)) await deleteBrand(page, id);
  }
});

// Each refusal of the footer, one at a time, with the input it is said at and its sentence. The links
// are sent in the rows' order with empty rows skipped, so a link after an empty row is refused, and
// drawn again, as Link 1.
const refusals: {
  name: string;
  footer: Parameters<typeof fillBrandFooter>[1];
  input: string;
  says: string;
}[] = [
  { name: "a label with no URL", footer: { footerLinks: [{ label: "Privacy", url: "" }] }, input: "footerLinks-0-url", says: "Link 1 needs a URL." },
  { name: "a URL with no label", footer: { footerLinks: [{ label: "", url: "https://example.com/" }] }, input: "footerLinks-0-label", says: "Link 1 needs a label." },
  {
    name: "an http: URL",
    footer: { footerLinks: [{ label: "Privacy", url: "https://example.com/privacy" }, { label: "Status", url: "http://status.example.com/" }] },
    input: "footerLinks-1-url",
    says: "The URL of link 2 must start with https:// and name a site, with no user name or password.",
  },
  {
    name: "a URL with a user name",
    footer: { footerLinks: [{ label: "Privacy", url: "https://example.com@other.example/" }] },
    input: "footerLinks-0-url",
    says: "The URL of link 1 must start with https:// and name a site, with no user name or password.",
  },
  {
    name: "a label of 41 characters",
    footer: { footerLinks: [{ label: "x".repeat(41), url: "https://example.com/" }] },
    input: "footerLinks-0-label",
    says: "The label of link 1 cannot exceed 40 characters.",
  },
  {
    name: "a language label with angle brackets",
    footer: {
      footerLinks: [
        { label: "Privacy", url: "https://example.com/privacy" },
        { label: "Help", url: "https://example.com/help", labels: { "pt-BR": "<b>Ajuda</b>" } },
      ],
    },
    input: "footerLinks-1-labels-pt-BR",
    says: "The pt-BR label of link 2 cannot contain the characters < or >.",
  },
  {
    name: "a link after an empty row",
    footer: { footerLinks: [{ label: "", url: "" }, { label: "Help", url: "" }] },
    input: "footerLinks-0-url",
    says: "Link 1 needs a URL.",
  },
  { name: "the support address", footer: { supportEmail: "not an address" }, input: "supportEmail", says: "Enter a valid support email address." },
  {
    name: "the support page URL",
    footer: { supportUrl: "http://example.com/support" },
    input: "supportUrl",
    says: "The support page URL must start with https:// and name a site, with no user name or password.",
  },
  {
    name: "the support phone number",
    footer: { supportPhone: "555-0123" },
    input: "supportPhone",
    says: "Enter the support phone number in international format: + and the country code, then the number, at most 15 digits in all, such as +44 20 7946 0958.",
  },
];

test("each footer refusal is said at its input, which takes the focus, and the form keeps what was typed", async ({ page }) => {
  for (const refusal of refusals) {
    await test.step(refusal.name, async () => {
      const name = uniqueIdentifier("brand");
      await page.goto(newBrandUrl);
      await fillBrandForm(page, { name });
      await fillBrandFooter(page, refusal.footer);
      const typed = await readBrandFooterForm(page);
      await page.locator("#btnCreate").click();

      await expect(page).toHaveURL(newBrandUrl);
      await expect(page.locator("#brand-error")).toHaveText(refusal.says);
      const input = page.locator(`#${refusal.input}`);
      await expect(input).toBeFocused();
      await expect(input).toHaveAttribute("aria-invalid", "true");
      await expect(input).toHaveAttribute("aria-describedby", /^brand-error\b/);
      // Only the refused input is marked: the preview's samples draw an inert invalid field of
      // their own, so the count is of the form's fields alone.
      await expect(page.locator('.brand-editor > form [aria-invalid="true"]')).toHaveCount(1);
      // What was typed is drawn again: the links in the order they were sent, empty rows last.
      expect(await readBrandFooterForm(page)).toEqual(typed);

      const row = /^footerLinks-(\d)-labels-/.exec(refusal.input);
      if (row) await expect(footerLanguageLabels(page, Number(row[1])), "the refused label's disclosure is open").toHaveAttribute("open", "");
      await page.goto(brandingUrl);
      await expect(page.locator("#brandsTable").getByText(name, { exact: true }), "nothing was created").toHaveCount(0);
    });
  }
});
