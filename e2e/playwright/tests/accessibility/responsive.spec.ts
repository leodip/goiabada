// The console and the auth server's forms at phone and tablet sizes, as ui.css and shell.js lay them
// out: below 1024 px the sidebar is a panel the menu button opens; below 640 px a list table reads as
// one card per row, each line labelled with its column's name, and wider it is a table scrolling
// inside its own region; dialogs, menus and forms stay within the screen, and no page scrolls
// sideways. Only the test's own tab is resized, so the fixtures work at the default size.
import type { Locator, Page } from "@playwright/test";
import { addRedirectUri, addSignOutRedirectUri, cancelDialog, clientUrl, setClientBrand, userUrl } from "../../lib/admin-console";
import { brandUrl, customCssField, fillBrandFooter, newBrandUrl, paletteField, withBrand } from "../../lib/brands";
import { openSignIn } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { uniqueIdentifier } from "../../lib/unique";

// A test visits a dozen pages at its size.
test.describe.configure({ timeout: 120_000 });

const viewports = [
  { name: "a phone", width: 390, height: 844 },
  { name: "a small phone", width: 320, height: 640 },
  { name: "a tablet", width: 768, height: 1024 },
  { name: "a tablet on its side", width: 1024, height: 768 },
];

// The widths ui.css changes the layout at: 64rem, where the sidebar stays beside the page, and 40rem,
// where a list table stops stacking into cards.
const sidebarWidth = 1024;
const tableWidth = 640;

// The lists whose tables stack, and the first row each is checked by.
const lists = [
  { path: "/admin/clients", table: "#clientsTable" },
  { path: "/admin/users", table: "#usersTable" },
  { path: "/admin/settings/keys", table: "#keysTable" },
  { path: "/admin/settings/audit-log-viewer", table: "#auditLogsTable" },
];

// How far the page scrolls sideways, in CSS pixels.
function sidewaysScroll(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

// The element's box lies within the screen's width, and its height too when asked; a pixel's
// rounding allowed.
async function expectWithinScreen(page: Page, element: Locator, { height = false } = {}) {
  const box = (await element.boundingBox())!;
  const screen = page.viewportSize()!;
  expect(box.x, "its left edge").toBeGreaterThanOrEqual(-1);
  expect(box.x + box.width, "its right edge").toBeLessThanOrEqual(screen.width + 1);
  if (height) {
    expect(box.y, "its top edge").toBeGreaterThanOrEqual(-1);
    expect(box.y + box.height, "its bottom edge").toBeLessThanOrEqual(screen.height + 1);
  }
}

// The form's fields and buttons that reach past either edge of the screen.
function controlsPastTheEdge(form: Locator): Promise<string[]> {
  return form.evaluate((form) => {
    const width = document.documentElement.clientWidth;
    const past: string[] = [];
    for (const control of Array.from(form.querySelectorAll<HTMLElement>("input, select, textarea, button"))) {
      if (!control.checkVisibility() || control.closest(".table-scroll")) continue;
      const box = control.getBoundingClientRect();
      if (box.left < -1 || box.right > width + 1) {
        past.push(`${control.tagName.toLowerCase()}${control.id ? `#${control.id}` : ""} spans ${Math.round(box.left)} to ${Math.round(box.right)}`);
      }
    }
    return past;
  });
}

// A table's first row as it is drawn: whether its cells sit one below another, as a card's lines
// do, and each labelled cell's label, its column's header, and whether the label is drawn.
function firstRowLayout(table: Locator) {
  return table.evaluate((element) => {
    const table = element as HTMLTableElement;
    const headers = Array.from(table.tHead!.rows[0].cells, (cell) => cell.textContent!.trim());
    const cells = Array.from(table.tBodies[0].rows[0].cells);
    const boxes = cells.map((cell) => cell.getBoundingClientRect());
    return {
      stacked: boxes.every((box, i) => i === 0 || box.top >= boxes[i - 1].bottom - 1),
      labels: cells
        .filter((cell) => cell.dataset.label !== undefined)
        .map((cell) => ({
          label: cell.dataset.label!,
          header: headers[cell.cellIndex],
          drawn: getComputedStyle(cell, "::before").content !== "none",
        })),
    };
  });
}

for (const viewport of viewports) {
  const size = { width: viewport.width, height: viewport.height };
  const panel = viewport.width < sidebarWidth;
  const cards = viewport.width < tableWidth;

  test.describe(`on ${viewport.name}, ${viewport.width}×${viewport.height}`, () => {
    const menus = panel
      ? "the menu button opens the sidebar and Close menu closes it; the user menu opens within the screen"
      : "the sidebar stays beside the page; the user menu opens within the screen";
    test(menus, async ({ page }) => {
      await page.setViewportSize(size);
      // Reduced motion, so the panel's slide is over the moment it opens, when its box is measured.
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.goto(`${env.adminUrl}/admin/clients`);
      const sidebar = page.locator("#app-sidebar");
      const open = page.locator("button[data-app-menu-open]");
      const close = page.locator("button[data-app-menu-close]");

      if (panel) {
        await expect(sidebar).toBeHidden();
        await expect(open).toHaveAccessibleName("Open menu");
        await open.click();
        await expect(sidebar).toBeVisible();
        await expect(open).toHaveAttribute("aria-expanded", "true");
        await expect(close).toBeFocused();
        await expect(close).toHaveAccessibleName("Close menu");
        await expectWithinScreen(page, sidebar, { height: true });

        await close.click();
        await expect(sidebar).toBeHidden();
        await expect(open).toHaveAttribute("aria-expanded", "false");
        await expect(open).toBeFocused();

        // Escape closes it too; and a link in it leads where it says, to a page where it is closed.
        await open.click();
        await expect(sidebar).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(sidebar).toBeHidden();
        await open.click();
        await sidebar.getByRole("link", { name: "Users", exact: true }).click();
        await expect(page).toHaveURL(`${env.adminUrl}/admin/users`);
        await expect(sidebar).toBeHidden();
      } else {
        await expect(sidebar).toBeVisible();
        await expect(open).toBeHidden();
        await expect(sidebar.getByRole("link", { name: "Users", exact: true })).toBeVisible();
      }

      const userMenu = page.locator("button[data-user-menu-button]");
      const userPanel = page.locator("#user-menu-panel");
      await userMenu.click();
      await expect(userPanel).toBeVisible();
      await expect(userMenu).toHaveAttribute("aria-expanded", "true");
      for (const link of ["Home", "Account", "Admin", "Sign out"]) {
        await expect(userPanel.getByRole("link", { name: link, exact: true })).toBeVisible();
      }
      await expectWithinScreen(page, userPanel, { height: true });
      await userMenu.click();
      await expect(userPanel).toBeHidden();
    });

    test("no page scrolls sideways, and forms and dialogs fit the screen", async ({ page, browser, clients, users }) => {
      const client = await clients.create();
      // A long redirect URI, which its list wraps rather than widen the page with.
      await addRedirectUri(page, client.id, `${env.webtest1Url}/callback/${"a-long-path-segment-".repeat(6)}end?state=${"x".repeat(40)}`);
      await addSignOutRedirectUri(page, client.id, `${env.webtest1Url}/signed-out/${"a-long-path-segment-".repeat(6)}end?state=${"x".repeat(40)}`);
      const user = await users.create();
      await page.setViewportSize(size);

      const pages: { url: string; form?: string }[] = [
        { url: `${env.adminUrl}/` },
        { url: `${env.adminUrl}/admin/clients` },
        { url: clientUrl(client.id, "settings"), form: "#formClientSettings" },
        { url: clientUrl(client.id, "redirect-uris") },
        { url: clientUrl(client.id, "sign-out-redirect-uris") },
        { url: clientUrl(client.id, "backchannel-logout"), form: "#formClientBackchannelLogout" },
        { url: `${env.adminUrl}/admin/users` },
        { url: userUrl(user.id, "profile"), form: "main form.panel" },
        { url: `${env.adminUrl}/admin/groups` },
        { url: `${env.adminUrl}/admin/resources` },
        { url: `${env.adminUrl}/admin/settings/general`, form: "main form.panel" },
        // The brand editor: its fields and the preview, two panes collapsing into one (#811).
        { url: newBrandUrl, form: "main .brand-editor" },
        { url: `${env.adminUrl}/admin/settings/keys` },
        { url: `${env.adminUrl}/admin/settings/audit-log-viewer` },
        { url: `${env.adminUrl}/account/profile`, form: "main form.panel" },
      ];
      for (const { url, form } of pages) {
        await test.step(url, async () => {
          await page.goto(url);
          expect.soft(await sidewaysScroll(page), `${url} scrolls sideways by`).toBeLessThanOrEqual(0);
          if (form) expect.soft(await controlsPastTheEdge(page.locator(form)), `the fields and buttons past the screen's edge on ${url}`).toEqual([]);
        });
      }

      await test.step("a save's confirmation", async () => {
        await page.goto(clientUrl(client.id, "settings"));
        await page.locator("#clientIdentifier").fill(`${client.identifier}-renamed`);
        await page.locator("#btnSave").click();
        const dialog = page.locator("dialog[open]");
        await expect(dialog).toBeVisible();
        await expectWithinScreen(page, dialog, { height: true });
        await cancelDialog(page);
      });

      await test.step("the widest dialog, a public key's", async () => {
        await page.goto(`${env.adminUrl}/admin/settings/keys`);
        await page.locator('button[data-format="pem"]').first().click();
        const dialog = page.locator("#publicKeyDialog");
        await expect(dialog).toBeVisible();
        await expectWithinScreen(page, dialog, { height: true });
        await page.keyboard.press("Escape");
        await expect(dialog).toBeHidden();
      });

      // The auth server's forms, in a browser nobody is signed in to: the console sends it to sign in.
      const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: size });
      const signedOut = await context.newPage();
      for (const url of [`${env.adminUrl}/account/profile`, `${env.authUrl}/forgot-password`]) {
        await test.step(url, async () => {
          await signedOut.goto(url);
          expect.soft(await sidewaysScroll(signedOut), `${signedOut.url()} scrolls sideways by`).toBeLessThanOrEqual(0);
          const past = await controlsPastTheEdge(signedOut.locator("form").first());
          expect.soft(past, `the fields and buttons past the screen's edge on ${signedOut.url()}`).toEqual([]);
        });
      }
      await context.close();
    });

    const tables = cards ? "a list table reads as one card per row, each line labelled with its column" : "a list table reads as a table, inside a region that scrolls";
    test(tables, async ({ page }) => {
      await page.setViewportSize(size);
      for (const { path, table } of lists) {
        await test.step(path, async () => {
          await page.goto(`${env.adminUrl}${path}`);
          const list = page.locator(table);
          const layout = await firstRowLayout(list);
          expect(layout.stacked, "the first row's cells one below another").toBe(cards);
          expect(layout.labels.length, "the cells labelled with their column").toBeGreaterThan(0);
          for (const { label, header, drawn } of layout.labels) {
            expect(label, "a cell's label").toBe(header);
            expect(drawn, `the label "${label}" drawn`).toBe(cards);
          }
          const region = page.locator(".table-scroll[role=region]").filter({ has: list });
          await expect(region).toHaveCSS("overflow-x", "auto");
          await expect(region).toHaveAttribute("tabindex", "0");
          await expectWithinScreen(page, region);
          expect(await sidewaysScroll(page), "the page scrolls sideways by").toBeLessThanOrEqual(0);
        });
      }

      if (!cards) {
        await test.step("a table wider than its place", async () => {
          // No list is wider than its place at these sizes with the data a run has, so the audit log
          // is widened where it is: it scrolls inside its region, and the page does not.
          await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer`);
          const list = page.locator("#auditLogsTable");
          await list.evaluate((table) => {
            (table as HTMLElement).style.minWidth = "2000px";
          });
          const region = page.locator(".table-scroll[role=region]").filter({ has: list });
          expect(await region.evaluate((element) => element.scrollWidth > element.clientWidth), "the region scrolls").toBe(true);
          expect(await sidewaysScroll(page), "the page scrolls sideways by").toBeLessThanOrEqual(0);
        });
      }
    });
  });
}

// A brand's whole footer (#814 decision 6), a long address among it, under a client's sign-in card at
// a phone's widths: it wraps within the screen, the page does not scroll sideways, and each of its
// links stays a target of at least 24 pixels. The brand is the test's own, given to a client of its
// own, so no other page changes.
test("a sign-in page's footer wraps within a phone's screen", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  await withBrand(page, { appearance: "light", theme: "plum" }, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandFooter(page, {
      footerLinks: [
        { label: "Privacy and cookie policy", url: "https://example.com/privacy" },
        { label: "Service status", url: "https://status.example.com/" },
        { label: "Terms of service", url: "https://example.com/terms" },
      ],
      supportEmail: "customer-support-and-account-recovery@a-rather-long-domain.example.com",
      supportUrl: "https://example.com/support",
      supportPhone: "+44 20 7946 0958",
    });
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    await setClientBrand(page, client.id, brand);

    for (const width of [320, 390]) {
      const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid", viewport: { width, height: 640 } });
      try {
        await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
        const footer = signIn.page.getByRole("contentinfo");
        await expect(footer).toBeVisible();
        expect(await sidewaysScroll(signIn.page), `${width}px: no sideways scroll`).toBeLessThanOrEqual(0);
        await expectWithinScreen(signIn.page, footer);
        const links = await footer.getByRole("link").all();
        expect(links, `${width}px: three links, the address, the number and the support page`).toHaveLength(6);
        for (const link of links) {
          await expectWithinScreen(signIn.page, link);
          const box = (await link.boundingBox())!;
          expect(box.height, `${width}px: ${await link.textContent()}`).toBeGreaterThanOrEqual(24);
          expect(box.width, `${width}px: ${await link.textContent()}`).toBeGreaterThanOrEqual(24);
        }
      } finally {
        await signIn.context.close();
      }
    }
  });
});

// The brand editor's Colors section (#815 decision 7) at a phone's widths, in Advanced, with all 23
// rows: each color's label takes its own line and its Light and Dark fields stay side by side under
// it, within the screen, each showing its whole #rrggbb value, and the page does not scroll sideways.
test("the Colors section keeps each color's two fields side by side at a phone's widths", async ({ page }) => {
  for (const width of [320, 390]) {
    await test.step(`${width}px`, async () => {
      await page.setViewportSize({ width, height: 800 });
      await page.goto(newBrandUrl);
      await page.locator("#theme-custom").check();
      await page.locator("#paletteMode-advanced").check();
      await expect(page.locator("[data-palette-row]:visible")).toHaveCount(23);
      expect(await sidewaysScroll(page), `${width}px: no sideways scroll`).toBeLessThanOrEqual(0);
      expect(await controlsPastTheEdge(page.locator("#brand-palette")), `${width}px: controls past the edge`).toEqual([]);

      for (const token of ["canvas", "brand-strong", "positive-soft"]) {
        const label = (await page.locator(`#palette-label-${token}`).boundingBox())!;
        const light = paletteField(page, "light", token);
        const dark = paletteField(page, "dark", token);
        const lightBox = (await light.boundingBox())!;
        const darkBox = (await dark.boundingBox())!;
        expect(lightBox.y, `${token}: the fields under the label`).toBeGreaterThanOrEqual(label.y + label.height - 1);
        expect(Math.abs(lightBox.y - darkBox.y), `${token}: Light and Dark on one line`).toBeLessThanOrEqual(1);
        expect(darkBox.x, `${token}: Dark after Light`).toBeGreaterThan(lightBox.x + lightBox.width);
        await expectWithinScreen(page, dark);
        for (const field of [light, dark]) {
          const clipped = await field.evaluate((input) => input.scrollWidth > input.clientWidth);
          expect(clipped, `${width}px: ${token}'s whole value shows`).toBe(false);
        }
      }
    });
  }
});

// The brand editor's Custom CSS field (#816) at a phone's widths, refused, holding a line longer than
// the screen: the field, its notice and the sentence about the preview stay within the screen, the long
// line wraps or scrolls inside the field, and the page does not scroll sideways.
test("the Custom CSS field, refused, stays within a phone's screen", async ({ page }) => {
  const longLine = `.auth-card { background-image: url("data:image/gif;base64,${"R0lGODlhAQABAIAAAAAAAP".repeat(12)}"); }`;
  for (const width of [320, 390]) {
    await test.step(`${width}px`, async () => {
      await page.setViewportSize({ width, height: 800 });
      await page.goto(newBrandUrl);
      await page.locator("#name").fill(uniqueIdentifier("brand"));
      await customCssField(page).fill(`${longLine}\n@import "theme.css";\n`);
      await page.locator("#btnCreate").click();
      await expect(customCssField(page)).toHaveAttribute("aria-invalid", "true");
      expect(await sidewaysScroll(page), `${width}px: no sideways scroll`).toBeLessThanOrEqual(0);
      for (const shown of [page.locator("#brand-error"), customCssField(page), page.locator("#customCssPreviewNote")]) {
        await expectWithinScreen(page, shown);
      }
    });
  }
});
