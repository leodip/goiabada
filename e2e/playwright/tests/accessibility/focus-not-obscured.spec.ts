// The field Tab or Shift+Tab moves the focus to is never hidden under the console's header, which
// stays pinned to the top of the page as it scrolls (WCAG 2.2 SC 2.4.11 Focus Not Obscured
// (Minimum)). Axe cannot check this: it depends on where the page has scrolled when the focus
// arrives. ui.css reserves the header's height, and a gap for the focus ring, as the page's
// scroll-padding-top, so the browser scrolls the field out from under the header (#722 decision 1).
//
// How a browser scrolls a focused field into view is its engine's own code, so this file runs in
// Chromium, Firefox and WebKit (playwright.config.ts), on a phone-sized window, where the header
// covers most of what a field needs. Each journey scrolls the next field under the header, wholly or
// in part, with the focus on its neighbour, then moves the focus onto it by keyboard.
import type { Locator, Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectFocused, expectWhollyBelowHeader } from "../../lib/focus";

test.use({ viewport: { width: 320, height: 480 } });

// One worker per browser, rather than one per test: each worker signs the administrator in, and the
// three browsers' workers count under the seeded cap of sessions per user (e2e/README.md).
test.describe.configure({ mode: "default" });

type Placement = "wholly" | "partly";

// Scrolls the page so the field lies under the header: wholly, its whole box within the header's,
// or partly, its top 20 pixels under the header and the rest below it.
async function scrollUnderHeader(field: Locator, placement: Placement) {
  const placed = await field.evaluate((field, placement) => {
    const header = document.querySelector(".app-header")!.getBoundingClientRect();
    const before = field.getBoundingClientRect();
    const top = placement === "wholly" ? header.bottom - 4 - before.height : header.bottom - 20;
    window.scrollBy(0, before.top - top);
    const box = field.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom, headerTop: header.top, headerBottom: header.bottom };
  }, placement);
  // The journey starts where it says it does, so a page too short to scroll that far fails here.
  if (placement === "wholly") {
    expect(placed.top, "the field's top is under the header").toBeGreaterThanOrEqual(placed.headerTop);
    expect(placed.bottom, "the field's bottom is under the header").toBeLessThanOrEqual(placed.headerBottom);
  } else {
    expect(placed.top, "the field's top is under the header").toBeLessThan(placed.headerBottom);
    expect(placed.bottom, "the field's bottom is below the header").toBeGreaterThan(placed.headerBottom);
  }
}

// With the focus on from and to under the header, the key moves the focus onto to, which shows,
// its ring included, below the header.
async function moveFocusOnto(page: Page, { from, to, key, placement }: { from: Locator; to: Locator; key: "Tab" | "Shift+Tab"; placement: Placement }) {
  await from.focus();
  await expect(from).toBeFocused();
  await scrollUnderHeader(to, placement);
  await page.keyboard.press(key);
  await expectFocused(to);
  await expectWhollyBelowHeader(to);
}

test("on the profile, Shift+Tab onto a field wholly under the header brings it into view below it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/account/profile`);
  await moveFocusOnto(page, {
    from: page.getByLabel("Middle name", { exact: true }),
    to: page.getByLabel("Given name", { exact: true }),
    key: "Shift+Tab",
    placement: "wholly",
  });
});

test("on the profile, Tab onto a field wholly under the header brings it into view below it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/account/profile`);
  await moveFocusOnto(page, {
    from: page.getByLabel("Given name", { exact: true }),
    to: page.getByLabel("Middle name", { exact: true }),
    key: "Tab",
    placement: "wholly",
  });
});

test("on the profile, Shift+Tab and Tab onto a field partly under the header bring it whole below it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/account/profile`);
  const givenName = page.getByLabel("Given name", { exact: true });
  const middleName = page.getByLabel("Middle name", { exact: true });
  await moveFocusOnto(page, { from: middleName, to: givenName, key: "Shift+Tab", placement: "partly" });
  await moveFocusOnto(page, { from: givenName, to: middleName, key: "Tab", placement: "partly" });
});

test("on the address, Shift+Tab and Tab onto a field under the header bring it into view below it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/account/address`);
  const line1 = page.getByLabel("Address line 1", { exact: true });
  const line2 = page.getByLabel("Address line 2", { exact: true });
  await moveFocusOnto(page, { from: line2, to: line1, key: "Shift+Tab", placement: "wholly" });
  await moveFocusOnto(page, { from: line1, to: line2, key: "Tab", placement: "wholly" });
  await moveFocusOnto(page, { from: line2, to: line1, key: "Shift+Tab", placement: "partly" });
});

test("on a client's settings, a long form, Shift+Tab and Tab onto a field under the header bring it into view below it", async ({
  page,
  clients,
}) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  const privacyPolicy = page.getByLabel("Privacy policy URL", { exact: true });
  const termsOfService = page.getByLabel("Terms of service URL", { exact: true });
  await moveFocusOnto(page, { from: termsOfService, to: privacyPolicy, key: "Shift+Tab", placement: "wholly" });
  await moveFocusOnto(page, { from: privacyPolicy, to: termsOfService, key: "Tab", placement: "wholly" });
  await moveFocusOnto(page, { from: privacyPolicy, to: termsOfService, key: "Tab", placement: "partly" });
});
