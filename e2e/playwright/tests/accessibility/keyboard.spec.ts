// The journeys a person makes by keyboard alone, with Tab, typing, Enter and Escape and nothing
// clicked: signing in on the auth server's form, the user menu, a console dialog left with Escape,
// and a client's tabs. Every element reached shows its focus ring.
import type { Locator, Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";

// The element has the focus, and shows the ring that says so.
async function expectFocused(element: Locator) {
  await expect(element).toBeFocused();
  await expect(element).toHaveCSS("outline-style", "solid");
}

// Presses Tab until the element has the focus.
async function tabTo(page: Page, element: Locator, limit = 60) {
  for (let presses = 0; presses < limit; presses++) {
    if (await element.evaluate((target) => target === document.activeElement)) {
      await expectFocused(element);
      return;
    }
    await page.keyboard.press("Tab");
  }
  throw new Error(`Tab never reached ${element}`);
}

test("a user signs in on the auth server's form by keyboard alone", async ({ browser, users }) => {
  const user = await users.create();
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(`${env.adminUrl}/account/profile`);

  // The address field has the focus as the page opens; Tab goes on to the password, the link for a
  // forgotten one, then the button.
  await expectFocused(page.locator("#email"));
  await page.keyboard.type(user.email);
  await page.keyboard.press("Tab");
  await expectFocused(page.locator("#password"));
  await page.keyboard.type(user.password);
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("link", { name: "Forgot your password?" }));
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("button", { name: "Sign in", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await context.close();
});

test("the user menu opens with Enter, takes Tab into its links, and Escape closes it", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  const button = page.locator("button[data-user-menu-button]");
  const panel = page.locator("#user-menu-panel");
  await tabTo(page, button);
  await page.keyboard.press("Enter");
  await expect(panel).toBeVisible();
  await expect(button).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("Tab");
  await expectFocused(panel.getByRole("link", { name: "Home", exact: true }));
  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expectFocused(button);
});

test("a confirmation opened by keyboard takes the focus, Escape closes it unanswered, and the focus goes back to Save", async ({
  page,
  clients,
}) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  const identifier = page.locator("#clientIdentifier");
  await tabTo(page, identifier);
  await page.keyboard.press("End");
  await page.keyboard.type("-renamed");
  const save = page.locator("#btnSave");
  await tabTo(page, save);
  await page.keyboard.press("Enter");

  const dialog = page.locator("#confirmSave_modalDialog");
  await expect(dialog).toBeVisible();
  expect(await dialog.evaluate((element) => element.contains(document.activeElement)), "the focus is in the dialog").toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expectFocused(save);

  // Escape answers nothing: the client keeps its identifier.
  await page.goto(clientUrl(client.id, "settings"));
  await expect(identifier).toHaveValue(client.identifier);
});

test("the skip link leads past the menu to a client's tabs, which Tab moves through and Enter follows", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "settings"));
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("link", { name: "Skip to main content" }));
  await page.keyboard.press("Enter");

  const tabs = page.getByRole("navigation", { name: "Sections" });
  await page.keyboard.press("Tab");
  await expectFocused(tabs.getByRole("link", { name: "Settings", exact: true }));
  await expect(tabs.getByRole("link", { name: "Settings", exact: true })).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Tab");
  await expectFocused(tabs.getByRole("link", { name: "Logo", exact: true }));
  await page.keyboard.press("Tab");
  await expectFocused(tabs.getByRole("link", { name: "Tokens", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(clientUrl(client.id, "tokens"));
  await expect(tabs.getByRole("link", { name: "Tokens", exact: true })).toHaveAttribute("aria-current", "page");
});
