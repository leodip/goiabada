// The journeys a person makes by keyboard alone, with Tab, typing, Enter, Space and Escape and
// nothing clicked: signing in on the auth server's form, its password shown and hidden again, the
// reset form's two password fields, the user menu, a console dialog left with Escape, and a client's
// tabs. Every element reached shows its focus ring, and is not hidden under the console's header
// (lib/focus.ts; focus-not-obscured.spec.ts scrolls fields under it on purpose). The sign-in page also
// works with JavaScript off, without its Show button, and puts a shown password back to dots as it is
// sent (#722). keyboard.system.ts takes the registration and activation forms, which need a setting.
import type { Browser, Locator, Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectFocused } from "../../lib/focus";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { watchPasswordFieldsAsSent } from "../../lib/submission";

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

// The status region the auth server's script adds beside a password field, right after its row.
function statusOf(page: Page, fieldId: string): Locator {
  return page.locator(`.input-row:has(#${fieldId}) + [role="status"]`);
}

// The auth server's sign-in, as an empty browser reaches it from the console.
async function openConsoleSignIn(browser: Browser, options: { javaScriptEnabled?: boolean } = {}) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, ...options });
  const page = await context.newPage();
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page).toHaveURL(/\/auth\/pwd/);
  return { context, page };
}

test("a user signs in on the auth server's form by keyboard alone", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await openConsoleSignIn(browser);

  // The address field has the focus as the page opens; Tab goes on to the password, its Show
  // button, the link for a forgotten one, then the button.
  await expectFocused(page.locator("#email"));
  await page.keyboard.type(user.email);
  await page.keyboard.press("Tab");
  const password = page.locator("#password");
  await expectFocused(password);
  await page.keyboard.type(user.password);
  await page.keyboard.press("Tab");
  const show = page.getByRole("button", { name: "Show password", exact: true });
  await expectFocused(show);
  await expect(show).toHaveText("Show");
  await expect(show).toHaveAttribute("aria-controls", "password");
  const status = statusOf(page, "password");
  await expect(status).toHaveText("");

  // Enter shows the password, Space hides it again, and the focus stays on the button.
  await page.keyboard.press("Enter");
  await expect(password).toHaveAttribute("type", "text");
  await expect(password).toHaveValue(user.password);
  const hide = page.getByRole("button", { name: "Hide password", exact: true });
  await expect(hide).toHaveText("Hide");
  await expect(status).toHaveText("Shown");
  await expectFocused(hide);
  await page.keyboard.press("Space");
  await expect(password).toHaveAttribute("type", "password");
  await expect(show).toHaveText("Show");
  await expect(status).toHaveText("Hidden");
  await expectFocused(show);

  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("link", { name: "Forgot your password?" }));
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("button", { name: "Sign in", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await context.close();
});

test("with JavaScript off, the sign-in page shows no Show button, and still signs in", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await openConsoleSignIn(browser, { javaScriptEnabled: false });
  await expect(page.locator("#password")).toBeVisible();
  await expect(page.locator("button[data-password-toggle]")).toBeHidden();
  await expect(page.getByRole("button", { name: "Show password" })).toHaveCount(0);

  await page.locator("#email").fill(user.email);
  await page.locator("#password").fill(user.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  // With no script, the response is carried on to the console by the form_post page's own button.
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await context.close();
});

test("signing in puts a shown password back to dots before the page leaves", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await openConsoleSignIn(browser);
  await page.locator("#email").fill(user.email);
  const password = page.locator("#password");
  await password.fill("not-the-password");
  await page.getByRole("button", { name: "Show password", exact: true }).click();
  await expect(password).toHaveAttribute("type", "text");

  // The submission is held at the network, so the page it leaves is still there to read; it is
  // then dropped, so nothing is signed in.
  const isSignIn = (url: URL) => url.origin === new URL(env.authUrl).origin && url.pathname === "/auth/pwd";
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  await page.route(isSignIn, async (route) => {
    if (route.request().method() !== "POST") {
      return route.continue();
    }
    await held;
    return route.abort();
  });
  const sent = page.waitForRequest((request) => request.method() === "POST" && isSignIn(new URL(request.url())));
  // Playwright reads no page while its navigation is held, so the page reports its own fields.
  const asSent = await watchPasswordFieldsAsSent(page, ["password"]);
  try {
    // The click does not wait for the navigation it starts, which the route holds until release.
    await page.getByRole("button", { name: "Sign in", exact: true }).click({ noWaitAfter: true });
    await sent;
    expect((await asSent.state).password).toEqual({ type: "password", buttonText: "Show", buttonName: "Show password" });
    const dropped = page.waitForEvent("requestfailed");
    release();
    await dropped;
  } finally {
    // A failed assertion still lets the held request go.
    release();
  }
  await context.close();
});

test("the reset form's two password fields each have their Show button, reached by Tab", async ({ browser, request, users }) => {
  // A reset link is only ever mailed to a verified address.
  const user = await users.create({ emailVerified: true });
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(`${env.authUrl}/forgot-password`);
  await page.locator("#email").fill(user.email);
  await page.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  const link = linksIn(await waitForMail(request, user.email)).find((l) => l.includes("/reset-password"))!;
  await page.goto(link);
  await expect(page.getByRole("heading", { name: "Set your password" })).toBeVisible();

  await expectFocused(page.locator("#password"));
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("button", { name: "Show password", exact: true }));
  await page.keyboard.press("Tab");
  await expectFocused(page.locator("#passwordConfirmation"));
  await page.keyboard.press("Tab");
  const showConfirmation = page.getByRole("button", { name: "Show password confirmation", exact: true });
  await expectFocused(showConfirmation);
  await expect(showConfirmation).toHaveText("Show");
  await expect(showConfirmation).toHaveAttribute("aria-controls", "passwordConfirmation");
  await page.keyboard.press("Enter");
  await expect(page.locator("#passwordConfirmation")).toHaveAttribute("type", "text");
  await expect(page.locator("#password")).toHaveAttribute("type", "password");
  await expectFocused(page.getByRole("button", { name: "Hide password confirmation", exact: true }));
  await expect(statusOf(page, "passwordConfirmation")).toHaveText("Shown");
  await page.keyboard.press("Tab");
  await expectFocused(page.getByRole("button", { name: "Set password", exact: true }));
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

  // The page begins with the link back to the list, above its heading, then the tabs.
  const tabs = page.getByRole("navigation", { name: "Sections" });
  await page.keyboard.press("Tab");
  await expectFocused(page.locator("#main").getByRole("link", { name: "Clients", exact: true }));
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
