// The admin console's shell: the home page, the user menu in the header and the sidebar every page
// with a menu carries, and the pages without one an administrator or a user can land on: page not
// found, administrators only, and the sign-out confirmation.
import { signInToConsole } from "../../lib/console-user";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";

const home = `${env.adminUrl}/`;

test("the home page names the signed-in administrator and links to what they can open", async ({ page }) => {
  await page.goto(home);
  await expect(page).toHaveTitle(/^Admin console – /);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Admin console");
  const identity = page.locator(".identity-row");
  await expect(identity).toContainText("Signed in as");
  await expect(identity).toContainText(env.adminEmail);
  await expect(identity.getByRole("link", { name: "Sign out", exact: true })).toHaveAttribute("href", "/auth/logout");
  // Each link is named by its title, with a line beneath it saying what it leads to.
  for (const [title, href] of [
    ["Your account", "/account/profile"],
    ["Administration", "/admin/clients"],
    ["OpenID Connect discovery", `${env.authUrl}/.well-known/openid-configuration`],
    ["REST API", `${env.authUrl}/openapi.yaml`],
    ["Documentation", "https://goiabada.dev"],
  ]) {
    await expect(page.getByRole("link", { name: new RegExp(`^${title} `) })).toHaveAttribute("href", href);
  }
  await expect(page.getByRole("heading", { name: "For developers" })).toBeVisible();
});

test("signed out, the home page offers the account and administration, which ask to sign in first", async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(home);
  await expect(page.locator(".identity-row")).toHaveCount(0);
  await expect(page.getByRole("link", { name: /^Administration / })).toBeVisible();
  await page.getByRole("link", { name: /^Your account / }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await context.close();
});

test("a user without administrator access is offered their account, but not administration", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(home);
  await expect(page.locator(".identity-row")).toContainText(user.email);
  await expect(page.getByRole("link", { name: /^Your account / })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Administration / })).toHaveCount(0);

  // Nor does the user menu offer it.
  await page.goto(`${env.adminUrl}/account/profile`);
  await page.locator("[data-user-menu-button]").click();
  const panel = page.locator("#user-menu-panel");
  await expect(panel.getByRole("link", { name: "Account", exact: true })).toBeVisible();
  await expect(panel.getByRole("link", { name: "Admin", exact: true })).toHaveCount(0);
  await context.close();
});

test("the user menu opens from its button with the user's links, and closes on Escape or a click elsewhere", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  const button = page.locator("[data-user-menu-button]");
  const panel = page.locator("#user-menu-panel");
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(panel).toBeHidden();

  await button.click();
  await expect(button).toHaveAttribute("aria-expanded", "true");
  await expect(panel).toBeVisible();
  await expect(panel).toContainText(env.adminEmail);
  for (const [name, href] of [
    ["Home", "/"],
    ["Account", "/account/profile"],
    ["Admin", "/admin/clients"],
    ["Sign out", "/auth/logout"],
  ]) {
    await expect(panel.getByRole("link", { name, exact: true })).toHaveAttribute("href", href);
  }

  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(button).toHaveAttribute("aria-expanded", "false");
  await expect(button).toBeFocused();

  await button.click();
  await expect(panel).toBeVisible();
  await page.getByRole("heading", { level: 1 }).click();
  await expect(panel).toBeHidden();
});

test("the sidebar marks the page open, and the section a page belongs to", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/settings/general`);
  const admin = page.getByRole("navigation", { name: "Admin", exact: true });
  await expect(admin.getByRole("link", { name: "General", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(admin.locator('[aria-current="page"]')).toHaveCount(1);
  await admin.getByRole("link", { name: "Audit log", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/settings/audit-log-viewer`);
  await expect(admin.getByRole("link", { name: "Audit log", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(admin.getByRole("link", { name: "General", exact: true })).not.toHaveAttribute("aria-current");
  // A page under a list marks the list's link.
  await page.goto(`${env.adminUrl}/admin/clients/new`);
  await expect(admin.getByRole("link", { name: "Clients", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(admin).toContainText(/Version \S/);

  // The account pages carry their own menu.
  await page.goto(`${env.adminUrl}/account/manage-consents`);
  const account = page.getByRole("navigation", { name: "Account", exact: true });
  await expect(account.getByRole("link", { name: "Consents", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(account.locator('[aria-current="page"]')).toHaveCount(1);
});

test("an address the console doesn't have says so, and its one action leads home", async ({ page }) => {
  const response = await page.goto(`${env.adminUrl}/no-such-page-e2e`);
  expect(response?.status()).toBe(404);
  await expect(page).toHaveTitle(/^Page not found – /);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Page not found");
  await expect(page.getByText("The address may be mistyped, or the page may have moved.")).toBeVisible();
  await page.getByRole("link", { name: "Go to the home page" }).click();
  await expect(page).toHaveURL(home);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Admin console");
});

test("administrators only: a user without access can go home, or sign out to use another account", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveURL(`${env.adminUrl}/unauthorized`);
  await expect(page).toHaveTitle(/^Administrators only – /);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Administrators only");
  await expect(page.getByText("This page is for administrators, and your account doesn't have administrator access.")).toBeVisible();
  await page.getByRole("link", { name: "Go to the home page" }).click();
  await expect(page).toHaveURL(home);
  await expect(page.locator(".identity-row")).toContainText(user.email);

  // Signed in with the wrong account: the second action signs out of the console and the auth
  // server, and ends on the home page, signed out.
  await page.goto(`${env.adminUrl}/admin/clients`);
  await page.getByRole("button", { name: "Sign out to use another account" }).click();
  await page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await expect(page.locator(".identity-row")).toHaveCount(0);
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await context.close();
});

test("the sign-out confirmation asks first, and Stay signed in leaves the session as it was", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(home);
  await page.locator(".identity-row").getByRole("link", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/auth/logout`);
  await expect(page).toHaveTitle(/^Sign out – /);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign out");
  await expect(page.getByText("Do you want to sign out? This will end your session in the admin console and on the auth server.")).toBeVisible();

  await page.getByRole("link", { name: "Stay signed in", exact: true }).click();
  await expect(page).toHaveURL(home);
  await expect(page.locator(".identity-row")).toContainText(user.email);
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await expect(page.locator("#givenName")).toHaveValue("Playwright");
  await context.close();
});

test("a session the auth server stopped honouring is ended on the home page, which says so once", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  // Where the console goes when the admin API refuses its access token.
  await page.goto(`${env.adminUrl}/auth/session-ended`);
  await expect(page).toHaveURL(home);
  await expect(page.getByRole("status")).toHaveText("Your sign-in has ended. Sign in again.");
  await expect(page.locator(".identity-row")).toHaveCount(0);
  await page.reload();
  await expect(page.getByText("Your sign-in has ended. Sign in again.")).toHaveCount(0);
  await context.close();
});
