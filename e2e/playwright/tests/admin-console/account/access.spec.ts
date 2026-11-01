// What the console lets a user reach: their own Account pages with authserver:manage-account, which
// every user holds, and the admin pages only with authserver:manage.
import type { Page } from "@playwright/test";
import { clientRow, grantUserPermission } from "../../../lib/admin-console";
import { expectCardHeldBack } from "../../../lib/auto-submit";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const adminPages = ["/admin/clients", "/admin/users", "/admin/settings/general", "/admin/settings/keys"];

test("a user without authserver:manage reaches their account, and is refused every admin page", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await expect(page.locator("#givenName")).toHaveValue("Playwright");
  // The admin link is not offered, in the menu or on the home page, which shows Administration only
  // to an administrator or to someone not signed in yet.
  await expect(page.locator('a[href="/admin/clients"]')).toHaveCount(0);
  await page.goto(`${env.adminUrl}/`);
  await expect(page.getByRole("link", { name: /^Your account/ })).toBeVisible();
  await expect(page.locator('a[href="/admin/clients"]')).toHaveCount(0);

  for (const path of adminPages) {
    await page.goto(`${env.adminUrl}${path}`);
    await expect(page).toHaveURL(`${env.adminUrl}/unauthorized`);
    await expect(page.getByRole("heading", { name: "Administrators only" })).toBeVisible();
    await expect(page.getByText("This page is for administrators, and your account doesn't have administrator access.")).toBeVisible();
  }
  // A write is refused too, not only the pages.
  const response = await page.request.post(`${env.adminUrl}/admin/settings/general`, { form: { appName: "pwned" }, maxRedirects: 0 });
  expect([302, 303, 403]).toContain(response.status());
  if (response.status() !== 403) expect(response.headers().location).toMatch(/unauthorized|\/auth\//);
  await context.close();
});

test("a user granted authserver:manage reaches the admin pages", async ({ page, browser, users }) => {
  const user = await users.create();
  await grantUserPermission(page, user.id, "authserver", "manage");

  const session = await signInToConsole(browser, user, "/admin/clients");
  await expect(session.page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(session.page, "admin-console-client")).toBeVisible();
  // The home page offers them Administration.
  await session.page.goto(`${env.adminUrl}/`);
  await expect(session.page.getByRole("link", { name: /^Administration/ })).toHaveAttribute("href", "/admin/clients");
  await session.context.close();
});

// The console's sign-out is a POST the origin check guards (#411): GET /auth/logout only asks to
// confirm, and the confirmation's button posts. The auth server is then asked to end its session too,
// so the next page asks for the password again rather than signing the user straight back in.
test("signing out ends the session: the next page asks for the password again", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(`${env.adminUrl}/auth/logout`);
  await expect(page.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  // The auth server ends the session and returns to the console's home page.
  await page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator("#password")).toBeVisible();
  await context.close();
});

// A page on another site, which links to the console's sign-out and posts a form to it.
const elsewhere = "https://elsewhere.example/";

async function expectStillSignedIn(page: Page) {
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await expect(page.locator("#givenName")).toHaveValue("Playwright");
}

test("another site cannot sign the user out, by a link or by a form (#411)", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await context.route(`${elsewhere}**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: `<a href="${env.adminUrl}/auth/logout">Follow</a>
        <form method="post" action="${env.adminUrl}/auth/logout"><button type="submit">Post</button></form>`,
    }),
  );

  // A link from another site only reaches the confirmation, which signs nobody out.
  await page.goto(elsewhere);
  await page.getByRole("link", { name: "Follow" }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/auth/logout`);
  await expect(page.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await expectStillSignedIn(page);

  // A form posted from another site is refused by the origin check before the sign-out runs.
  await page.goto(elsewhere);
  const [refused] = await Promise.all([
    page.waitForResponse((response) => response.url() === `${env.adminUrl}/auth/logout` && response.request().method() === "POST"),
    page.getByRole("button", { name: "Post" }).click(),
  ]);
  expect(refused.status()).toBe(403);
  await expectStillSignedIn(page);
  await context.close();
});

// The header's user menu opens only with script, like the rest of the console's controls; the home
// page's Sign out is a plain link, and from there the sign-out takes no script at all.
test("signing out from the home page works without JavaScript (#411)", async ({ browser, users }) => {
  const user = await users.create();
  const { context } = await signInToConsole(browser, user);
  // The same browser's cookies, in a context that runs no script.
  const noScript = await browser.newContext({ storageState: await context.storageState(), javaScriptEnabled: false });
  const page = await noScript.newPage();
  await page.goto(`${env.adminUrl}/`);
  await page.getByRole("link", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  // The form binding to the auth server cannot submit itself without script; its Continue button can.
  const binding = page.locator("form.auth-status[data-auto-submit]");
  await expect(binding.getByRole("heading", { name: "Signing you out" })).toBeVisible();
  await expectCardHeldBack(page);
  await binding.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator("#password")).toBeVisible();
  await noScript.close();
  await context.close();
});
