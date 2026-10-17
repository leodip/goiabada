// What the console lets a user reach: their own Account pages with authserver:manage-account, which
// every user holds, and the admin pages only with authserver:manage.
import type { Page } from "@playwright/test";
import { addPermissionRow, userUrl } from "../../../lib/admin-console";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const adminPages = ["/admin/clients", "/admin/users", "/admin/settings/general", "/admin/settings/keys"];

test("a user without authserver:manage reaches their account, and is refused every admin page", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="givenName"]')).toHaveValue("Playwright");
  // The admin link in the menu is not offered.
  await expect(page.locator('a[href="/admin/clients"]')).toHaveCount(0);

  for (const path of adminPages) {
    await page.goto(`${env.adminUrl}${path}`);
    await expect(page).toHaveURL(`${env.adminUrl}/unauthorized`);
    await expect(page.getByText("Apologies, but you don't have the required privileges to enter this page.")).toBeVisible();
  }
  // A write is refused too, not only the pages.
  const response = await page.request.post(`${env.adminUrl}/admin/settings/general`, { form: { appName: "pwned" }, maxRedirects: 0 });
  expect([302, 303, 403]).toContain(response.status());
  if (response.status() !== 403) expect(response.headers().location).toMatch(/unauthorized|\/auth\//);
  await context.close();
});

test("a user granted authserver:manage reaches the admin pages", async ({ page, browser, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "permissions"));
  await addPermissionRow(page, "authserver", "manage");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Permissions saved successfully")).toBeVisible();

  const session = await signInToConsole(browser, user, "/admin/clients");
  await expect(session.page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(session.page.getByRole("cell", { name: "admin-console-client", exact: true })).toBeVisible();
  await session.context.close();
});

// The console's sign-out is a POST the origin check guards (#411): GET /auth/logout only asks to
// confirm, and the confirmation's button posts. The auth server is then asked to end its session too,
// so the next page asks for the password again rather than signing the user straight back in.
test("signing out ends the session: the next page asks for the password again", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(`${env.adminUrl}/auth/logout`);
  await expect(page.getByRole("heading", { name: "Sign out?" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  // The auth server ends the session and returns to the console's home page.
  await page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await context.close();
});

// A page on another site, which links to the console's sign-out and posts a form to it.
const elsewhere = "https://elsewhere.example/";

async function expectStillSignedIn(page: Page) {
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page).toHaveURL(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="givenName"]')).toHaveValue("Playwright");
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
  await expect(page.getByRole("heading", { name: "Sign out?" })).toBeVisible();
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

test("signing out from the menu works without JavaScript (#411)", async ({ browser, users }) => {
  const user = await users.create();
  const { context } = await signInToConsole(browser, user);
  // The same browser's cookies, in a context that runs no script.
  const noScript = await browser.newContext({ storageState: await context.storageState(), javaScriptEnabled: false });
  const page = await noScript.newPage();
  await page.goto(`${env.adminUrl}/account/profile`);
  // The account menu is a CSS dropdown, opened by focusing its label.
  await page.locator(".dropdown > label").click();
  await page.getByRole("link", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign out?" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  // The form binding to the auth server cannot submit itself without script; its fallback button can.
  const binding = page.locator("#logoutForm");
  await expect(binding).toBeAttached();
  await binding.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.waitForURL((url) => url.origin === env.adminUrl && url.pathname === "/");
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await noScript.close();
  await context.close();
});
