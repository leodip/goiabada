// What the console lets a user reach: their own Account pages with authserver:manage-account, which
// every user holds, and the admin pages only with authserver:manage.
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

test("signing out ends the session: the next page asks for the password again", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page } = await signInToConsole(browser, user);
  await page.goto(`${env.adminUrl}/auth/logout`);
  // The auth server ends the session and returns; whatever page it lands on, the console is signed out.
  await page.waitForLoadState("networkidle");
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await context.close();
});
