import { cancelDialog, clientRow, clientUrl, confirmDialog, rowWithCell } from "../../../lib/admin-console";
import { signInThroughClient } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { authorizeAgain } from "../../../lib/sessions";
import { browserSignInClient } from "../../../lib/test-clients";

test("a new client has no user sessions", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "user-sessions"));
  await expect(page.getByText("No one is signed in to this client.")).toBeVisible();
});

test("a user signed in through the client is listed, and End session asks first, then signs them out", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  await page.goto(clientUrl(client.id, "user-sessions"));
  const row = rowWithCell(page, user.email);
  await expect(row).toHaveCount(1);
  const end = row.getByRole("button", { name: /^End session/ });

  // Cancel leaves the session as it was.
  await end.click();
  await cancelDialog(page, `End the session of ${user.email} on`);
  await expect(end).toBeVisible();

  await end.click();
  await confirmDialog(page, `End the session of ${user.email} on`);
  // The button gives way to a tag, and the page says so.
  await expect(row.getByText("Ended", { exact: true })).toBeVisible();
  await expect(end).toHaveCount(0);
  await expect(page.locator("#sessions-status")).toContainText("Session ended.");

  // The browser holds no session any more: signing in again asks for the password.
  const again = await authorizeAgain(signIn.context, client.identifier);
  expect(again.landed).toBe("password");
  await signIn.context.close();
});

test("the admin console client lists the administrator's own session on this device", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await clientRow(page, "admin-console-client").getByRole("link", { name: "admin-console-client", exact: true }).click();
  await page.getByRole("navigation", { name: "Sections" }).getByRole("link", { name: "Sessions", exact: true }).click();
  await expect(page).toHaveURL(/\/user-sessions$/);
  const current = page.getByRole("row").filter({ has: page.getByText("This device", { exact: true }) });
  await expect(current).toHaveCount(1);
  await expect(current.getByRole("link", { name: env.adminEmail, exact: true })).toBeVisible();

  // Ending it would sign the suite out: its question says so, and Cancel keeps it.
  await current.getByRole("button", { name: /^End session/ }).click();
  await cancelDialog(page, "It's your own, on the device you're using, so you'll be signed out.");
  await expect(current.getByRole("button", { name: /^End session/ })).toBeVisible();
  await expect(page.locator("#sessions-status")).toBeEmpty();
});
