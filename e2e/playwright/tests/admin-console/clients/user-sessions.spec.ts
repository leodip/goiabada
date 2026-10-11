import { clientRow, clientUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

test("a new client has no user sessions", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "user-sessions"));
  await expect(page.getByText("No sessions found.")).toBeVisible();
});

test("the admin console client lists the administrator's own session as current", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await clientRow(page, "admin-console-client").getByRole("link", { name: "Manage" }).click();
  await page.getByRole("link", { name: "User sessions" }).click();
  await expect(page).toHaveURL(/\/user-sessions$/);
  await expect(page.getByText(env.adminEmail).first()).toBeVisible();
  await expect(page.getByText("Current session")).toBeVisible();
  // Ending it would sign the suite out; that waits for a second user.
});
