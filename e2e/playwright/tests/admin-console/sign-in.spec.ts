import { expect, test } from "@playwright/test";
import { env } from "../../lib/environment";

test("the administrator signs in to the admin console through the auth server", async ({ page }) => {
  // A protected page sends a visitor with no session to the auth server's password page.
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));

  await page.locator('input[name="email"]').fill(env.adminEmail);
  await page.locator('input[name="password"]').fill(env.adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Back on the admin console, on the page asked for, signed in.
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveTitle(/Admin - Clients/);
  await expect(page.getByText(env.adminEmail, { exact: true })).toBeVisible();

  // The list comes from the auth server's admin API with the administrator's token: the admin
  // console's own client, which the first start seeded, is in it.
  await expect(page.getByRole("cell", { name: "admin-console-client", exact: true })).toBeVisible();
});
