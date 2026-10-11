import { expect, test, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { env } from "../../lib/environment";

// A protected admin console page sends a visitor with no session to the auth server's password page.
async function startSignIn(page: Page) {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
}

async function submitPassword(page: Page, email: string, password: string) {
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function expectSignedIn(page: Page) {
  // Back on the admin console, on the page asked for, signed in.
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveTitle(/Admin - Clients/);
  await expect(page.getByText(env.adminEmail, { exact: true })).toBeVisible();
}

async function expectRefused(page: Page, message: string) {
  // The password page again, with the message, and still no session at the admin console.
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(page.getByText(message, { exact: true })).toBeVisible();
  await expect(page.locator('input[name="password"]')).toHaveValue("");
}

test("the administrator signs in to the admin console through the auth server", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expectSignedIn(page);

  // The list comes from the auth server's admin API with the administrator's token: the admin
  // console's own client, which the first start seeded, is in it.
  await expect(page.getByRole("cell", { name: "admin-console-client", exact: true })).toBeVisible();
});

// No negative test here uses a wrong password for the administrator: every one counts against the
// account's failure budget (10 per 15 minutes from one address, held in memory until the next
// reset), so a few runs in a row would lock the administrator out and fail every test after them.
// A wrong password for a real account waits for throwaway users.

test("an address that names no account is refused, and the same sign-in then succeeds", async ({ page }) => {
  await startSignIn(page);
  // A fresh address each run, so its failure budget is never shared with another run's.
  const nobody = `nobody-${randomUUID()}@example.com`;
  await submitPassword(page, nobody, "not-a-password-anyone-has");

  await expectRefused(page, "Authentication failed.");
  // The address typed stays in the form for the retry.
  await expect(page.locator('input[name="email"]')).toHaveValue(nobody);

  // A mistake does not end the sign-in: the re-rendered form carries it on.
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expectSignedIn(page);
});

test("an empty email is refused before any password is checked", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, "", "anything");
  await expectRefused(page, "Email is required.");
});

test("an empty password is refused before it is checked", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, env.adminEmail, "");
  await expectRefused(page, "Password is required.");
  await expect(page.locator('input[name="email"]')).toHaveValue(env.adminEmail);
});

test("without signing in, the admin console's pages stay out of reach", async ({ page }) => {
  for (const path of ["/admin/clients", "/admin/users", "/admin/settings/general"]) {
    await page.goto(`${env.adminUrl}${path}`);
    await expect(page, `${path} should send the visitor to sign in`).toHaveURL(
      new RegExp(`^${env.authUrl}/auth/pwd\\?`),
    );
  }
});
