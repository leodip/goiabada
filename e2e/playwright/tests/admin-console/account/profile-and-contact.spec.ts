// The user's own profile, email, phone and address pages, which the administrator sees the same way.
import type { Page } from "@playwright/test";
import { userUrl } from "../../../lib/admin-console";
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { uniqueIdentifier } from "../../../lib/unique";

async function optionByLabel(page: Page, name: string, label: RegExp): Promise<string> {
  return (await page.locator(`select[name="${name}"] option`).filter({ hasText: label }).first().getAttribute("value"))!;
}

test("the user edits their own profile, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  await own.page.locator('input[name="givenName"]').fill("Katherine");
  await own.page.locator('input[name="familyName"]').fill("Johnson");
  await own.page.locator('input[name="nickname"]').fill("kat");
  await own.page.getByRole("button", { name: "Update" }).click();
  await expect(own.page.getByText("Profile saved successfully")).toBeVisible();

  // Refused like on the admin's page.
  await own.page.locator('input[name="givenName"]').fill("K4therine");
  await own.page.getByRole("button", { name: "Update" }).click();
  await expect(own.page.getByText("Please enter a valid given name.")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "profile"));
  await expect(page.locator('input[name="givenName"]')).toHaveValue("Katherine");
  await expect(page.locator('input[name="nickname"]')).toHaveValue("kat");
});

test("the user's refused date of birth is kept as typed, and their stored one stays", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user);
  const dateOfBirth = own.page.locator('input[name="dateOfBirth"]');
  await dateOfBirth.fill("1990-05-17");
  await own.page.getByRole("button", { name: "Update" }).click();
  await expect(own.page.getByText("Profile saved successfully")).toBeVisible();

  await dateOfBirth.fill("17/05/1991");
  await own.page.getByRole("button", { name: "Update" }).click();
  await expect(own.page.getByText("The date of birth is invalid. Please use the format YYYY-MM-DD.")).toBeVisible();
  await expect(dateOfBirth).toHaveValue("17/05/1991");
  await own.page.goto(`${env.adminUrl}/account/profile`);
  await expect(dateOfBirth).toHaveValue("1990-05-17");
  await own.context.close();
});

test("the user changes their email with their password, which must be right and confirmed", async ({ page, browser, users }) => {
  const user = await users.create();
  const newEmail = `${uniqueIdentifier("u")}@example.com`;
  const own = await signInToConsole(browser, user, "/account/email");
  const submit = async (email: string, confirmation: string, password: string) => {
    await own.page.locator('input[name="email"]').fill(email);
    await own.page.locator('input[name="emailConfirmation"]').fill(confirmation);
    await own.page.locator('input[name="currentPassword"]').fill(password);
    await own.page.getByRole("button", { name: "Update email" }).click();
  };

  await submit(newEmail, `x${newEmail}`, user.password);
  await expect(own.page.getByText("The email and email confirmation entries must be identical.")).toBeVisible();
  await submit(newEmail, newEmail, "not-the-password");
  await expect(own.page.getByText("Authentication failed. Check your current password and try again.")).toBeVisible();
  await submit(newEmail, newEmail, user.password);
  await expect(own.page.getByText("Email updated successfully")).toBeVisible();

  // A new address starts unverified; verifying it with the mailed code is in email.spec.ts.
  await own.page.goto(`${env.adminUrl}/account/email-verification`);
  await expect(own.page.getByText("isn't verified")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "email"));
  await expect(page.locator('input[name="email"]')).toHaveValue(newEmail);
  await expect(page.locator('input[name="emailVerified"]')).not.toBeChecked();
});

test("the user saves their phone, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/phone");
  // The page loads its country list for a user who is not an administrator too.
  await expect(own.page.locator('select[name="phoneCountryUniqueId"]')).toBeVisible();
  await expect(own.page.getByText("Enter the number as it's dialled from another country, after the country code.")).toBeVisible();
  const country = await optionByLabel(own.page, "phoneCountryUniqueId", /Portugal/);
  await own.page.locator('select[name="phoneCountryUniqueId"]').selectOption(country);
  // A refused number draws the page again, country list and all, with the refusal on it.
  await own.page.locator('input[name="phoneNumber"]').fill("91x 345 678");
  await own.page.getByRole("button", { name: "Update phone" }).click();
  await expect(own.page.getByText("Please enter a valid number.")).toBeVisible();
  await expect(own.page.locator('select[name="phoneCountryUniqueId"]')).toHaveValue(country);
  await own.page.locator('input[name="phoneNumber"]').fill("912 345 678");
  await own.page.getByRole("button", { name: "Update phone" }).click();
  await expect(own.page.getByText("Phone number updated successfully")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "phone"));
  await expect(page.locator('select[name="phoneCountryUniqueId"]')).toHaveValue(country);
  await expect(page.locator('input[name="phoneNumber"]')).toHaveValue("912 345 678");
});

test("the user saves their address, and the administrator sees it", async ({ page, browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/address");
  await own.page.locator('input[name="addressLine1"]').fill("Rua Augusta 100");
  await own.page.locator('input[name="addressLocality"]').fill("Lisboa");
  await own.page.locator('input[name="addressPostalCode"]').fill("1100-053");
  await own.page.getByRole("button", { name: "Update" }).click();
  await expect(own.page.getByText("Address saved successfully")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "address"));
  await expect(page.locator('input[name="addressLine1"]')).toHaveValue("Rua Augusta 100");
  await expect(page.locator('input[name="addressPostalCode"]')).toHaveValue("1100-053");
});
