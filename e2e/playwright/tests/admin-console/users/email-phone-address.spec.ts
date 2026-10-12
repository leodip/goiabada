import type { Page } from "@playwright/test";
import { userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken, userinfo, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const saved = "Saved successfully";

// The value of the first option of a select whose label matches.
async function optionByLabel(page: Page, name: string, label: RegExp): Promise<string> {
  const option = page.locator(`select[name="${name}"] option`).filter({ hasText: label }).first();
  return (await option.getAttribute("value"))!;
}

test("a new email is saved, signs in in place of the old one, and reaches the email claims", async ({
  page,
  request,
  clients,
  users,
}) => {
  const user = await users.create();
  const newEmail = `${uniqueIdentifier("u")}@example.com`;
  await page.goto(userUrl(user.id, "email"));
  await expect(page.locator('input[name="email"]')).toHaveValue(user.email);
  await page.locator('input[name="email"]').fill(newEmail);
  await page.locator('input[name="emailVerified"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.locator('input[name="email"]')).toHaveValue(newEmail);
  await expect(page.locator('input[name="emailVerified"]')).toBeChecked();

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, { email: newEmail, password: user.password }, "openid email");
  expect(id.email).toBe(newEmail);
  expect(id.email_verified).toBe(true);
  const old = await passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect(old.body.error).toBe("invalid_grant");
});

for (const { name, value, message } of [
  { name: "malformed", value: "not-an-email", message: "Please enter a valid email address." },
  { name: "empty", value: "", message: "Please enter an email address." },
]) {
  test(`an ${name} email is refused`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "email"));
    await page.locator('input[name="email"]').fill(value);
    await page.locator("#btnSave").click();
    await expect(page.getByText(message)).toBeVisible();
    await page.goto(userUrl(user.id, "email"));
    await expect(page.locator('input[name="email"]')).toHaveValue(user.email);
  });
}

test("another user's email is refused", async ({ page, users }) => {
  const first = await users.create();
  const second = await users.create();
  await page.goto(userUrl(second.id, "email"));
  await page.locator('input[name="email"]').fill(first.email);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Apologies, but this email address is already registered.")).toBeVisible();
});

test("a phone number is saved and reaches the phone claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "phone"));
  const country = await optionByLabel(page, "phoneCountryUniqueId", /Portugal/);
  await page.locator('select[name="phoneCountryUniqueId"]').selectOption(country);
  await page.locator('input[name="phoneNumber"]').fill("912 345 678");
  await page.locator('input[name="phoneNumberVerified"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.locator('select[name="phoneCountryUniqueId"]')).toHaveValue(country);
  await expect(page.locator('input[name="phoneNumber"]')).toHaveValue("912 345 678");

  const { client, secret } = await passwordGrantClient(page, clients);
  const { body, id } = await userTokens(request, client.identifier, secret, user, "openid phone");
  // In E.164, the calling code then the digits with no spacing, in the ID token and at /userinfo alike.
  expect(id.phone_number).toBe("+351912345678");
  expect(id.phone_number_verified).toBe(true);
  const info = await userinfo(request, body.access_token as string);
  expect(info.status).toBe(200);
  expect(info.body.phone_number).toBe("+351912345678");
  expect(info.body.phone_number_verified).toBe(true);
});

test("a number too long for E.164 with its calling code is saved, but left out of the claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "phone"));
  await expect(page.getByText("Enter the number as it's dialled from another country, after the country code.")).toBeVisible();
  await page.locator('select[name="phoneCountryUniqueId"]').selectOption(await optionByLabel(page, "phoneCountryUniqueId", /Portugal/));
  // 13 digits, 16 with Portugal's 351: the form takes up to 30 characters, E.164 at most 15 digits.
  await page.locator('input[name="phoneNumber"]').fill("9123 4567 89123");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  const { client, secret } = await passwordGrantClient(page, clients);
  const { body, id } = await userTokens(request, client.identifier, secret, user, "openid phone");
  expect(id).not.toHaveProperty("phone_number");
  expect(id.phone_number_verified).toBe(false);
  const info = await userinfo(request, body.access_token as string);
  expect(info.body).not.toHaveProperty("phone_number");
});

for (const { name, country, number, message } of [
  { name: "a number with letters", country: /Portugal/, number: "91x 345 678", message: "Please enter a valid number." },
  { name: "a number with no country", country: null, number: "912 345 678", message: "You must select a country for your phone number." },
  { name: "a country with no number", country: /Portugal/, number: "", message: "The phone number field must contain a valid phone number." },
]) {
  test(`${name} is refused`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "phone"));
    if (country) await page.locator('select[name="phoneCountryUniqueId"]').selectOption(await optionByLabel(page, "phoneCountryUniqueId", country));
    await page.locator('input[name="phoneNumber"]').fill(number);
    await page.locator("#btnSave").click();
    await expect(page.getByText(message)).toBeVisible();
    // Drawn with the stored user: the title names them, and every tab links to their pages.
    await expect(page.getByRole("heading", { name: `User - Phone - ${user.email}`, exact: true })).toBeVisible();
    const tabs = page.locator(".tabs a");
    await expect(tabs).toHaveCount(12);
    for (const href of await tabs.evaluateAll((links) => links.map((a) => a.getAttribute("href")))) {
      expect(href).toMatch(new RegExp(`^/admin/users/${user.id}/`));
    }
    await page.goto(userUrl(user.id, "phone"));
    await expect(page.locator('input[name="phoneNumber"]')).toHaveValue("");
  });
}

test("an address is saved and reaches the address claim", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "address"));
  await page.locator('input[name="addressLine1"]').fill("Rua Augusta 100");
  await page.locator('input[name="addressLine2"]').fill("3rd floor");
  await page.locator('input[name="addressLocality"]').fill("Lisboa");
  await page.locator('input[name="addressRegion"]').fill("Lisboa");
  await page.locator('input[name="addressPostalCode"]').fill("1100-053");
  const country = await optionByLabel(page, "addressCountry", /Portugal/);
  await page.locator('select[name="addressCountry"]').selectOption(country);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.locator('input[name="addressLine1"]')).toHaveValue("Rua Augusta 100");
  await expect(page.locator('select[name="addressCountry"]')).toHaveValue(country);

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid address");
  expect(id.address).toMatchObject({
    street_address: "Rua Augusta 100\r\n3rd floor",
    locality: "Lisboa",
    region: "Lisboa",
    postal_code: "1100-053",
  });
});

for (const { name, field, value, message } of [
  { name: "an over-long postal code", field: "addressPostalCode", value: "1".repeat(31), message: "Please ensure the postal code is no longer than" },
  { name: "angle brackets", field: "addressLine1", value: "<b>street</b>", message: "Address fields cannot contain the characters < or >." },
]) {
  test(`an address with ${name} is refused`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "address"));
    await page.locator(`input[name="${field}"]`).fill(value);
    await page.locator("#btnSave").click();
    await expect(page.getByText(message)).toBeVisible();
    await page.goto(userUrl(user.id, "address"));
    await expect(page.locator(`input[name="${field}"]`)).toHaveValue("");
  });
}
