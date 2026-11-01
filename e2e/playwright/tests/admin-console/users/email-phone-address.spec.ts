import { choose, expectRefusal, userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken, userinfo, userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const saved = "Changes saved.";
const portugal = /Portugal \(\+351\)$/;

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
  // The heading names the user by the address as stored.
  await expect(page.getByRole("heading", { level: 1, name: newEmail, exact: true })).toBeVisible();

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
    await expectRefusal(page, "email-error", "email", message);
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
  await expectRefusal(page, "email-error", "email", "Apologies, but this email address is already registered.");
});

test("a phone number is saved and reaches the phone claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "phone"));
  await choose(page, "phoneCountryUniqueId", "Portugal", portugal);
  await page.locator('input[name="phoneNumber"]').fill("912 345 678");
  await page.locator('input[name="phoneNumberVerified"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.locator("#phoneCountryUniqueId")).toHaveValue(portugal);
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
  await choose(page, "phoneCountryUniqueId", "Portugal", portugal);
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

test("a phone number is removed by choosing no country and leaving the number empty", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "phone"));
  await choose(page, "phoneCountryUniqueId", "Portugal", portugal);
  await page.locator('input[name="phoneNumber"]').fill("912 345 678");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  // Opened afresh, so the notice read next is this save's.
  await page.goto(userUrl(user.id, "phone"));
  await choose(page, "phoneCountryUniqueId", "Not set", "Not set");
  await page.locator('input[name="phoneNumber"]').fill("");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.goto(userUrl(user.id, "phone"));
  await expect(page.locator("#phoneCountryUniqueId")).toHaveValue("");
  await expect(page.locator('input[name="phoneNumber"]')).toHaveValue("");
});

for (const { name, country, number, field, message } of [
  { name: "a number with letters", country: true, number: "91x 345 678", field: "phoneNumber", message: "Please enter a valid number." },
  { name: "a number with no country", country: false, number: "912 345 678", field: "phoneCountryUniqueId", message: "You must select a country for your phone number." },
  { name: "a country with no number", country: true, number: "", field: "phoneNumber", message: "Enter the phone number. To remove it, set the country to Not set." },
]) {
  test(`${name} is refused`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "phone"));
    if (country) await choose(page, "phoneCountryUniqueId", "Portugal", portugal);
    await page.locator('input[name="phoneNumber"]').fill(number);
    await page.locator("#btnSave").click();
    await expectRefusal(page, "phone-error", field, message);
    // Drawn with the stored user: the heading and the tab's title name them, the Phone tab is the
    // current one, and every tab links to their pages.
    await expect(page.getByRole("heading", { level: 1, name: user.email, exact: true })).toBeVisible();
    await expect(page).toHaveTitle(new RegExp(`^Phone – ${user.email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} – `));
    const tabBar = page.getByRole("navigation", { name: "Sections" });
    const tabs = tabBar.getByRole("link");
    await expect(tabs).toHaveCount(13);
    await expect(tabBar.getByRole("link", { name: "Phone", exact: true })).toHaveAttribute("aria-current", "page");
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
  await choose(page, "addressCountry", "Portugal", /Portugal$/);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.locator('input[name="addressLine1"]')).toHaveValue("Rua Augusta 100");
  await expect(page.locator("#addressCountry")).toHaveValue(/Portugal$/);

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid address");
  expect(id.address).toMatchObject({
    street_address: "Rua Augusta 100\r\n3rd floor",
    locality: "Lisboa",
    region: "Lisboa",
    postal_code: "1100-053",
  });
});

for (const { name, field, value, message, marked } of [
  { name: "an over-long postal code", field: "addressPostalCode", value: "1".repeat(31), message: "Please ensure the postal code is no longer than", marked: true },
  // Angle brackets are refused in whichever field holds them, so that refusal marks none.
  { name: "angle brackets", field: "addressLine1", value: "<b>street</b>", message: "Address fields cannot contain the characters < or >.", marked: false },
]) {
  test(`an address with ${name} is refused`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "address"));
    await page.locator(`input[name="${field}"]`).fill(value);
    await page.locator("#btnSave").click();
    if (marked) await expectRefusal(page, "address-error", field, message);
    else await expect(page.locator("#address-error")).toContainText(message);
    await page.goto(userUrl(user.id, "address"));
    await expect(page.locator(`input[name="${field}"]`)).toHaveValue("");
  });
}
