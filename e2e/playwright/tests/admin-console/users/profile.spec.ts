import type { Page } from "@playwright/test";
import { userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const saved = "Profile saved successfully";

// The value of the first option of a select whose value matches.
async function optionValue(page: Page, name: string, pattern: RegExp): Promise<string> {
  const values = await page.locator(`select[name="${name}"] option`).evaluateAll((options) =>
    options.map((o) => (o as HTMLOptionElement).value),
  );
  const value = values.find((v) => pattern.test(v));
  if (!value) throw new Error(`no ${name} option matching ${pattern}`);
  return value;
}

function usernameFor(id: number) {
  // Letters, digits and underscores, 2 to 24 characters.
  return `e2e_${id}_${uniqueIdentifier("x").slice(-6)}`;
}

test("the profile is saved, shown again, and reaches the profile claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const username = usernameFor(user.id);
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="givenName"]').fill("Mary");
  await page.locator('input[name="middleName"]').fill("Ann");
  await page.locator('input[name="familyName"]').fill("O'Brien-Smith");
  await page.locator('input[name="nickname"]').fill("mob");
  await page.locator('input[name="website"]').fill("https://mary.example.com");
  await page.locator('select[name="gender"]').selectOption("0");
  await page.locator('input[name="dateOfBirth"]').fill("1990-05-17");
  const zone = await optionValue(page, "zoneInfo", /___Europe\/Lisbon$/);
  await page.locator('select[name="zoneInfo"]').selectOption(zone);
  const locale = await optionValue(page, "locale", /^pt-BR$/);
  await page.locator('select[name="locale"]').selectOption(locale);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="username"]')).toHaveValue(username);
  await expect(page.locator('input[name="familyName"]')).toHaveValue("O'Brien-Smith");
  await expect(page.locator('select[name="gender"]')).toHaveValue("0");
  await expect(page.locator('input[name="dateOfBirth"]')).toHaveValue("1990-05-17");
  await expect(page.locator('select[name="zoneInfo"]')).toHaveValue(zone);
  await expect(page.locator('select[name="locale"]')).toHaveValue(locale);

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(id).toMatchObject({
    preferred_username: username,
    given_name: "Mary",
    middle_name: "Ann",
    family_name: "O'Brien-Smith",
    name: "Mary Ann O'Brien-Smith",
    nickname: "mob",
    website: "https://mary.example.com",
    gender: "female",
    birthdate: "1990-05-17",
    zoneinfo: "Europe/Lisbon",
    locale,
  });
  expect(typeof id.updated_at).toBe("number");
});

for (const { field, value, message } of [
  { field: "username", value: "1abc", message: "Usernames must start with a letter" },
  { field: "givenName", value: "M4ry", message: "Please enter a valid given name." },
  { field: "familyName", value: "x", message: "Please enter a valid family name." },
  { field: "nickname", value: "has space", message: "Nicknames must start with a letter" },
  { field: "website", value: "not a url", message: "Please enter a valid website URL." },
  { field: "dateOfBirth", value: "17/05/1990", message: "The date of birth is invalid. Please use the format YYYY-MM-DD." },
  { field: "dateOfBirth", value: "2999-01-01", message: "The date of birth can't be in the future." },
]) {
  test(`the ${field} ${JSON.stringify(value)} is refused, and the form keeps it`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "profile"));
    await page.locator(`input[name="${field}"]`).fill(value);
    await page.locator("#btnSave").click();
    await expect(page.getByText(message)).toBeVisible();
    // The form echoes what was typed, a date of birth it cannot parse included.
    await expect(page.locator(`input[name="${field}"]`)).toHaveValue(value);
    await page.goto(userUrl(user.id, "profile"));
    await expect(page.locator(`input[name="${field}"]`)).not.toHaveValue(value);
  });
}

test("a username already taken is refused", async ({ page, users }) => {
  const first = await users.create();
  const second = await users.create();
  const username = usernameFor(first.id);
  await page.goto(userUrl(first.id, "profile"));
  await page.locator('input[name="username"]').fill(username);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.goto(userUrl(second.id, "profile"));
  await page.locator('input[name="username"]').fill(username);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Sorry, this username is already taken.")).toBeVisible();
});
