import { choose, expectRefusal, userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { userTokens } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const saved = "Profile saved.";

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
  // The time zone and the language are searched for, each entry naming its zone or its tag.
  await choose(page, "zoneInfo", "Europe/Lisbon", /Europe\/Lisbon/);
  await choose(page, "locale", "pt-BR", /^pt-BR – /);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="username"]')).toHaveValue(username);
  await expect(page.locator('input[name="familyName"]')).toHaveValue("O'Brien-Smith");
  await expect(page.locator('select[name="gender"]')).toHaveValue("0");
  await expect(page.locator('input[name="dateOfBirth"]')).toHaveValue("1990-05-17");
  await expect(page.locator("#zoneInfo")).toHaveValue(/Europe\/Lisbon/);
  await expect(page.locator("#locale")).toHaveValue(/^pt-BR – /);
  // What the form posts: the hidden selects behind the two fields.
  await expect(page.locator('select[name="zoneInfo"]')).toHaveValue(/___Europe\/Lisbon$/);
  await expect(page.locator('select[name="locale"]')).toHaveValue("pt-BR");

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
    locale: "pt-BR",
  });
  expect(typeof id.updated_at).toBe("number");
});

test("one-character names are saved, shown again, and reach the profile claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="givenName"]').fill("김");
  await page.locator('input[name="middleName"]').fill("J");
  await page.locator('input[name="familyName"]').fill("王");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="givenName"]')).toHaveValue("김");
  await expect(page.locator('input[name="middleName"]')).toHaveValue("J");
  await expect(page.locator('input[name="familyName"]')).toHaveValue("王");

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(id).toMatchObject({ given_name: "김", middle_name: "J", family_name: "王", name: "김 J 王" });
});

// A name is written with the marks on its letters, as Hindi's vowel signs are, and with the
// typographic apostrophe an iPhone types (#669).
test("names written with marks and the typographic apostrophe are saved, shown again, and reach the profile claims", async ({ page, request, clients, users }) => {
  const user = await users.create();
  // अमित: a, ma, the vowel sign i (a spacing mark), ta.
  const givenName = "\u0905\u092E\u093F\u0924";
  const familyName = "O\u2019Brien";
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="givenName"]').fill(givenName);
  await page.locator('input[name="familyName"]').fill(familyName);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="givenName"]')).toHaveValue(givenName);
  await expect(page.locator('input[name="familyName"]')).toHaveValue(familyName);

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(id).toMatchObject({ given_name: givenName, family_name: familyName, name: `${givenName} ${familyName}` });
});

// A nickname is a casual name, free text rather than a username's shape (#632).
test("a nickname with a space is saved, shown again, and reaches the nickname claim", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="nickname"]').fill("Amazing Grace");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await page.reload();
  await expect(page.locator('input[name="nickname"]')).toHaveValue("Amazing Grace");

  const { client, secret } = await passwordGrantClient(page, clients);
  const { id } = await userTokens(request, client.identifier, secret, user, "openid profile");
  expect(id).toMatchObject({ nickname: "Amazing Grace" });
});

for (const { field, value, message } of [
  { field: "username", value: "1abc", message: "Usernames must start with a letter" },
  { field: "givenName", value: "M4ry", message: "Please enter a valid given name." },
  // A name needs a letter, so a lone hyphen is refused where a lone letter is not.
  { field: "familyName", value: "-", message: "Please enter a valid family name." },
  // At most four nonspacing marks stack on one letter, so a name cannot draw over the page (#669).
  { field: "givenName", value: "a\u0301\u0302\u0303\u0304\u0306", message: "Please enter a valid given name." },
  // A nickname is free text, but angle brackets are refused rather than stripped (#275, #632).
  { field: "nickname", value: "ni<ck", message: "The nickname cannot contain the characters < or >." },
  { field: "website", value: "not a url", message: "Please enter a valid website URL." },
  { field: "dateOfBirth", value: "17/05/1990", message: "The date of birth is invalid. Please use the format YYYY-MM-DD." },
  { field: "dateOfBirth", value: "2999-01-01", message: "The date of birth can't be in the future." },
]) {
  test(`the ${field} ${JSON.stringify(value)} is refused, and the form keeps it`, async ({ page, users }) => {
    const user = await users.create();
    await page.goto(userUrl(user.id, "profile"));
    await page.locator(`input[name="${field}"]`).fill(value);
    await page.locator("#btnSave").click();
    await expectRefusal(page, "profile-error", field, message);
    // The form echoes what was typed, a date of birth it cannot parse included.
    await expect(page.locator(`input[name="${field}"]`)).toHaveValue(value);
    await page.goto(userUrl(user.id, "profile"));
    await expect(page.locator(`input[name="${field}"]`)).not.toHaveValue(value);
  });
}

test("a refused date of birth over a stored one is kept as typed, and the stored one stays", async ({ page, users }) => {
  const user = await users.create();
  const dateOfBirth = page.locator('input[name="dateOfBirth"]');
  await page.goto(userUrl(user.id, "profile"));
  await dateOfBirth.fill("1990-05-17");
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await dateOfBirth.fill("17/05/1991");
  await page.locator("#btnSave").click();
  await expectRefusal(page, "profile-error", "dateOfBirth", "The date of birth is invalid. Please use the format YYYY-MM-DD.");
  // What was typed, not the stored date beside a refusal of it.
  await expect(dateOfBirth).toHaveValue("17/05/1991");
  await page.goto(userUrl(user.id, "profile"));
  await expect(dateOfBirth).toHaveValue("1990-05-17");
});

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
  await expectRefusal(page, "profile-error", "username", "Sorry, this username is already taken.");
});
