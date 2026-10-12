import { deleteUser, rowWithCell, submitNewUser, userUrl } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const list = `${env.adminUrl}/admin/users`;

test("a user is created, shown on their page, found by search, and can sign in", async ({ page, request, clients }) => {
  const local = uniqueIdentifier("u");
  const email = `${local}@example.com`;
  // The address is stored in lower case and trimmed.
  await submitNewUser(page, { email: `  ${local.toUpperCase()}@Example.COM `, givenName: "Ada", familyName: "Lovelace", password: "a-good-password" });
  await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
  const id = Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]);
  try {
    const dialog = page.locator("dialog[open]");
    await expect(dialog).toContainText("User created successfully.");
    await dialog.getByRole("button", { name: "Close" }).click();

    const row = (label: string) => rowWithCell(page, label).getByRole("cell").nth(1);
    await expect(row("Email")).toHaveText(email);
    await expect(row("Full name")).toHaveText("Ada Lovelace");
    await expect(row("Subject")).toHaveText(/^[0-9a-f-]{36}$/);
    await expect(page.locator("#enabledDisabled")).toBeChecked();

    for (const query of [local, "Lovelace"]) {
      await page.goto(`${list}?query=${encodeURIComponent(query)}`);
      await expect(rowWithCell(page, email)).toHaveCount(1);
    }

    const { client, secret } = await passwordGrantClient(page, clients);
    const answer = await passwordToken(request, client.identifier, secret, email, "a-good-password", "openid");
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  } finally {
    await deleteUser(page, id);
  }
  await page.goto(`${list}?query=${local}`);
  await expect(page.getByText("Could not find any user.")).toBeVisible();
});

test("a search that matches nobody says so", async ({ page }) => {
  await page.goto(`${list}?query=nobody-matches-this-e2e-search`);
  await expect(page.getByText("Could not find any user.")).toBeVisible();
});

for (const { name, user, message } of [
  { name: "no email", user: { email: "" }, message: "The email address cannot be empty." },
  { name: "a malformed email", user: { email: "not-an-email" }, message: "Please enter a valid email address." },
  { name: "a given name with digits", user: { givenName: "R2D2" }, message: "Please enter a valid given name." },
  { name: "no password", user: { password: "" }, message: "Password is required" },
  { name: "a password under the policy's 6 characters", user: { password: "abc" }, message: "The minimum length for the password is 6 characters" },
]) {
  test(`a user with ${name} is refused, and the form keeps what was typed`, async ({ page }) => {
    const email = `${uniqueIdentifier("u")}@example.com`;
    // The two refused-email cases replace the generated address with their own.
    const defaults = { email, givenName: "Grace", familyName: "Hopper", password: "a-good-password" };
    const submitted = { ...defaults, ...user };
    await submitNewUser(page, submitted);
    await expect(page).toHaveURL(`${list}/new`);
    await expect(page.getByText(message)).toBeVisible();
    await expect(page.locator("#email")).toHaveValue(submitted.email);
    await expect(page.locator("#givenName")).toHaveValue(submitted.givenName);
    await expect(page.locator("#familyName")).toHaveValue(submitted.familyName);
    await page.goto(`${list}?query=${email.split("@")[0]}`);
    await expect(page.getByText("Could not find any user.")).toBeVisible();
  });
}

test("an email already registered is refused", async ({ page, users }) => {
  const existing = await users.create();
  await submitNewUser(page, { email: existing.email.toUpperCase(), password: "a-good-password" });
  await expect(page).toHaveURL(`${list}/new`);
  await expect(page.getByText("This email address is already registered")).toBeVisible();
});

test("the system administrator is listed, and their page opens", async ({ page }) => {
  await page.goto(`${list}?query=${encodeURIComponent(env.adminEmail)}`);
  const row = rowWithCell(page, env.adminEmail);
  await expect(row).toHaveCount(1);
  const href = await row.getByRole("link", { name: "Manage" }).getAttribute("href");
  const id = Number(href!.match(/\/admin\/users\/(\d+)\//)![1]);
  await page.goto(userUrl(id, "details"));
  await expect(rowWithCell(page, "Email").getByRole("cell").nth(1)).toHaveText(env.adminEmail);
});
