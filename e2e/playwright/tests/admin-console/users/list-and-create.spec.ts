import { deleteUser, detail, expectRefusal, idFromListLink, rowWithCell, submitNewUser, userUrl } from "../../../lib/admin-console";
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
    await expect(page.getByText("User created.")).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: email, exact: true })).toBeVisible();
    await expect(detail(page, "Email")).toHaveText(email);
    await expect(detail(page, "Name")).toHaveText("Ada Lovelace");
    await expect(detail(page, "Username")).toHaveText("Not set");
    await expect(detail(page, "Subject")).toHaveText(/^[0-9a-f-]{36}$/);
    await expect(page.locator("#enabledDisabled")).toBeChecked();

    for (const query of [local, "Lovelace"]) {
      await page.goto(`${list}?query=${encodeURIComponent(query)}`);
      await expect(rowWithCell(page, email)).toHaveCount(1);
    }
    // The list names the user beside the address.
    await expect(rowWithCell(page, email).getByRole("cell").nth(1)).toHaveText("Ada Lovelace");

    const { client, secret } = await passwordGrantClient(page, clients);
    const answer = await passwordToken(request, client.identifier, secret, email, "a-good-password", "openid");
    expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  } finally {
    await deleteUser(page, id);
  }
  await page.goto(`${list}?query=${local}`);
  await expect(page.getByText("No users found.")).toBeVisible();
});

test("a search that matches nobody says so", async ({ page }) => {
  await page.goto(`${list}?query=nobody-matches-this-e2e-search`);
  await expect(page.getByText("No users found.")).toBeVisible();
});

test("the search box finds a user, whose pages lead back to the search, and Clear search ends it", async ({ page, users }) => {
  const user = await users.create();
  const search = page.getByRole("searchbox", { name: "Search users" });
  await page.goto(list);
  await search.fill(user.email);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page).toHaveURL((url) => url.pathname === "/admin/users" && url.searchParams.get("query") === user.email);
  await expect(rowWithCell(page, user.email)).toHaveCount(1);
  // One page of results: no pager.
  await expect(page.getByRole("navigation", { name: "Pagination" })).toHaveCount(0);

  // The address is the link to the user, whose tabs and link back keep the search.
  await page.getByRole("table").getByRole("link", { name: user.email, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/details\\?`));
  await page.getByRole("navigation", { name: "Sections" }).getByRole("link", { name: "Profile", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}/profile\\?`));
  await page.getByRole("main").getByRole("link", { name: "Users", exact: true }).click();
  await expect(page).toHaveURL((url) => url.pathname === "/admin/users" && url.searchParams.get("query") === user.email);
  await expect(search).toHaveValue(user.email);

  await page.getByRole("link", { name: "Clear search" }).click();
  await expect(page).toHaveURL(list);
  await expect(search).toHaveValue("");
});

test("a search matching more than a page of users is paged, and the pager keeps the search", async ({ page }) => {
  // Eleven users, one more than a page holds, sharing a token in their addresses: created by hand to
  // choose those addresses, and deleted below.
  test.slow();
  const token = uniqueIdentifier("u");
  const ids: number[] = [];
  try {
    for (let i = 0; i < 11; i++) {
      await submitNewUser(page, { email: `${token}-${i}@example.com`, password: "a-good-password" });
      await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
      ids.push(Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]));
    }

    await page.goto(`${list}?query=${token}`);
    const rows = page.locator("#usersTable tbody tr");
    const pager = page.getByRole("navigation", { name: "Pagination" });
    await expect(rows).toHaveCount(10);
    await expect(pager.getByRole("link", { name: "1", exact: true })).toHaveAttribute("aria-current", "page");
    await expect(pager.getByRole("link", { name: "Previous page" })).toHaveCount(0);

    await pager.getByRole("link", { name: "Next page" }).click();
    await expect(page).toHaveURL((url) => url.searchParams.get("page") === "2" && url.searchParams.get("query") === token);
    await expect(rows).toHaveCount(1);
    await expect(pager.getByRole("link", { name: "2", exact: true })).toHaveAttribute("aria-current", "page");
    await expect(pager.getByRole("link", { name: "Next page" })).toHaveCount(0);

    await pager.getByRole("link", { name: "Previous page" }).click();
    await expect(rows).toHaveCount(10);
  } finally {
    for (const id of ids) await deleteUser(page, id);
  }
});

test("choosing to email a link hides the password field, and setting it now shows it again", async ({ page }) => {
  // The baseline sends mail, so the new user page offers the choice.
  await page.goto(`${list}/new`);
  const password = page.locator("#password");
  await expect(page.getByRole("radio", { name: "Set the password now" })).toBeChecked();
  await expect(password).toBeVisible();
  await page.getByRole("radio", { name: "Email a link to set it" }).check();
  await expect(password).toBeHidden();
  await page.getByRole("radio", { name: "Set the password now" }).check();
  await expect(password).toBeVisible();
});

for (const { name, user, field, message } of [
  { name: "no email", user: { email: "" }, field: "email", message: "The email address cannot be empty." },
  { name: "a malformed email", user: { email: "not-an-email" }, field: "email", message: "Please enter a valid email address." },
  { name: "a given name with digits", user: { givenName: "R2D2" }, field: "givenName", message: "Please enter a valid given name." },
  { name: "no password", user: { password: "" }, field: "password", message: "Password is required" },
  { name: "a password under the policy's 6 characters", user: { password: "abc" }, field: "password", message: "Use at least 6 characters for the password." },
]) {
  test(`a user with ${name} is refused, and the form keeps what was typed`, async ({ page }) => {
    const email = `${uniqueIdentifier("u")}@example.com`;
    // The two refused-email cases replace the generated address with their own.
    const defaults = { email, givenName: "Grace", familyName: "Hopper", password: "a-good-password" };
    const submitted = { ...defaults, ...user };
    await submitNewUser(page, submitted);
    await expect(page).toHaveURL(`${list}/new`);
    // The notice says why, at the top of the form, and the field it is about is marked.
    await expectRefusal(page, "user-error", field, message);
    await expect(page.locator("#email")).toHaveValue(submitted.email);
    await expect(page.locator("#givenName")).toHaveValue(submitted.givenName);
    await expect(page.locator("#familyName")).toHaveValue(submitted.familyName);
    await page.goto(`${list}?query=${email.split("@")[0]}`);
    await expect(page.getByText("No users found.")).toBeVisible();
  });
}

test("an email already registered is refused", async ({ page, users }) => {
  const existing = await users.create();
  await submitNewUser(page, { email: existing.email.toUpperCase(), password: "a-good-password" });
  await expect(page).toHaveURL(`${list}/new`);
  await expectRefusal(page, "user-error", "email", "This email address is already registered");
});

test("the system administrator is listed, and their page opens", async ({ page }) => {
  const id = await idFromListLink(page, `${list}?query=${encodeURIComponent(env.adminEmail)}`, env.adminEmail);
  await expect(rowWithCell(page, env.adminEmail)).toHaveCount(1);
  await page.goto(userUrl(id, "details"));
  await expect(detail(page, "Email")).toHaveText(env.adminEmail);
});
